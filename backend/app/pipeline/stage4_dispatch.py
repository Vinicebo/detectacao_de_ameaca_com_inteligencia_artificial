"""Stage 4 — persist scored events and publish alerts.

Duas saídas com exigências opostas:

* **Alerta** vai para o Redis **na hora**. É o produto do sistema; segurá-lo dois
  segundos num buffer para economizar uma escrita seria trocar a única coisa que
  o usuário percebe por eficiência que ele não vê.
* **Persistência** vai em lote. Um INSERT por requisição custaria mais que o
  pipeline inteiro de detecção, e o Postgres viraria o gargalo antes do ONNX.

Eventos LOW são amostrados. São a esmagadora maioria do tráfego e existem só para
análise de padrão agregada — guardar todos infla a tabela em ordens de grandeza
sem agregar sinal.
"""

from __future__ import annotations

import random
import time
from typing import Any

from app.config import Settings
from app.db.models import Severity, ThreatEvent
from app.db.session import session_scope
from app.logging_setup import get_logger
from app.pipeline.types import ScoredEntry
from app.realtime.bus import AlertBus

log = get_logger(__name__)


def to_alert_payload(scored: ScoredEntry, event_id: int | None = None) -> dict[str, Any]:
    """Converte para o formato que trafega no WebSocket."""
    entry = scored.featured.entry
    return {
        "id": event_id,
        "ts": entry.ts.isoformat(),
        "remote_addr": entry.remote_addr,
        "method": entry.method,
        "path": entry.path,
        "query": entry.query or None,
        "status": entry.status,
        "country": scored.featured.country,
        "user_agent": entry.user_agent or None,
        "rule_score": round(scored.rule_score, 4),
        "ml_score": round(scored.ml_score, 4),
        "threat_score": round(scored.threat_score, 4),
        "severity": scored.severity.value,
        "categories": scored.categories,
        "matched_rules": [
            {
                "rule_id": m.rule_id,
                "category": m.category,
                "severity": m.severity,
                "score": m.score,
                "description": m.description,
                "matched_on": m.matched_on,
            }
            for m in scored.matched_rules
        ],
        "model_version": scored.model_version,
        # Recomendação, não ação: este sistema observa. Bloquear com base em
        # detecção automática derruba usuário legítimo no primeiro falso positivo.
        "recommend_block": scored.severity == Severity.HIGH,
    }


def to_orm(scored: ScoredEntry) -> ThreatEvent:
    entry = scored.featured.entry
    return ThreatEvent(
        ts=entry.ts,
        remote_addr=entry.remote_addr,
        method=entry.method,
        path=entry.path[:8192],
        query=entry.query[:8192] if entry.query else None,
        protocol=entry.protocol,
        status=entry.status,
        bytes_sent=entry.bytes_sent,
        referer=entry.referer[:4096] if entry.referer else None,
        user_agent=entry.user_agent[:2048] if entry.user_agent else None,
        country=scored.featured.country,
        asn=scored.featured.asn,
        rule_score=scored.rule_score,
        ml_score=scored.ml_score,
        threat_score=scored.threat_score,
        severity=scored.severity,
        categories=scored.categories,
        matched_rules=[
            {
                "rule_id": m.rule_id,
                "category": m.category,
                "severity": m.severity,
                "score": m.score,
                "description": m.description,
                "matched_on": m.matched_on,
            }
            for m in scored.matched_rules
        ],
        features=scored.featured.features,
        model_version=scored.model_version,
    )


class Dispatcher:
    """Consome a fila pontuada, persiste em lote e publica alertas."""

    def __init__(self, settings: Settings, bus: AlertBus) -> None:
        self._settings = settings
        self._bus = bus
        self._buffer: list[ScoredEntry] = []
        self._last_flush = time.monotonic()
        self._rng = random.Random(20260806)
        self.persisted = 0
        self.sampled_out = 0
        self.failed_writes = 0

    def _should_persist(self, scored: ScoredEntry) -> bool:
        if scored.severity != Severity.LOW:
            return True
        return self._rng.random() < self._settings.low_severity_sample_rate

    async def handle(self, scored: ScoredEntry) -> None:
        # Alerta primeiro, e sem esperar o lote. É o caminho que o usuário sente.
        if scored.severity in (Severity.HIGH, Severity.MEDIUM):
            await self._bus.publish(to_alert_payload(scored))

        if self._should_persist(scored):
            self._buffer.append(scored)
        else:
            self.sampled_out += 1

        if len(self._buffer) >= self._settings.dispatch_batch_size:
            await self.flush()

    async def flush(self) -> None:
        """Grava o lote acumulado. Sem lote, não faz nada."""
        if not self._buffer:
            self._last_flush = time.monotonic()
            return

        batch, self._buffer = self._buffer, []
        try:
            async with session_scope() as session:
                session.add_all([to_orm(scored) for scored in batch])
            self.persisted += len(batch)
        except Exception as exc:
            # Descartamos o lote em vez de reenfileirar. Reenfileirar num banco
            # indisponível faria o buffer crescer sem limite até o OOM — e aí
            # perderíamos tudo em vez de um lote. O contador denuncia a perda.
            self.failed_writes += len(batch)
            log.error("dispatch.write_failed", error=str(exc), lost=len(batch))
        finally:
            self._last_flush = time.monotonic()

    @property
    def seconds_since_flush(self) -> float:
        return time.monotonic() - self._last_flush

    def stats(self) -> dict[str, int]:
        return {
            "events_persisted": self.persisted,
            "alerts_published": self._bus.published,
            "low_severity_sampled_out": self.sampled_out,
            "failed_writes": self.failed_writes,
            "buffered": len(self._buffer),
        }
