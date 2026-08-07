"""Stage 2 — turn a parsed entry into the 35-dimensional feature vector.

Três fontes se juntam aqui:

1. A própria requisição (estrutura da URI, tokens, método, status, cliente).
2. Janela deslizante de 60s por IP, mantida no Redis — é o que distingue um 404
   isolado de uma varredura de diretório.
3. GeoIP, opcional.

A ordem e a semântica das dimensões vêm de :mod:`app.ml.features_spec`.
"""

from __future__ import annotations

import itertools
import math
import statistics
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote_plus

import redis.asyncio as redis

from app.config import Settings
from app.logging_setup import get_logger
from app.ml import features_spec as fs
from app.pipeline.types import FeaturedEntry, LogEntry

log = get_logger(__name__)

# Teto de entradas guardadas por IP na janela. Um flood de 100 mil requisições em
# 60s não pode virar um sorted set de 100 mil membros por IP no Redis; para as
# estatísticas que calculamos, as 500 mais recentes já saturam o sinal.
MAX_WINDOW_ENTRIES = 500

_sequence = itertools.count()


@dataclass(slots=True)
class WindowStats:
    request_count: int = 0
    unique_paths: int = 0
    error_rate: float = 0.0
    mean_interarrival: float = 0.0
    burstiness: float = 0.0


class IPWindowTracker:
    """Janela deslizante por IP em Redis Sorted Set.

    No Redis e não em memória por dois motivos: sobrevive a restart do `detector`
    (senão todo deploy zeraria o histórico e um scanner em curso passaria batido)
    e é compartilhada se houver mais de um processo ingerindo.
    """

    def __init__(self, client: redis.Redis, window_seconds: int) -> None:
        self._redis = client
        self._window = window_seconds

    @staticmethod
    def _key(ip: str) -> str:
        return f"win:{ip}"

    async def observe(self, entry: LogEntry) -> WindowStats:
        """Registra a requisição e devolve as estatísticas da janela."""
        now = entry.ts.timestamp()
        cutoff = now - self._window
        key = self._key(entry.remote_addr)

        # Timestamp do nginx tem resolução de segundo, então várias requisições
        # compartilham score. O contador garante membro único — sem ele, o ZADD
        # sobrescreveria e a contagem sairia menor que a real.
        member = f"{next(_sequence)}|{entry.status}|{hash(entry.path) & 0xFFFFFFFF:08x}"

        try:
            pipe = self._redis.pipeline()
            pipe.zremrangebyscore(key, "-inf", cutoff)
            pipe.zadd(key, {member: now})
            pipe.zremrangebyrank(key, 0, -(MAX_WINDOW_ENTRIES + 1))
            pipe.zrange(key, 0, -1, withscores=True)
            pipe.expire(key, self._window * 2)
            results = await pipe.execute()
            members: list[tuple[str, float]] = results[3]
        except Exception as exc:
            # Redis fora do ar degrada as 5 features de janela para zero, mas as
            # outras 30 continuam válidas e o motor de regras nem depende disso.
            log.warning("window.redis_unavailable", error=type(exc).__name__)
            return WindowStats()

        return self._compute(members)

    def _compute(self, members: list[tuple[str, float]]) -> WindowStats:
        if not members:
            return WindowStats()

        count = len(members)
        paths: set[str] = set()
        errors = 0
        for raw_member, _score in members:
            parts = raw_member.split("|")
            if len(parts) != 3:
                continue
            _seq, status, path_hash = parts
            paths.add(path_hash)
            if status.isdigit() and int(status) >= 400:
                errors += 1

        scores = sorted(score for _m, score in members)
        if count > 1:
            span = scores[-1] - scores[0]
            mean_gap = span / (count - 1)
            gaps = [b - a for a, b in itertools.pairwise(scores)]
            # Coeficiente de variação: tráfego humano chega irregular, script
            # chega em intervalo quase constante (CV perto de zero) ou em rajada
            # concentrada (CV alto). Os dois extremos são suspeitos.
            stdev = statistics.pstdev(gaps) if len(gaps) > 1 else 0.0
            burstiness = stdev / mean_gap if mean_gap > 0 else 0.0
        else:
            mean_gap = float(self._window)
            burstiness = 0.0

        return WindowStats(
            request_count=count,
            unique_paths=len(paths),
            error_rate=errors / count,
            mean_interarrival=mean_gap,
            burstiness=burstiness,
        )


class GeoIPResolver:
    """Consulta MaxMind GeoLite2, se o banco existir.

    Ausência do .mmdb não é erro: as bases exigem conta na MaxMind e não podem ser
    versionadas. Sem elas a dimensão de país vira 0 e o resto do sistema não muda.
    """

    def __init__(self, country_db: Path) -> None:
        self._reader: object | None = None
        self._enabled = False
        if not country_db.is_file():
            log.info("geoip.disabled", reason="banco ausente", path=str(country_db))
            return
        try:
            import geoip2.database

            self._reader = geoip2.database.Reader(str(country_db))
            self._enabled = True
            log.info("geoip.enabled", path=str(country_db))
        except Exception as exc:
            log.warning("geoip.load_failed", error=str(exc))

    @property
    def enabled(self) -> bool:
        return self._enabled

    def country(self, ip: str) -> str | None:
        if not self._enabled or self._reader is None:
            return None
        try:
            response = self._reader.country(ip)  # type: ignore[attr-defined]
            return response.country.iso_code  # type: ignore[no-any-return]
        except Exception:
            # IP privado ou ausente da base. Comum e esperado.
            return None

    def close(self) -> None:
        if self._reader is not None:
            self._reader.close()  # type: ignore[attr-defined]
            self._reader = None
            self._enabled = False


def _decode_twice(value: str) -> str:
    """Decodifica percent-encoding em duas passadas.

    ``%252e%252e%252f`` decodifica para ``%2e%2e%2f`` e só então para ``../``.
    Contar tokens sobre o texto cru deixaria passar a codificação dupla, que é a
    evasão mais barata que existe.
    """
    try:
        once = unquote_plus(value)
        return unquote_plus(once)
    except Exception:
        return value


class FeatureExtractor:
    """Monta o vetor de 35 dimensões."""

    def __init__(self, settings: Settings, redis_client: redis.Redis) -> None:
        self._settings = settings
        self._window = IPWindowTracker(redis_client, settings.ip_window_seconds)
        self._geoip = GeoIPResolver(settings.geoip_db_path)

    async def extract(self, entry: LogEntry) -> FeaturedEntry:
        window = await self._window.observe(entry)
        country = self._geoip.country(entry.remote_addr)
        vector = self.build_vector(entry, window, country)
        return FeaturedEntry(entry=entry, features=vector, country=country)

    @staticmethod
    def build_vector(entry: LogEntry, window: WindowStats, country: str | None) -> list[float]:
        """Função pura: mesma entrada, mesmo vetor.

        Separada de ``extract`` para o treino sintético e os testes construírem
        vetores sem Redis nem GeoIP no caminho.
        """
        path = entry.path
        query = entry.query
        # As features estruturais olham o texto cru (comprimento, entropia — a
        # codificação em si é sinal), mas a contagem de tokens olha o decodificado.
        decoded = _decode_twice(f"{path}?{query}" if query else path)
        combined_raw = f"{path}{query}"

        params = [p for p in query.split("&") if p] if query else []
        max_param_len = max((len(p.partition("=")[2]) for p in params), default=0)

        hour_sin, hour_cos = fs.hour_cyclic(entry.ts.hour)
        ua = entry.user_agent

        # O nginx grava "-" quando o cabeçalho não veio. Tratar "-" como referer
        # presente colocaria toda requisição sem referer — que é a maioria do
        # tráfego de API e de bot — numa faixa intermediária inexistente, e
        # deslocaria a distribuição que o modelo aprendeu.
        if not entry.referer or entry.referer == "-":
            referer_state = 0.0
        elif entry.referer.startswith("/"):
            referer_state = 0.5
        else:
            referer_state = 1.0

        vector = [
            # --- estrutura da URI (12) ---
            fs.saturate(len(path), 64),
            fs.saturate(len(query), 64),
            fs.shannon_entropy(path),
            fs.shannon_entropy(query),
            fs.saturate(len(params), 8),
            fs.saturate(max_param_len, 48),
            fs.special_char_ratio(combined_raw),
            fs.digit_ratio(combined_raw),
            fs.saturate(fs.count_pct_encoded(combined_raw), 4),
            fs.saturate(fs.count_double_encoded(combined_raw), 2),
            fs.saturate(path.count("/"), 6),
            1.0 if fs.has_suspicious_extension(path) else 0.0,
            # --- tokens de ataque (5) ---
            fs.saturate(fs.count_sql_tokens(decoded), 2),
            fs.saturate(fs.count_xss_tokens(decoded), 2),
            fs.saturate(fs.count_traversal_tokens(decoded), 2),
            fs.saturate(fs.count_cmdi_tokens(decoded), 2),
            fs.saturate(fs.count_jndi_tokens(decoded), 1),
            # --- requisição / resposta (7) ---
            fs.method_id(entry.method),
            1.0 if fs.is_write_method(entry.method) else 0.0,
            fs.status_normalized(entry.status),
            fs.saturate(math.log1p(max(entry.bytes_sent, 0)), 8),
            fs.protocol_version(entry.protocol),
            hour_sin,
            hour_cos,
            # --- cliente (5) ---
            fs.saturate(len(ua), 64),
            fs.shannon_entropy(ua),
            1.0 if not ua or ua == "-" else 0.0,
            1.0 if fs.is_known_scanner(ua) else 0.0,
            referer_state,
            # --- janela por IP (5) ---
            fs.saturate(window.request_count, 20),
            fs.saturate(window.unique_paths, 15),
            fs.clamp01(window.error_rate),
            # Invertido: intervalo curto = mais suspeito, então a feature cresce
            # quando as requisições chegam mais juntas.
            1.0 - fs.saturate(window.mean_interarrival, 5),
            fs.saturate(window.burstiness, 2),
            # --- geoip (1) ---
            fs.country_risk(country),
        ]

        return fs.validate_vector(vector)

    def close(self) -> None:
        self._geoip.close()
