"""Stage 3 — score a featured entry with rules plus the ML ensemble."""

from __future__ import annotations

from app.config import Settings
from app.detection import scoring
from app.detection.engine import RuleEngine
from app.detection.onnx_session import EnsembleSession, try_load
from app.logging_setup import get_logger
from app.pipeline.types import FeaturedEntry, ScoredEntry

log = get_logger(__name__)


class Detector:
    """Motor de regras + ensemble ONNX.

    O ensemble é opcional: sem ele o detector segue funcionando só com as regras.
    Isso não é degradação teórica — é o estado real do sistema nos dois primeiros
    minutos de vida, enquanto o treino inicial roda.
    """

    def __init__(self, settings: Settings, rule_engine: RuleEngine | None = None) -> None:
        self._settings = settings
        self._rules = rule_engine or RuleEngine()
        self._ensemble: EnsembleSession | None = try_load(settings.model_dir)

    @property
    def mode(self) -> str:
        return "ensemble" if self._ensemble is not None else "rules_only"

    @property
    def rule_count(self) -> int:
        return len(self._rules.rules)

    @property
    def model_version(self) -> str | None:
        return self._ensemble.version if self._ensemble else None

    def reload_models(self) -> bool:
        """Recarrega os modelos do disco, usado após um retreino.

        A sessão nova é construída antes de trocar a antiga: se o carregamento
        falhar, seguimos com o modelo que estava funcionando em vez de cair para
        somente-regras por causa de um treino ruim.
        """
        replacement = try_load(self._settings.model_dir)
        if replacement is None:
            log.warning("detector.reload_failed", keeping=self.mode)
            return False
        self._ensemble = replacement
        log.info("detector.reloaded", version=replacement.version)
        return True

    def score(self, featured: FeaturedEntry) -> ScoredEntry:
        rule_score, matches = self._rules.evaluate(featured.entry)

        ae = rf = iso = None
        ml_score = 0.0
        if self._ensemble is not None:
            try:
                ae, rf, iso = self._ensemble.score(featured.features)
                ml_score = scoring.combine_ml(ae, rf, iso, self._settings)
            except Exception as exc:
                # Uma predição que explode não pode derrubar o pipeline. As regras
                # ainda pontuam esta requisição.
                log.warning("detector.inference_failed", error=str(exc))
                ae = rf = iso = None

        breakdown = scoring.fuse(
            rule_score,
            ml_score,
            self._settings,
            autoencoder=ae,
            random_forest=rf,
            isolation_forest=iso,
        )

        return ScoredEntry(
            featured=featured,
            rule_score=breakdown.rule_score,
            ml_score=breakdown.ml_score,
            threat_score=breakdown.threat_score,
            severity=breakdown.severity,
            matched_rules=matches,
            model_version=self.model_version,
        )
