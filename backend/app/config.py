"""Application settings, loaded from environment variables / .env.

Toda a configuração passa por aqui. Nenhum módulo lê ``os.environ`` diretamente —
isso mantém os defaults num lugar só e permite sobrescrever tudo em teste.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["dev", "test", "prod"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ---------------------------------------------------------------- app
    environment: Environment = "dev"
    log_level: str = "INFO"
    service_name: str = "threat-detector"

    # ---------------------------------------------------------------- auth
    api_key: SecretStr = Field(
        default=SecretStr("change-me-in-env"),
        description="Chave exigida no header X-API-Key e no handshake do WebSocket.",
    )
    rate_limit_per_minute: int = 300

    # ---------------------------------------------------------------- storage
    database_url: str = "postgresql+asyncpg://detector:detector@postgres:5432/detector"
    db_pool_size: int = 10
    db_max_overflow: int = 5

    redis_url: str = "redis://redis:6379/0"
    alerts_channel: str = "threats:alerts"

    # ---------------------------------------------------------------- ingestão
    log_dir: Path = Path("/var/log/nginx")
    log_glob: str = "*access*.log"
    poll_interval_seconds: float = 1.0
    raw_queue_maxsize: int = 10_000
    parsed_queue_maxsize: int = 10_000
    scored_queue_maxsize: int = 5_000

    # Lote de escrita no Postgres: descarrega ao atingir o tamanho OU o timeout,
    # o que vier primeiro. Sem o timeout, tráfego baixo nunca persistiria.
    dispatch_batch_size: int = 100
    dispatch_flush_seconds: float = 2.0

    # ---------------------------------------------------------------- detecção
    ip_window_seconds: int = 60
    severity_high_threshold: float = 0.7
    severity_medium_threshold: float = 0.5
    # Eventos LOW são a maioria esmagadora do tráfego; guardar todos infla o banco
    # sem agregar sinal, então amostramos.
    low_severity_sample_rate: float = 0.05

    weight_autoencoder: float = 0.4
    weight_random_forest: float = 0.4
    weight_isolation_forest: float = 0.2
    ensemble_agreement_bonus: float = 0.1

    # ---------------------------------------------------------------- ml
    model_dir: Path = Path("/models")
    geoip_db_path: Path = Path("/data/geoip/GeoLite2-Country.mmdb")
    # Aponta para o servidor MLflow, não para o SQLite direto. Com dois processos
    # escrevendo no mesmo arquivo (o servidor e o treino da API), a migração de
    # schema do alembic colide e o servidor entra em laço de restart. Assim há um
    # escritor só, e o cliente fala HTTP.
    mlflow_tracking_uri: str = "http://mlflow:5000"

    min_f1: float = 0.80
    min_pr_auc: float = 0.85
    synthetic_sample_count: int = 40_000
    retrain_min_samples_per_class: int = 500
    # Rótulos heurísticos para eventos não revisados. A faixa entre os dois é
    # ambígua demais para virar rótulo e é descartada.
    retrain_attack_score_floor: float = 0.7
    retrain_benign_score_ceiling: float = 0.2

    @field_validator("severity_medium_threshold")
    @classmethod
    def _medium_below_high(cls, v: float, info: object) -> float:
        # Validado de novo em _check_thresholds; aqui só barramos o absurdo.
        if not 0.0 < v < 1.0:
            raise ValueError("severity_medium_threshold deve estar entre 0 e 1")
        return v

    @field_validator("log_level")
    @classmethod
    def _upper(cls, v: str) -> str:
        return v.upper()

    def model_post_init(self, __context: object) -> None:
        if self.severity_medium_threshold >= self.severity_high_threshold:
            raise ValueError(
                "severity_medium_threshold precisa ser menor que severity_high_threshold"
            )
        total = self.weight_autoencoder + self.weight_random_forest + self.weight_isolation_forest
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"pesos do ensemble devem somar 1.0 (soma atual: {total})")

    @property
    def is_prod(self) -> bool:
        return self.environment == "prod"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
