"""The 35-dimensional feature contract — single source of truth.

Treino (`app.ml.synthetic`, `app.ml.train`) e inferência (`app.pipeline.stage2_features`)
importam daqui. Se os dois lados calculassem as features separadamente, uma divergência
não geraria erro nenhum: os modelos simplesmente passariam a receber um vetor com
significado diferente do que aprenderam, e a detecção degradaria em silêncio.

Regras para mexer aqui:

* **Ordem é contrato.** O índice de cada feature é o índice na entrada do ONNX.
  Nunca reordene nem remova — só acrescente no fim, e aí `FEATURE_COUNT` muda e
  todos os modelos precisam ser retreinados.
* **Tudo limitado a [0, 1].** Transformações saturantes (log, min) em vez de valores
  crus. Uma URL de 8 KB não pode virar um outlier que domina o `StandardScaler`.
* **Sem NaN, sem infinito.** Campo ausente vira 0.0.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Final

# ---------------------------------------------------------------------------
# Nomes, na ordem exata do vetor
# ---------------------------------------------------------------------------

FEATURE_NAMES: Final[tuple[str, ...]] = (
    # --- estrutura da URI (12) ---
    "path_length",
    "query_length",
    "path_entropy",
    "query_entropy",
    "param_count",
    "max_param_value_length",
    "special_char_ratio",
    "digit_ratio",
    "pct_encoded_count",
    "double_encoded_count",
    "path_depth",
    "suspicious_extension",
    # --- tokens de ataque (5) ---
    "sql_token_count",
    "xss_token_count",
    "traversal_token_count",
    "cmdi_token_count",
    "jndi_token_count",
    # --- requisição / resposta (7) ---
    "method_id",
    "is_write_method",
    "status_normalized",
    "bytes_sent_log",
    "protocol_version",
    "hour_sin",
    "hour_cos",
    # --- cliente (5) ---
    "ua_length",
    "ua_entropy",
    "ua_is_empty",
    "ua_is_known_scanner",
    "referer_state",
    # --- janela por IP, 60s (5) ---
    "window_request_count",
    "window_unique_paths",
    "window_error_rate",
    "window_mean_interarrival",
    "window_burstiness",
    # --- geoip (1) ---
    "country_risk",
)

FEATURE_COUNT: Final[int] = len(FEATURE_NAMES)
FEATURE_INDEX: Final[dict[str, int]] = {name: i for i, name in enumerate(FEATURE_NAMES)}

assert FEATURE_COUNT == 35, f"o contrato prevê 35 dimensões, encontrado {FEATURE_COUNT}"


# ---------------------------------------------------------------------------
# Normalizações
# ---------------------------------------------------------------------------


def saturate(value: float, scale: float) -> float:
    """Comprime [0, ∞) em [0, 1), aproximadamente linear perto de zero.

    Usado no lugar de min(x/scale, 1) porque preserva alguma ordenação acima do
    ponto de saturação: um path de 2000 caracteres continua pontuando acima de um
    de 500, em vez de os dois virarem 1.0.
    """
    if value <= 0 or scale <= 0:
        return 0.0
    return value / (value + scale)


def clamp01(value: float) -> float:
    if not math.isfinite(value):
        return 0.0
    return max(0.0, min(1.0, value))


def shannon_entropy(text: str) -> float:
    """Entropia de Shannon normalizada para [0, 1] (divisor: 8 bits).

    Payload codificado/ofuscado tem entropia bem mais alta que caminho legível.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
    return clamp01(entropy / 8.0)


def ratio(count: int, total: int) -> float:
    return clamp01(count / total) if total > 0 else 0.0


# ---------------------------------------------------------------------------
# Vocabulário de tokens
# ---------------------------------------------------------------------------
#
# Contagem grosseira e barata, de propósito: aqui só produzimos um número para o
# modelo. A decisão precisa de "isto é SQLi" é do motor de regras
# (`app.detection`), que casa padrões completos e com contexto.

_SQL_TOKENS: Final[re.Pattern[str]] = re.compile(
    r"\b(union|select|insert|update|delete|drop|truncate|exec|declare|cast|convert|"
    r"information_schema|sysobjects|waitfor|benchmark|sleep|pg_sleep|load_file|"
    r"outfile|dumpfile|having|group\s+by|order\s+by)\b|"
    r"(--|#|/\*|\*/|;\s*$|'\s*(or|and)\s*'|\bor\b\s+\d+\s*=\s*\d+|\|\|)",
    re.IGNORECASE,
)

_XSS_TOKENS: Final[re.Pattern[str]] = re.compile(
    r"(<\s*script|</\s*script|javascript:|vbscript:|data:text/html|"
    r"\bon(error|load|click|mouseover|focus|submit|toggle|animationstart)\s*=|"
    r"<\s*(img|svg|iframe|object|embed|body|video|audio|details|marquee)\b|"
    r"\b(alert|prompt|confirm|eval|atob|fromcharcode)\s*\(|"
    r"document\.(cookie|domain|write)|window\.(location|name))",
    re.IGNORECASE,
)

_TRAVERSAL_TOKENS: Final[re.Pattern[str]] = re.compile(
    r"(\.\./|\.\.\\|%2e%2e[/\\%]|%252e%252e|\.\.%2f|\.\.%5c|"
    r"/etc/(passwd|shadow|hosts)|/proc/self|boot\.ini|win\.ini|"
    r"\bfile://|\.(env|git/config|aws/credentials|ssh/id_rsa)\b)",
    re.IGNORECASE,
)

_CMDI_TOKENS: Final[re.Pattern[str]] = re.compile(
    r"(;\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|python|perl)\b|"
    r"\|\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh)\b|"
    r"`[^`]+`|\$\([^)]+\)|&&\s*\w+|\|\|\s*\w+|"
    r"\b(nc|netcat)\s+-[a-z]*e|/bin/(ba)?sh|cmd\.exe|powershell)",
    re.IGNORECASE,
)

# Log4Shell e primos: JNDI sobre qualquer protocolo, incluindo as variantes com
# ${lower:...} e afins usadas para driblar filtro ingênuo.
_JNDI_TOKENS: Final[re.Pattern[str]] = re.compile(
    r"(\$\{jndi:|\$\{[^}]*j[^}]*n[^}]*d[^}]*i[^}]*:|"
    r"\b(ldaps?|rmi|dns|iiop|corba|nis|nds):/{2}|"
    r"\$\{(env|sys|lower|upper|date|ctx|base64):)",
    re.IGNORECASE,
)

_SUSPICIOUS_EXTENSIONS: Final[frozenset[str]] = frozenset(
    {
        "php",
        "php3",
        "php4",
        "php5",
        "phtml",
        "asp",
        "aspx",
        "jsp",
        "jspx",
        "cgi",
        "pl",
        "sh",
        "bash",
        "exe",
        "dll",
        "bak",
        "old",
        "swp",
        "sql",
        "env",
        "ini",
        "conf",
        "config",
        "log",
        "git",
        "yml",
        "yaml",
        "pem",
        "key",
    }
)

_SCANNER_AGENTS: Final[re.Pattern[str]] = re.compile(
    r"(sqlmap|nikto|nmap|masscan|zgrab|nessus|acunetix|netsparker|burp|"
    r"dirbuster|gobuster|feroxbuster|ffuf|wpscan|joomscan|hydra|metasploit|"
    r"havij|w3af|arachni|openvas|qualys|whatweb|wafw00f|nuclei|"
    r"python-requests|go-http-client|libwww-perl|curl/|wget/|scrapy|zmeu)",
    re.IGNORECASE,
)

_SPECIAL_CHARS: Final[frozenset[str]] = frozenset("<>\"'`;|&$(){}[]\\*%!~^")

_METHOD_IDS: Final[dict[str, float]] = {
    "GET": 0.1,
    "POST": 0.2,
    "HEAD": 0.3,
    "PUT": 0.4,
    "DELETE": 0.5,
    "PATCH": 0.6,
    "OPTIONS": 0.7,
    "TRACE": 0.8,
    "CONNECT": 0.9,
}
_WRITE_METHODS: Final[frozenset[str]] = frozenset({"POST", "PUT", "DELETE", "PATCH"})

_PCT_ENCODED: Final[re.Pattern[str]] = re.compile(r"%[0-9a-fA-F]{2}")
_DOUBLE_ENCODED: Final[re.Pattern[str]] = re.compile(r"%25[0-9a-fA-F]{2}", re.IGNORECASE)

# Países com concentração desproporcional de tráfego hostil em datasets públicos.
# Sinal fraco de propósito: geografia não é evidência, e o peso é baixo. Serve
# como desempate, nunca como motivo isolado para classificar algo como ataque.
_COUNTRY_RISK: Final[dict[str, float]] = {
    "CN": 0.7,
    "RU": 0.7,
    "KP": 0.9,
    "IR": 0.7,
    "BR": 0.3,
    "IN": 0.4,
    "VN": 0.5,
    "ID": 0.4,
    "UA": 0.4,
    "NL": 0.3,
    "SC": 0.6,
    "PA": 0.5,  # hubs de hosting à prova de queixa
}
_DEFAULT_COUNTRY_RISK: Final[float] = 0.2


# ---------------------------------------------------------------------------
# Extratores individuais
# ---------------------------------------------------------------------------


def count_sql_tokens(text: str) -> int:
    return len(_SQL_TOKENS.findall(text))


def count_xss_tokens(text: str) -> int:
    return len(_XSS_TOKENS.findall(text))


def count_traversal_tokens(text: str) -> int:
    return len(_TRAVERSAL_TOKENS.findall(text))


def count_cmdi_tokens(text: str) -> int:
    return len(_CMDI_TOKENS.findall(text))


def count_jndi_tokens(text: str) -> int:
    return len(_JNDI_TOKENS.findall(text))


def count_pct_encoded(text: str) -> int:
    return len(_PCT_ENCODED.findall(text))


def count_double_encoded(text: str) -> int:
    return len(_DOUBLE_ENCODED.findall(text))


def special_char_ratio(text: str) -> float:
    if not text:
        return 0.0
    return ratio(sum(1 for c in text if c in _SPECIAL_CHARS), len(text))


def digit_ratio(text: str) -> float:
    if not text:
        return 0.0
    return ratio(sum(1 for c in text if c.isdigit()), len(text))


def has_suspicious_extension(path: str) -> bool:
    tail = path.rsplit("/", 1)[-1]
    if "." not in tail:
        return False
    return tail.rsplit(".", 1)[-1].lower() in _SUSPICIOUS_EXTENSIONS


def is_known_scanner(user_agent: str) -> bool:
    return bool(user_agent) and bool(_SCANNER_AGENTS.search(user_agent))


def method_id(method: str) -> float:
    """Métodos fora da lista recebem 1.0 — método exótico já é anomalia."""
    return _METHOD_IDS.get(method.upper(), 1.0)


def is_write_method(method: str) -> bool:
    return method.upper() in _WRITE_METHODS


def protocol_version(protocol: str) -> float:
    if "2" in protocol:
        return 1.0
    if "1.1" in protocol:
        return 0.5
    if "1.0" in protocol:
        return 0.25
    return 0.0


def country_risk(country: str | None) -> float:
    if not country:
        return 0.0
    return _COUNTRY_RISK.get(country.upper(), _DEFAULT_COUNTRY_RISK)


def status_normalized(status: int) -> float:
    """Mapeia a classe do status para [0, 1]. 401/403/404 pesam mais alto porque
    é o rastro que varredura de diretório e força bruta deixam."""
    if status in (401, 403, 404, 405):
        return 0.8
    if 500 <= status < 600:
        return 0.9
    if 400 <= status < 500:
        return 0.6
    if 300 <= status < 400:
        return 0.3
    return 0.1


def hour_cyclic(hour: int) -> tuple[float, float]:
    """Hora como seno/cosseno, deslocados para [0, 1].

    Codificar a hora como 0..23 cru ensinaria o modelo que 23h e 0h são opostos,
    quando são vizinhos. Isso importa: tráfego de bot se concentra de madrugada.
    """
    angle = 2 * math.pi * (hour % 24) / 24.0
    return (math.sin(angle) + 1) / 2, (math.cos(angle) + 1) / 2


def validate_vector(vector: list[float]) -> list[float]:
    """Última barreira antes do modelo: tamanho certo, finito e em [0, 1].

    Rede: uma feature nova mal normalizada é corrigida aqui em vez de virar
    predição silenciosamente errada.
    """
    if len(vector) != FEATURE_COUNT:
        raise ValueError(f"esperado {FEATURE_COUNT} features, recebido {len(vector)}")
    return [clamp01(v) for v in vector]
