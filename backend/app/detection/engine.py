"""Declarative rule engine.

As regras ficam em YAML (``app/detection/rules/*.yaml``) para poderem ser
revisadas, versionadas e ajustadas sem mexer no código — quem escreve regra de
detecção nem sempre é quem escreve o motor.

Como pontua: o escore da requisição é o **maior** escore casado, mais um pequeno
bônus por categoria distinta adicional. Somar tudo faria três regras fracas da
mesma família (que costumam casar juntas no mesmo payload) valerem mais que uma
regra forte e específica. Já casar SQLi *e* traversal na mesma requisição é sinal
genuinamente independente, e aí o bônus se justifica.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from app.detection import normalize
from app.logging_setup import get_logger
from app.pipeline.types import LogEntry, RuleMatch

log = get_logger(__name__)

RULES_DIR = Path(__file__).parent / "rules"

VALID_TARGETS = frozenset(
    {
        "method",
        "path",
        "query",
        "uri",
        "uri_decommented",
        "user_agent",
        "referer",
        "raw_path",
        "raw_query",
    }
)
VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low"})

# Bônus por categoria distinta além da primeira. Baixo de propósito: é desempate,
# não deve sozinho empurrar um MEDIUM para HIGH sem uma regra forte por trás.
CATEGORY_BONUS = 0.05
MAX_CATEGORY_BONUS = 0.15


@dataclass(slots=True, frozen=True)
class Rule:
    id: str
    category: str
    severity: str
    score: float
    description: str
    targets: tuple[str, ...]
    pattern: re.Pattern[str]


class RuleLoadError(Exception):
    """Regra malformada. Falha no arranque, não em tempo de detecção."""


def _parse_rule(raw: dict[str, Any], source: Path) -> Rule:
    def require(key: str) -> Any:
        if key not in raw:
            raise RuleLoadError(f"{source.name}: regra sem campo obrigatório '{key}': {raw}")
        return raw[key]

    rule_id = str(require("id"))
    targets = raw.get("targets") or [raw.get("target", "uri")]
    targets = tuple(str(t) for t in targets)

    for target in targets:
        if target not in VALID_TARGETS:
            raise RuleLoadError(
                f"{source.name}:{rule_id}: alvo '{target}' inválido. "
                f"Válidos: {sorted(VALID_TARGETS)}"
            )

    severity = str(raw.get("severity", "medium")).lower()
    if severity not in VALID_SEVERITIES:
        raise RuleLoadError(f"{source.name}:{rule_id}: severidade '{severity}' inválida")

    score = float(require("score"))
    if not 0.0 <= score <= 1.0:
        raise RuleLoadError(f"{source.name}:{rule_id}: score {score} fora de [0, 1]")

    try:
        # Compilado no arranque: uma regex ruim quebra o deploy, não a detecção
        # em produção. E o custo de compilação sai do caminho quente.
        pattern = re.compile(str(require("pattern")), re.IGNORECASE)
    except re.error as exc:
        raise RuleLoadError(f"{source.name}:{rule_id}: regex inválida: {exc}") from exc

    return Rule(
        id=rule_id,
        category=str(require("category")),
        severity=severity,
        score=score,
        description=str(raw.get("description", "")),
        targets=targets,
        pattern=pattern,
    )


def load_rules(rules_dir: Path = RULES_DIR) -> list[Rule]:
    """Carrega e compila todas as regras. Levanta ``RuleLoadError`` se algo estiver errado."""
    if not rules_dir.is_dir():
        raise RuleLoadError(f"diretório de regras não encontrado: {rules_dir}")

    rules: list[Rule] = []
    seen: set[str] = set()

    for path in sorted(rules_dir.glob("*.yaml")):
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise RuleLoadError(f"{path.name}: YAML inválido: {exc}") from exc

        for raw in document.get("rules", []):
            rule = _parse_rule(raw, path)
            if rule.id in seen:
                # ID duplicado tornaria impossível rastrear qual regra disparou.
                raise RuleLoadError(f"{path.name}: id de regra duplicado: {rule.id}")
            seen.add(rule.id)
            rules.append(rule)

    if not rules:
        raise RuleLoadError(f"nenhuma regra carregada de {rules_dir}")

    log.info("rules.loaded", count=len(rules), categories=len({r.category for r in rules}))
    return rules


class RuleEngine:
    """Avalia requisições contra o conjunto de regras."""

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self._rules = rules if rules is not None else load_rules()

    @property
    def rules(self) -> list[Rule]:
        return self._rules

    def evaluate(self, entry: LogEntry) -> tuple[float, list[RuleMatch]]:
        """Devolve ``(escore, casamentos)`` para a requisição."""
        request = normalize.build(
            method=entry.method,
            path=entry.path,
            query=entry.query,
            user_agent=entry.user_agent,
            referer=entry.referer,
        )

        matches: list[RuleMatch] = []
        for rule in self._rules:
            for target in rule.targets:
                text = request.field(target)
                if not text:
                    continue
                found = rule.pattern.search(text)
                if found is None:
                    continue
                matches.append(
                    RuleMatch(
                        rule_id=rule.id,
                        category=rule.category,
                        severity=rule.severity,
                        score=rule.score,
                        description=rule.description,
                        # Guardar o trecho que casou é o que torna um alerta
                        # revisável: sem isso o analista não sabe por que disparou.
                        matched_on=f"{target}:{found.group(0)[:120]}",
                    )
                )
                # Uma regra conta uma vez, mesmo casando em vários alvos.
                break

        return self._score(matches), matches

    @staticmethod
    def _score(matches: list[RuleMatch]) -> float:
        if not matches:
            return 0.0
        base = max(match.score for match in matches)
        extra_categories = len({m.category for m in matches}) - 1
        bonus = min(extra_categories * CATEGORY_BONUS, MAX_CATEGORY_BONUS)
        return min(base + bonus, 1.0)
