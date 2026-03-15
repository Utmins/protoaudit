"""Normalized rule execution for analyzer results."""

from __future__ import annotations

from collections.abc import Iterable

from protoaudit.core.config import FrameworkConfig
from protoaudit.core.models import AnalysisResult, Finding


class Rule:
    """Normalized Python rule contract."""

    rule_id: str = "uninitialized-rule"
    title: str = "Unnamed Rule"
    applies_to: str = "*"

    def evaluate(self, result: AnalysisResult, config: FrameworkConfig | None = None) -> list[Finding]:
        return []


class RuleEngine:
    def __init__(self, rules: Iterable[Rule] | None = None, *, config: FrameworkConfig | None = None) -> None:
        self._rules = list(rules or [])
        self._config = config or FrameworkConfig()

    def evaluate(self, result: AnalysisResult) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self._rules:
            if rule.applies_to not in ("*", result.analyzer_name):
                continue
            if not self._config.is_rule_enabled(getattr(rule, "rule_id", "")):
                continue
            findings.extend(rule.evaluate(result, self._config))
        return findings
