"""Primary analysis execution pipeline."""

from __future__ import annotations

from protoaudit.analyzers.crypto import CryptoAnalyzer
from protoaudit.analyzers.protocol import ProtocolAnalyzer
from protoaudit.analyzers.randomness import RandomnessAnalyzer
from protoaudit.core.config import FrameworkConfig
from protoaudit.core.correlation import CorrelationEngine
from protoaudit.core.models import AnalysisResult, Artifact, ReportBundle
from protoaudit.core.plugin_loader import PluginManager
from protoaudit.core.rule_engine import RuleEngine
from protoaudit.rules.crypto_rules import get_crypto_rules
from protoaudit.rules.protocol_rules import get_protocol_rules
from protoaudit.rules.randomness_rules import get_randomness_rules


class AnalysisEngine:
    def __init__(self, config: FrameworkConfig | None = None) -> None:
        self.config = config or FrameworkConfig()
        self._correlation_engine = CorrelationEngine()
        self._plugin_manager = PluginManager(config=self.config)

    def analyze(self, *, artifact: Artifact, analyzer_name: str) -> ReportBundle:
        result = self._run_analyzer(artifact=artifact, analyzer_name=analyzer_name)

        if self.config.enable_rules:
            rule_engine = RuleEngine(self._get_rules_for(analyzer_name), config=self.config)
            result.findings.extend(rule_engine.evaluate(result))

        result = self._plugin_manager.apply(result)
        correlation = self._correlation_engine.correlate([result]) if self.config.enable_correlation else None
        return ReportBundle(
            artifacts=[artifact],
            analysis_results=[result],
            correlation_result=correlation,
        )

    def correlate_results(self, results: list[AnalysisResult]) -> ReportBundle:
        artifacts = [result.artifact for result in results]
        return ReportBundle(
            artifacts=artifacts,
            analysis_results=results,
            correlation_result=self._correlation_engine.correlate(results),
        )

    def _run_analyzer(self, *, artifact: Artifact, analyzer_name: str) -> AnalysisResult:
        analyzers = {
            "protocol": ProtocolAnalyzer(config=self.config),
            "crypto": CryptoAnalyzer(),
            "randomness": RandomnessAnalyzer(),
        }
        if analyzer_name not in analyzers:
            raise ValueError(f"Unsupported analyzer: {analyzer_name}")
        return analyzers[analyzer_name].analyze(artifact)

    def _get_rules_for(self, analyzer_name: str):
        rules = {
            "protocol": get_protocol_rules(),
            "crypto": get_crypto_rules(),
            "randomness": get_randomness_rules(),
        }
        return rules.get(analyzer_name, [])
