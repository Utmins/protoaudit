"""Randomness rules migrated from final framework and RNG leakage analyzer."""

from __future__ import annotations

from protoaudit.core.models import AnalysisResult, Finding, Severity
from protoaudit.core.rule_engine import Rule


class HighRepeatedRatioRule(Rule):
    rule_id = "RNG-001"
    title = "Repeated outputs detected"
    applies_to = "randomness"

    def evaluate(self, result: AnalysisResult, config=None) -> list[Finding]:
        ratio = float(result.metrics.get("repeated_ratio", 0.0))
        if ratio <= 0.0:
            return []
        severity = Severity.HIGH if ratio > 0.10 else Severity.MEDIUM
        return [Finding.create(
            title=self.title,
            description="Repeated outputs reduce confidence in nonce or challenge uniqueness and may indicate weak seeding or deterministic behavior.",
            severity=severity,
            confidence=0.9,
            analyzer=result.analyzer_name,
            recommendation="Review seeding, reseeding, and duplicate-detection controls for sensitive RNG outputs.",
            evidence=result.evidence[:2],
            metadata={"rule_id": self.rule_id, "repeated_ratio": ratio},
        )]


class LowUniqueRatioRule(Rule):
    rule_id = "RNG-002"
    title = "Output diversity is low"
    applies_to = "randomness"

    def evaluate(self, result: AnalysisResult, config=None) -> list[Finding]:
        unique_ratio = float(result.metrics.get("unique_ratio", 1.0))
        if unique_ratio >= 0.90:
            return []
        return [Finding.create(
            title=self.title,
            description="Observed outputs are not diverse enough for material expected to behave like challenges or nonces.",
            severity=Severity.HIGH,
            confidence=0.9,
            analyzer=result.analyzer_name,
            recommendation="Inspect seeding, reseeding, and any state reuse across sessions or processes.",
            evidence=result.evidence[:2],
            metadata={"rule_id": self.rule_id, "unique_ratio": unique_ratio},
        )]


class HiddenBitsExposureRule(Rule):
    rule_id = "RNG-003"
    title = "Potential state exposure per sample"
    applies_to = "randomness"

    def evaluate(self, result: AnalysisResult, config=None) -> list[Finding]:
        state_bits = result.metrics.get("state_bits") or result.metrics.get("hidden_bits")
        leaked_bits = result.metrics.get("revealed_state_related_bits_per_sample")
        if not isinstance(state_bits, (int, float)) or not isinstance(leaked_bits, (int, float)) or not state_bits:
            return []
        if leaked_bits < 0.7 * state_bits:
            return []
        return [Finding.create(
            title=self.title,
            description="Per-sample revealed bits appear to expose a large fraction of the modeled hidden state size.",
            severity=Severity.HIGH,
            confidence=0.85,
            analyzer=result.analyzer_name,
            recommendation="Reduce state-related output exposure and re-evaluate truncation and disclosure assumptions.",
            evidence=result.evidence[:2],
            metadata={"rule_id": self.rule_id, "state_bits": state_bits, "leaked_bits": leaked_bits},
        )]


class DeterministicOutputRule(Rule):
    rule_id = "RNG-004"
    title = "Deterministic challenge or nonce generation"
    applies_to = "randomness"

    def evaluate(self, result: AnalysisResult, config=None) -> list[Finding]:
        if result.metrics.get("deterministic_outputs") is not True:
            return []
        return [Finding.create(
            title=self.title,
            description="Deterministic generation may permit replay or prediction depending on protocol context and keying assumptions.",
            severity=Severity.HIGH,
            confidence=0.8,
            analyzer=result.analyzer_name,
            recommendation="Use a reviewed cryptographic RNG and validate nonce uniqueness and freshness requirements.",
            evidence=result.evidence[:2],
            metadata={"rule_id": self.rule_id},
        )]


class TruncationExposureRule(Rule):
    rule_id = "RNG-005"
    title = "Truncated outputs still expose substantial state-sized material"
    applies_to = "randomness"

    def evaluate(self, result: AnalysisResult, config=None) -> list[Finding]:
        if result.metrics.get("samples_are_truncated") is not True:
            return []
        state_bits = result.metrics.get("state_bits")
        output_bits = result.metrics.get("output_bits")
        if not isinstance(state_bits, (int, float)) or not isinstance(output_bits, (int, float)) or state_bits <= 0:
            return []
        if output_bits < 0.75 * state_bits:
            return []
        return [Finding.create(
            title=self.title,
            description="Outputs are truncated, but still expose a large fraction of state-sized material per sample.",
            severity=Severity.HIGH,
            confidence=0.85,
            analyzer=result.analyzer_name,
            recommendation="Reduce output exposure or use a standard DRBG construction with stronger margins.",
            evidence=result.evidence[:2],
            metadata={"rule_id": self.rule_id, "state_bits": state_bits, "output_bits": output_bits},
        )]


class CustomRngRule(Rule):
    rule_id = "RNG-006"
    title = "Custom RNG in use"
    applies_to = "randomness"

    def evaluate(self, result: AnalysisResult, config=None) -> list[Finding]:
        if result.metrics.get("uses_custom_rng") is not True:
            return []
        return [Finding.create(
            title=self.title,
            description="Custom RNG constructions deserve independent review because security assumptions are easy to overstate.",
            severity=Severity.MEDIUM,
            confidence=0.75,
            analyzer=result.analyzer_name,
            recommendation="Prefer well-reviewed standard designs or subject the custom RNG to dedicated review and testing.",
            evidence=result.evidence[:2],
            metadata={"rule_id": self.rule_id},
        )]


def get_randomness_rules() -> list[Rule]:
    return [
        HighRepeatedRatioRule(),
        LowUniqueRatioRule(),
        HiddenBitsExposureRule(),
        DeterministicOutputRule(),
        TruncationExposureRule(),
        CustomRngRule(),
    ]
