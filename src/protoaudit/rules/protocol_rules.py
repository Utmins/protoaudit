"""Protocol rules migrated from legacy protocol and transcript analysis behavior."""

from __future__ import annotations

from protoaudit.core.config import FrameworkConfig
from protoaudit.core.models import AnalysisResult, Finding, Severity
from protoaudit.core.rule_engine import Rule


class ChallengeFieldObservedRule(Rule):
    rule_id = "PROTO-001"
    title = "Challenge-like field observed"
    applies_to = "protocol"

    def evaluate(self, result: AnalysisResult, config: FrameworkConfig | None = None) -> list[Finding]:
        count = int(result.metrics.get("challenge_indicator_count", 0))
        if count <= 0:
            return []
        return [
            Finding.create(
                title=self.title,
                description="The transcript or script contains challenge-like fields that may require replay-resistance and binding review.",
                severity=Severity.INFO,
                confidence=0.9,
                analyzer=result.analyzer_name,
                recommendation="Review challenge generation, binding, and nonce lifecycle assumptions in the protocol flow.",
                evidence=result.evidence[:2],
                metadata={"rule_id": self.rule_id, "challenge_indicator_count": count},
            )
        ]


class RepeatedResponseRule(Rule):
    rule_id = "PROTO-002"
    title = "Repeated protocol responses detected"
    applies_to = "protocol"

    def evaluate(self, result: AnalysisResult, config: FrameworkConfig | None = None) -> list[Finding]:
        ratio = float(result.metrics.get("repeated_response_ratio", 0.0))
        threshold = 0.5 if config is None else float(config.threshold("protocol_repeated_response_ratio", 0.5) or 0.5)
        if ratio < threshold:
            return []
        return [
            Finding.create(
                title=self.title,
                description="Repeated inbound responses may indicate deterministic server behavior, weak challenge handling, or limited transcript variability.",
                severity=Severity.LOW,
                confidence=0.8,
                analyzer=result.analyzer_name,
                recommendation="Replay the same interaction under controlled conditions and verify whether deterministic responses are expected.",
                evidence=result.evidence[:2],
                metadata={"rule_id": self.rule_id, "repeated_response_ratio": ratio, "threshold": threshold},
            )
        ]


class RepeatedChallengeValuesRule(Rule):
    rule_id = "PROTO-003"
    title = "Challenge-like values repeat across messages"
    applies_to = "protocol"

    def evaluate(self, result: AnalysisResult, config: FrameworkConfig | None = None) -> list[Finding]:
        count = int(result.metrics.get("repeated_challenge_value_count", 0))
        threshold = 1 if config is None else int(config.threshold("protocol_repeated_challenge_value_count", 1) or 1)
        if count < threshold:
            return []
        return [
            Finding.create(
                title=self.title,
                description="A value labeled as a challenge, nonce, token, or similar field appears to repeat across messages.",
                severity=Severity.MEDIUM,
                confidence=0.9,
                analyzer=result.analyzer_name,
                recommendation="Validate freshness guarantees and confirm whether these fields are truly session-unique rather than labels for static identifiers.",
                evidence=result.evidence[:4],
                metadata={"rule_id": self.rule_id, "repeated_challenge_value_count": count},
            )
        ]


class IncompleteHandshakeRule(Rule):
    rule_id = "PROTO-004"
    title = "Handshake-like flow appears incomplete"
    applies_to = "protocol"

    def evaluate(self, result: AnalysisResult, config: FrameworkConfig | None = None) -> list[Finding]:
        if not result.metrics.get("handshake_detected"):
            return []
        if bool(result.metrics.get("handshake_complete")):
            return []
        return [
            Finding.create(
                title=self.title,
                description="The transcript contains a recognizable handshake pattern, but it does not appear to reach an acknowledgement or completion phase.",
                severity=Severity.LOW,
                confidence=0.76,
                analyzer=result.analyzer_name,
                recommendation="Confirm whether the capture is truncated or whether the protocol genuinely permits partial handshakes without explicit completion.",
                evidence=result.evidence[:3],
                metadata={"rule_id": self.rule_id, "handshake_style": result.metrics.get("handshake_style")},
            )
        ]


class RepeatedPhaseLoopRule(Rule):
    rule_id = "PROTO-005"
    title = "Repeated protocol phase loop observed"
    applies_to = "protocol"

    def evaluate(self, result: AnalysisResult, config: FrameworkConfig | None = None) -> list[Finding]:
        loop_count = int(result.metrics.get("phase_loop_count", 0))
        threshold = 2 if config is None else int(config.threshold("protocol_phase_loop_threshold", 2) or 2)
        if loop_count < threshold:
            return []
        return [
            Finding.create(
                title=self.title,
                description="The inferred state machine revisits the same transition patterns multiple times, which can indicate retries, loops, or replay-prone behavior.",
                severity=Severity.MEDIUM,
                confidence=0.78,
                analyzer=result.analyzer_name,
                recommendation="Review whether repeated state transitions are expected for retries or whether challenge/response material is being reused across attempts.",
                evidence=result.evidence[:3],
                metadata={"rule_id": self.rule_id, "phase_loop_count": loop_count},
            )
        ]


def get_protocol_rules() -> list[Rule]:
    return [
        ChallengeFieldObservedRule(),
        RepeatedResponseRule(),
        RepeatedChallengeValuesRule(),
        IncompleteHandshakeRule(),
        RepeatedPhaseLoopRule(),
    ]
