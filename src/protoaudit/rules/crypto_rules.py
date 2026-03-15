"""Crypto rules migrated from final framework and universal audit tools."""

from __future__ import annotations

from protoaudit.core.models import AnalysisResult, Finding, Severity
from protoaudit.core.rule_engine import Rule


class MissingProofOfPossessionRule(Rule):
    rule_id = "CRYPTO-001"
    title = "Missing proof-of-possession"
    applies_to = "crypto"

    def evaluate(self, result: AnalysisResult, config=None) -> list[Finding]:
        if result.metrics.get("aggregate_support") is not True or result.metrics.get("proof_of_possession_required") is not False:
            return []
        return [Finding.create(
            title=self.title,
            description="Aggregate or multi-party signature flows without proof-of-possession are exposed to rogue-key style risks.",
            severity=Severity.HIGH,
            confidence=0.95,
            analyzer=result.analyzer_name,
            recommendation="Require proof-of-possession or a stronger participant-registration binding mechanism before accepting public keys.",
            evidence=result.evidence[:2],
            metadata={"rule_id": self.rule_id},
        )]


class UntrustedPublicKeysRule(Rule):
    rule_id = "CRYPTO-002"
    title = "Untrusted public keys accepted"
    applies_to = "crypto"

    def evaluate(self, result: AnalysisResult, config=None) -> list[Finding]:
        if result.metrics.get("accepts_untrusted_pubkeys") is not True:
            return []
        return [Finding.create(
            title=self.title,
            description="The design appears to accept untrusted public keys without sufficient validation or provenance guarantees.",
            severity=Severity.MEDIUM,
            confidence=0.85,
            analyzer=result.analyzer_name,
            recommendation="Validate public keys, enforce trust registration, and bind accepted keys to signer identity and context.",
            evidence=result.evidence[:2],
            metadata={"rule_id": self.rule_id},
        )]


class MissingMessageBindingRule(Rule):
    rule_id = "CRYPTO-003"
    title = "Message context binding is unclear"
    applies_to = "crypto"

    def evaluate(self, result: AnalysisResult, config=None) -> list[Finding]:
        if result.metrics.get("binds_message_context") is not False:
            return []
        return [Finding.create(
            title=self.title,
            description="Verification does not clearly bind message context, increasing the risk of replay or substitution style logic errors.",
            severity=Severity.MEDIUM,
            confidence=0.8,
            analyzer=result.analyzer_name,
            recommendation="Bind protocol context, signer set, and message domain explicitly into verification.",
            evidence=result.evidence[:2],
            metadata={"rule_id": self.rule_id},
        )]


class MissingDomainSeparationRule(Rule):
    rule_id = "CRYPTO-004"
    title = "Domain separation absent"
    applies_to = "crypto"

    def evaluate(self, result: AnalysisResult, config=None) -> list[Finding]:
        if result.metrics.get("domain_separation") is not False:
            return []
        return [Finding.create(
            title=self.title,
            description="Absent domain separation can cause cross-protocol misuse or verification confusion.",
            severity=Severity.MEDIUM,
            confidence=0.85,
            analyzer=result.analyzer_name,
            recommendation="Introduce explicit domain separation or message tagging for each protocol context.",
            evidence=result.evidence[:2],
            metadata={"rule_id": self.rule_id},
        )]


class ParticipantBindingRule(Rule):
    rule_id = "CRYPTO-005"
    title = "Verifier does not bind participant set"
    applies_to = "crypto"

    def evaluate(self, result: AnalysisResult, config=None) -> list[Finding]:
        if result.metrics.get("verifier_binds_participants") is not False:
            return []
        return [Finding.create(
            title=self.title,
            description="Aggregate verification should bind the exact participant set and message context.",
            severity=Severity.HIGH,
            confidence=0.9,
            analyzer=result.analyzer_name,
            recommendation="Bind participant identities and ordering into the verified statement and associated transcript context.",
            evidence=result.evidence[:2],
            metadata={"rule_id": self.rule_id},
        )]


def get_crypto_rules() -> list[Rule]:
    return [
        MissingProofOfPossessionRule(),
        UntrustedPublicKeysRule(),
        MissingMessageBindingRule(),
        MissingDomainSeparationRule(),
        ParticipantBindingRule(),
    ]
