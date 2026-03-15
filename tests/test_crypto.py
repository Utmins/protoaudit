from protoaudit.analyzers.crypto import CryptoAnalyzer
from protoaudit.core.models import Artifact, ArtifactType
from protoaudit.core.rule_engine import RuleEngine
from protoaudit.rules.crypto_rules import get_crypto_rules


def test_crypto_analyzer_and_rules_emit_findings():
    artifact = Artifact.create(
        artifact_type=ArtifactType.CRYPTO_METADATA,
        content='{}',
        metadata={
            'parsed': {
                'scheme_type': 'aggregate_signature',
                'proof_of_possession': False,
                'accepts_untrusted_pubkeys': True,
                'domain_separation': False,
                'verifier_binds_participants': False,
            }
        },
    )
    result = CryptoAnalyzer().analyze(artifact)
    findings = RuleEngine(get_crypto_rules()).evaluate(result)
    assert len(findings) >= 4
