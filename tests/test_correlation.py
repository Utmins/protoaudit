import json

from protoaudit.analyzers.crypto import CryptoAnalyzer
from protoaudit.analyzers.protocol import ProtocolAnalyzer
from protoaudit.analyzers.randomness import RandomnessAnalyzer
from protoaudit.core.correlation import CorrelationEngine
from protoaudit.core.models import Artifact, ArtifactType
from protoaudit.core.rule_engine import RuleEngine
from protoaudit.rules.crypto_rules import get_crypto_rules
from protoaudit.rules.randomness_rules import get_randomness_rules


def test_correlation_engine_links_crypto_and_randomness():
    protocol_artifact = Artifact(
        artifact_id="p1",
        artifact_type=ArtifactType.PROTOCOL_TRACE,
        source_path=None,
        content='recv: {"challenge":"c1"}',
    )
    crypto_data = {"scheme_type": "aggregate_signature", "proof_of_possession": False}
    crypto_artifact = Artifact(
        artifact_id="c1",
        artifact_type=ArtifactType.CRYPTO_METADATA,
        source_path=None,
        content=json.dumps(crypto_data),
        metadata={"parsed": crypto_data},
    )
    rng_data = {"metadata": {"sample_encoding": "utf-8"}, "samples": ["x", "x", "y"]}
    rng_artifact = Artifact(
        artifact_id="r1",
        artifact_type=ArtifactType.RANDOM_SEQUENCE,
        source_path=None,
        content=json.dumps(rng_data),
        metadata={"parsed": rng_data},
    )

    protocol_result = ProtocolAnalyzer().analyze(protocol_artifact)
    crypto_result = CryptoAnalyzer().analyze(crypto_artifact)
    crypto_result.findings.extend(RuleEngine(get_crypto_rules()).evaluate(crypto_result))
    randomness_result = RandomnessAnalyzer().analyze(rng_artifact)
    randomness_result.findings.extend(RuleEngine(get_randomness_rules()).evaluate(randomness_result))

    correlation = CorrelationEngine().correlate([protocol_result, crypto_result, randomness_result])
    assert correlation.risk_posture == "elevated"
    assert correlation.combined_findings
