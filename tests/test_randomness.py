from protoaudit.analyzers.randomness import RandomnessAnalyzer
from protoaudit.core.models import Artifact, ArtifactType
from protoaudit.core.rule_engine import RuleEngine
from protoaudit.rules.randomness_rules import get_randomness_rules


def test_randomness_analyzer_extracts_metrics():
    artifact = Artifact.create(
        artifact_type=ArtifactType.RANDOM_SEQUENCE,
        content='aa aa aa aa',
        metadata={
            'parsed': {
                'metadata': {
                    'sample_encoding': 'utf-8',
                    'state_bits': 256,
                    'output_bits': 224,
                    'samples_are_truncated': True,
                    'revealed_state_related_bits_per_sample': 224,
                    'deterministic_nonce_or_challenge': True,
                    'uses_custom_rng': True,
                },
                'samples': ['aa', 'aa', 'aa', 'aa'],
            }
        },
    )
    result = RandomnessAnalyzer().analyze(artifact)
    findings = RuleEngine(get_randomness_rules()).evaluate(result)
    assert result.metrics['recovery_feasibility'] == 'high'
    assert len(findings) >= 4
