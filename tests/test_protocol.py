from protoaudit.analyzers.protocol import ProtocolAnalyzer
from protoaudit.core.config import FrameworkConfig
from protoaudit.core.models import Artifact, ArtifactType
from protoaudit.core.rule_engine import RuleEngine
from protoaudit.rules.protocol_rules import get_protocol_rules


def test_protocol_analyzer_extracts_indicators_and_repeats():
    artifact = Artifact.create(
        artifact_type=ArtifactType.TRANSCRIPT,
        content='recv: {"nonce":"abc"}\nrecv: {"nonce":"abc"}\nrecv: ok\nrecv: ok',
    )
    result = ProtocolAnalyzer().analyze(artifact)
    assert result.metrics["challenge_indicator_count"] == 2
    assert result.metrics["repeated_response_count"] >= 1
    assert result.metrics["repeated_challenge_value_count"] == 1


def test_protocol_analyzer_infers_handshake_and_phase_loops():
    artifact = Artifact.create(
        artifact_type=ArtifactType.TRANSCRIPT,
        content='''[00:00:01] C -> S : HELLO\n[00:00:02] S -> C : CHALLENGE 7A9F12\n[00:00:03] C -> S : RESPONSE 0x9f81c22e\n[00:00:04] S -> C : ACK\n[00:00:05] C -> S : HELLO\n[00:00:06] S -> C : CHALLENGE 7A9F12\n[00:00:07] C -> S : RESPONSE 0x9f81c22e\n[00:00:08] S -> C : ACK''',
    )
    result = ProtocolAnalyzer().analyze(artifact)
    findings = RuleEngine(get_protocol_rules(), config=FrameworkConfig.from_sources(profile="strict")).evaluate(result)
    assert result.metrics["handshake_detected"] is True
    assert result.metrics["handshake_complete"] is True
    assert result.metrics["handshake_style"] == "challenge-response"
    assert result.metrics["phase_loop_count"] >= 3
    assert any(f.metadata["rule_id"] == "PROTO-005" for f in findings)


def test_protocol_rule_detects_incomplete_handshake():
    artifact = Artifact.create(
        artifact_type=ArtifactType.TRANSCRIPT,
        content='send: HELLO\nrecv: CHALLENGE abc\nsend: RESPONSE 123',
    )
    result = ProtocolAnalyzer().analyze(artifact)
    findings = RuleEngine(get_protocol_rules()).evaluate(result)
    assert any(f.metadata["rule_id"] == "PROTO-004" for f in findings)
