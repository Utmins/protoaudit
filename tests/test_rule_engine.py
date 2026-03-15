import json

from protoaudit.analyzers.protocol import ProtocolAnalyzer
from protoaudit.core.models import Artifact, ArtifactType
from protoaudit.core.rule_engine import RuleEngine
from protoaudit.rules.protocol_rules import get_protocol_rules


def test_rule_engine_emits_protocol_finding():
    artifact = Artifact(
        artifact_id="a1",
        artifact_type=ArtifactType.PROTOCOL_TRACE,
        source_path=None,
        content='recv: {"challenge":"hello"}',
    )
    result = ProtocolAnalyzer().analyze(artifact)
    findings = RuleEngine(get_protocol_rules()).evaluate(result)
    assert findings
    assert findings[0].metadata["rule_id"] == "PROTO-001"
