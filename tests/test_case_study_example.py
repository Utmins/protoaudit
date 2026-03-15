from pathlib import Path

from protoaudit.core.engine import AnalysisEngine
from protoaudit.core.io import load_artifact_from_path
from protoaudit.core.models import ArtifactType


def test_retry_loop_case_study_triggers_expected_protocol_findings() -> None:
    path = Path('examples/protocol/retry_loop_case_study/session.txt')
    artifact = load_artifact_from_path(path, artifact_type=ArtifactType.PROTOCOL_TRACE)
    bundle = AnalysisEngine().analyze(artifact=artifact, analyzer_name='protocol')
    result = bundle.analysis_results[0]

    titles = {finding.title for finding in result.findings}
    assert 'Challenge-like field observed' in titles
    assert 'Challenge-like values repeat across messages' in titles
    assert 'Handshake-like flow appears incomplete' in titles
    assert 'Repeated protocol phase loop observed' in titles
    assert result.metrics['handshake_style'] == 'challenge-response'
    assert result.metrics['handshake_complete'] is False
