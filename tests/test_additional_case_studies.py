from pathlib import Path

from protoaudit.core.engine import AnalysisEngine
from protoaudit.core.io import load_artifact_from_path
from protoaudit.core.models import ArtifactType


def test_cached_handshake_case_study_triggers_repeat_findings_without_incomplete_handshake() -> None:
    path = Path('examples/protocol/cached_handshake_material_case_study/session.txt')
    artifact = load_artifact_from_path(path, artifact_type=ArtifactType.PROTOCOL_TRACE)
    bundle = AnalysisEngine().analyze(artifact=artifact, analyzer_name='protocol')
    result = bundle.analysis_results[0]

    titles = {finding.title for finding in result.findings}
    assert 'Challenge-like field observed' in titles
    assert 'Repeated protocol responses detected' in titles
    assert 'Challenge-like values repeat across messages' in titles
    assert 'Repeated protocol phase loop observed' in titles
    assert 'Handshake-like flow appears incomplete' not in titles
    assert result.metrics['handshake_style'] == 'challenge-response'
    assert result.metrics['handshake_complete'] is True


def test_structured_pairing_retry_case_study_exercises_script_semantics() -> None:
    path = Path('examples/protocol/structured_pairing_retry_case_study/script.json')
    artifact = load_artifact_from_path(path, artifact_type=ArtifactType.PROTOCOL_TRACE)
    bundle = AnalysisEngine().analyze(artifact=artifact, analyzer_name='protocol')
    result = bundle.analysis_results[0]

    titles = {finding.title for finding in result.findings}
    assert 'Challenge-like field observed' in titles
    assert 'Repeated protocol responses detected' in titles
    assert 'Challenge-like values repeat across messages' in titles
    assert 'Handshake-like flow appears incomplete' in titles
    assert 'Repeated protocol phase loop observed' in titles
    assert result.metrics['script_step_count'] == 10
    assert result.metrics['handshake_complete'] is False
