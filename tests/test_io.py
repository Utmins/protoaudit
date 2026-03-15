from pathlib import Path
import json

from protoaudit.core.config import FrameworkConfig
from protoaudit.core.io import infer_artifact_type, load_artifact_from_path, load_artifacts_from_path
from protoaudit.core.models import ArtifactType


def test_io_infers_protocol_script(tmp_path: Path):
    path = tmp_path / "protocol.json"
    path.write_text('{"steps": [{"action": "send", "data": "hi"}]}', encoding='utf-8')
    artifact = load_artifact_from_path(path)
    assert artifact.artifact_type == ArtifactType.PROTOCOL_TRACE
    assert artifact.metadata["parsed"]["steps"][0]["action"] == "send"


def test_io_infers_from_name():
    assert infer_artifact_type("sample_transcript.txt") == ArtifactType.TRANSCRIPT


def test_io_detects_transcript_from_content(tmp_path: Path):
    path = tmp_path / "capture.log"
    path.write_text('[00:00:01] C -> S : HELLO\n[00:00:02] S -> C : CHALLENGE 123', encoding='utf-8')
    artifact = load_artifact_from_path(path)
    assert artifact.artifact_type == ArtifactType.TRANSCRIPT
    assert artifact.metadata["looks_like_transcript"] is True


def test_io_loads_manifest_and_directory(tmp_path: Path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({
        "artifacts": [
            {"artifact_type": "crypto_metadata", "content": '{"scheme_type":"aggregate_signature"}'},
            {"artifact_type": "random_sequence", "content": 'aa aa aa'},
        ]
    }), encoding='utf-8')
    artifacts = load_artifacts_from_path(manifest)
    assert len(artifacts) == 2
    assert artifacts[0].artifact_type == ArtifactType.CRYPTO_METADATA

    samples_dir = tmp_path / "inputs"
    samples_dir.mkdir()
    (samples_dir / "one.txt").write_text('recv: {"challenge":"x"}', encoding='utf-8')
    (samples_dir / "two.txt").write_text('aa aa aa', encoding='utf-8')
    cfg = FrameworkConfig.from_sources(overrides={"io": {"recursive": True}})
    loaded = load_artifacts_from_path(samples_dir, config=cfg)
    assert len(loaded) == 2
