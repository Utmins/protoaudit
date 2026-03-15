import json
from pathlib import Path

from protoaudit.core.config import FrameworkConfig
from protoaudit.core.engine import AnalysisEngine
from protoaudit.core.io import load_artifact_from_path
from protoaudit.core.models import ArtifactType
from protoaudit.core.plugin_loader import PluginManager


def test_plugin_manager_loads_builtin_plugins_from_config(tmp_path: Path):
    config_path = tmp_path / "plugins.json"
    config_path.write_text(json.dumps({"plugins": {"enabled": ["json-lines", "finding-tags"]}}), encoding="utf-8")
    config = FrameworkConfig.from_sources(path=config_path)
    manager = PluginManager(config=config)
    names = [plugin.name for plugin in manager.plugins]
    assert names == ["json-lines", "finding-tags"]


def test_plugins_enrich_analysis_results():
    config = FrameworkConfig.from_sources(overrides={"plugins": {"enabled": ["json-lines", "finding-tags"]}})
    engine = AnalysisEngine(config=config)
    artifact = load_artifact_from_path(
        "examples/protocol/retry_loop_case_study/session.txt",
        artifact_type=ArtifactType.PROTOCOL_TRACE,
        config=config,
    )
    bundle = engine.analyze(artifact=artifact, analyzer_name="protocol")
    result = bundle.analysis_results[0]
    assert "json-lines" in result.metadata.get("plugins", [])
    assert "finding-tags" in result.metadata.get("applied_plugins", [])
    assert any(tag.startswith("rule:") for tag in result.metadata.get("tags", []))
