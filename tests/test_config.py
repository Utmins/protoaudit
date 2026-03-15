import json
from pathlib import Path

from protoaudit.core.config import FrameworkConfig


def test_config_profile_and_rule_policy_loading(tmp_path: Path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "profile": "strict",
        "rule_policy": {"disabled_rule_ids": ["PROTO-002"]},
        "io": {"recursive": True},
    }), encoding="utf-8")

    config = FrameworkConfig.from_sources(path=path)
    assert config.profile == "strict"
    assert config.io.recursive is True
    assert config.is_rule_enabled("PROTO-002") is False
    assert config.threshold("protocol_repeated_response_ratio") == 0.25
