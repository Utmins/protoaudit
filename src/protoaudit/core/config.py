"""Configuration models and loading helpers for protoaudit."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import json
import os

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None


DEFAULT_THRESHOLDS = {
    "randomness_repeated_ratio_high": 0.10,
    "randomness_repeated_ratio_medium": 0.0,
    "randomness_unique_ratio_low": 0.90,
    "protocol_repeated_response_ratio": 0.50,
    "protocol_repeated_challenge_value_count": 1,
    "protocol_phase_loop_threshold": 2,
}

DEFAULT_PROFILES: dict[str, dict[str, Any]] = {
    "default": {
        "enable_rules": True,
        "enable_correlation": True,
        "enable_plugins": True,
        "default_output_format": "console",
        "thresholds": DEFAULT_THRESHOLDS,
        "rule_policy": {"enabled_rule_ids": [], "disabled_rule_ids": []},
        "plugins": {"enabled": [], "disabled": [], "search_paths": [], "allow_entry_points": True},
        "io": {"recursive": False, "max_file_size_bytes": 5_000_000, "structured_suffixes": [".json", ".yaml", ".yml"]},
    },
    "strict": {
        "thresholds": {
            "randomness_repeated_ratio_high": 0.05,
            "randomness_unique_ratio_low": 0.95,
            "protocol_repeated_response_ratio": 0.25,
            "protocol_phase_loop_threshold": 1,
        }
    },
    "research": {
        "thresholds": {
            "randomness_repeated_ratio_high": 0.15,
            "randomness_unique_ratio_low": 0.85,
            "protocol_repeated_response_ratio": 0.75,
            "protocol_phase_loop_threshold": 3,
        },
        "io": {"recursive": True},
    },
}


@dataclass(slots=True)
class RulePolicy:
    enabled_rule_ids: list[str] = field(default_factory=list)
    disabled_rule_ids: list[str] = field(default_factory=list)


@dataclass(slots=True)
class PluginsConfig:
    enabled: list[str] = field(default_factory=list)
    disabled: list[str] = field(default_factory=list)
    search_paths: list[str] = field(default_factory=list)
    allow_entry_points: bool = True


@dataclass(slots=True)
class IOConfig:
    recursive: bool = False
    max_file_size_bytes: int = 5_000_000
    structured_suffixes: list[str] = field(default_factory=lambda: [".json", ".yaml", ".yml"])


@dataclass(slots=True)
class FrameworkConfig:
    enable_rules: bool = True
    enable_correlation: bool = True
    enable_plugins: bool = True
    default_output_format: str = "console"
    thresholds: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_THRESHOLDS))
    analyzer_settings: dict[str, Any] = field(default_factory=dict)
    rule_policy: RulePolicy = field(default_factory=RulePolicy)
    plugins: PluginsConfig = field(default_factory=PluginsConfig)
    io: IOConfig = field(default_factory=IOConfig)
    profile: str = "default"

    @classmethod
    def from_file(cls, path: str | Path | None, *, profile: str | None = None) -> "FrameworkConfig":
        return cls.from_sources(path=path, profile=profile)

    @classmethod
    def from_sources(
        cls,
        *,
        path: str | Path | None = None,
        profile: str | None = None,
        overrides: dict[str, Any] | None = None,
    ) -> "FrameworkConfig":
        data = _deep_copy_dict(DEFAULT_PROFILES["default"])
        selected_profile = profile or "default"
        if selected_profile in DEFAULT_PROFILES and selected_profile != "default":
            _deep_merge(data, DEFAULT_PROFILES[selected_profile])
        if path:
            file_data = _read_config_file(path)
            if isinstance(file_data, dict):
                profile_from_file = file_data.get("profile")
                if isinstance(profile_from_file, str) and profile_from_file in DEFAULT_PROFILES and selected_profile == "default":
                    selected_profile = profile_from_file
                    data = _deep_copy_dict(DEFAULT_PROFILES["default"])
                    _deep_merge(data, DEFAULT_PROFILES[selected_profile])
                _deep_merge(data, file_data)
        env_data = _config_from_env()
        if env_data:
            _deep_merge(data, env_data)
        if overrides:
            _deep_merge(data, overrides)
        return cls(
            enable_rules=bool(data.get("enable_rules", True)),
            enable_correlation=bool(data.get("enable_correlation", True)),
            enable_plugins=bool(data.get("enable_plugins", True)),
            default_output_format=str(data.get("default_output_format", "console")),
            thresholds={**DEFAULT_THRESHOLDS, **dict(data.get("thresholds", {}))},
            analyzer_settings=dict(data.get("analyzer_settings", {})),
            rule_policy=RulePolicy(**dict(data.get("rule_policy", {}))),
            plugins=PluginsConfig(**dict(data.get("plugins", {}))),
            io=IOConfig(**dict(data.get("io", {}))),
            profile=selected_profile,
        )

    def is_rule_enabled(self, rule_id: str) -> bool:
        if self.rule_policy.enabled_rule_ids and rule_id not in self.rule_policy.enabled_rule_ids:
            return False
        if rule_id in self.rule_policy.disabled_rule_ids:
            return False
        return True

    def threshold(self, name: str, default: float | None = None) -> float | None:
        return self.thresholds.get(name, default)

    def is_plugin_enabled(self, plugin_name: str) -> bool:
        if self.plugins.enabled and plugin_name not in self.plugins.enabled and all(":" not in item for item in self.plugins.enabled):
            return False
        if plugin_name in self.plugins.disabled:
            return False
        return True


def _read_config_file(path: str | Path) -> dict[str, Any]:
    file_path = Path(path)
    raw = file_path.read_text(encoding="utf-8")
    if file_path.suffix.lower() == ".json":
        data = json.loads(raw)
    elif file_path.suffix.lower() in {".yaml", ".yml"} and yaml is not None:
        data = yaml.safe_load(raw)
    else:
        data = {}
    return data if isinstance(data, dict) else {}


def _deep_merge(base: dict[str, Any], incoming: dict[str, Any]) -> None:
    for key, value in incoming.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value


def _deep_copy_dict(data: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(data))


def _config_from_env() -> dict[str, Any]:
    data: dict[str, Any] = {}
    if "PROTOAUDIT_PROFILE" in os.environ:
        data["profile"] = os.environ["PROTOAUDIT_PROFILE"]
    if "PROTOAUDIT_ENABLE_RULES" in os.environ:
        data["enable_rules"] = os.environ["PROTOAUDIT_ENABLE_RULES"].strip().lower() in {"1", "true", "yes", "on"}
    if "PROTOAUDIT_ENABLE_CORRELATION" in os.environ:
        data["enable_correlation"] = os.environ["PROTOAUDIT_ENABLE_CORRELATION"].strip().lower() in {"1", "true", "yes", "on"}
    if "PROTOAUDIT_DISABLED_RULES" in os.environ:
        data.setdefault("rule_policy", {})["disabled_rule_ids"] = [item.strip() for item in os.environ["PROTOAUDIT_DISABLED_RULES"].split(",") if item.strip()]
    if "PROTOAUDIT_PLUGINS" in os.environ:
        data.setdefault("plugins", {})["enabled"] = [item.strip() for item in os.environ["PROTOAUDIT_PLUGINS"].split(",") if item.strip()]
    if "PROTOAUDIT_DISABLED_PLUGINS" in os.environ:
        data.setdefault("plugins", {})["disabled"] = [item.strip() for item in os.environ["PROTOAUDIT_DISABLED_PLUGINS"].split(",") if item.strip()]
    return data
