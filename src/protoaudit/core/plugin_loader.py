"""Runtime plugin loading for protoaudit."""

from __future__ import annotations

from dataclasses import dataclass
import importlib
from importlib import metadata as importlib_metadata
from typing import Any

from protoaudit.core.config import FrameworkConfig
from protoaudit.core.models import AnalysisResult
from protoaudit.core.plugin_api import Plugin

ENTRY_POINT_GROUP = "protoaudit.plugins"
BUILTIN_PLUGIN_SPECS = {
    "json-lines": "protoaudit.plugins.json_lines:JsonLinesPlugin",
    "finding-tags": "protoaudit.plugins.finding_tags:FindingTagPlugin",
}


@dataclass(slots=True)
class LoadedPlugin:
    name: str
    source: str
    plugin: Plugin


class PluginManager:
    def __init__(self, config: FrameworkConfig | None = None) -> None:
        self.config = config or FrameworkConfig()
        self._loaded: list[LoadedPlugin] = self._load_plugins()

    @property
    def plugins(self) -> list[Plugin]:
        return [item.plugin for item in self._loaded]

    def plugin_metadata(self) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        for item in self._loaded:
            rows.append(
                {
                    "name": item.name,
                    "source": item.source,
                    "description": getattr(item.plugin, "description", "") or "",
                    "applies_to": getattr(item.plugin, "applies_to", "*") or "*",
                }
            )
        return rows

    def apply(self, result: AnalysisResult) -> AnalysisResult:
        if not self._loaded:
            return result
        applied: list[str] = []
        for item in self._loaded:
            plugin = item.plugin
            if not plugin.should_apply(result, self.config):
                continue
            result = plugin.apply(result, self.config)
            applied.append(item.name)
        if applied:
            result.metadata.setdefault("applied_plugins", []).extend(applied)
        return result

    def _load_plugins(self) -> list[LoadedPlugin]:
        if not self.config.enable_plugins:
            return []
        specs = self._resolve_requested_plugin_specs()
        loaded: list[LoadedPlugin] = []
        seen: set[str] = set()
        for source_name, spec in specs:
            plugin = _instantiate_plugin(spec)
            if plugin.name in seen or not self.config.is_plugin_enabled(plugin.name):
                continue
            loaded.append(LoadedPlugin(name=plugin.name, source=source_name, plugin=plugin))
            seen.add(plugin.name)
        return loaded

    def _resolve_requested_plugin_specs(self) -> list[tuple[str, str]]:
        requested = list(self.config.plugins.enabled)
        if not requested:
            requested = [name for name, spec in BUILTIN_PLUGIN_SPECS.items() if _is_enabled_by_default(spec)]

        specs: list[tuple[str, str]] = []
        for item in requested:
            if ":" in item:
                specs.append(("config", item))
                continue
            builtin_spec = BUILTIN_PLUGIN_SPECS.get(item)
            if builtin_spec:
                specs.append(("builtin", builtin_spec))
                continue
            entry_spec = _entry_point_spec(item)
            if entry_spec:
                specs.append(("entry-point", entry_spec))
                continue
            raise ValueError(f"Unknown plugin requested: {item}")
        return specs


def _entry_point_spec(name: str) -> str | None:
    try:
        candidates = importlib_metadata.entry_points(group=ENTRY_POINT_GROUP)
    except TypeError:  # pragma: no cover
        candidates = importlib_metadata.entry_points().get(ENTRY_POINT_GROUP, [])
    for entry_point in candidates:
        if entry_point.name == name:
            return entry_point.value
    return None


def _is_enabled_by_default(spec: str) -> bool:
    plugin = _instantiate_plugin(spec)
    return getattr(plugin, "enabled_by_default", False) is True


def _instantiate_plugin(spec: str) -> Plugin:
    module_name, _, attribute = spec.partition(":")
    if not module_name or not attribute:
        raise ValueError(f"Invalid plugin specification: {spec}")
    module = importlib.import_module(module_name)
    obj: Any = getattr(module, attribute)
    plugin = obj() if isinstance(obj, type) else obj
    if not isinstance(plugin, Plugin):
        raise TypeError(f"Plugin spec did not resolve to a Plugin: {spec}")
    return plugin
