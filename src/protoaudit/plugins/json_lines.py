"""Example plugin for JSON Lines enrichment."""

from __future__ import annotations

from protoaudit.core.config import FrameworkConfig
from protoaudit.core.models import AnalysisResult
from protoaudit.core.plugin_api import Plugin


class JsonLinesPlugin(Plugin):
    name = "json-lines"
    description = "Mark results that passed through the runtime plugin pipeline."
    applies_to = "*"
    enabled_by_default = False

    def apply(self, result: AnalysisResult, config: FrameworkConfig | None = None) -> AnalysisResult:
        del config
        result.metadata.setdefault("plugins", []).append(self.name)
        return result
