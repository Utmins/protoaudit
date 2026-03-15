"""Plugin contracts for optional extensions."""

from __future__ import annotations

from abc import ABC, abstractmethod

from protoaudit.core.config import FrameworkConfig
from protoaudit.core.models import AnalysisResult


class Plugin(ABC):
    """Base contract for protoaudit plugins."""

    name: str = "unnamed-plugin"
    description: str = ""
    applies_to: str = "*"
    enabled_by_default: bool = False

    def should_apply(self, result: AnalysisResult, config: FrameworkConfig | None = None) -> bool:
        del config
        return self.applies_to in ("*", result.analyzer_name)

    @abstractmethod
    def apply(self, result: AnalysisResult, config: FrameworkConfig | None = None) -> AnalysisResult:
        """Return an enriched or transformed analysis result."""
