"""Built-in plugin that derives compact tags from findings."""

from __future__ import annotations

from protoaudit.core.config import FrameworkConfig
from protoaudit.core.models import AnalysisResult
from protoaudit.core.plugin_api import Plugin


class FindingTagPlugin(Plugin):
    name = "finding-tags"
    description = "Derive compact severity and topical tags from emitted findings."
    applies_to = "*"
    enabled_by_default = False

    def apply(self, result: AnalysisResult, config: FrameworkConfig | None = None) -> AnalysisResult:
        del config
        tags: set[str] = set(result.metadata.get("tags", []))
        for finding in result.findings:
            tags.add(f"severity:{finding.severity.value}")
            rule_id = finding.metadata.get("rule_id")
            if isinstance(rule_id, str) and rule_id:
                tags.add(f"rule:{rule_id}")
            title = finding.title.lower()
            if "handshake" in title:
                tags.add("topic:handshake")
            if "random" in title or "nonce" in title or "challenge" in title:
                tags.add("topic:freshness")
            if "crypto" in title or "public key" in title or "proof-of-possession" in title:
                tags.add("topic:crypto")
        if tags:
            result.metadata["tags"] = sorted(tags)
        return result
