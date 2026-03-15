"""Canonical domain models for protoaudit."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


class ArtifactType(str, Enum):
    TRANSCRIPT = "transcript"
    PROTOCOL_TRACE = "protocol_trace"
    CRYPTO_METADATA = "crypto_metadata"
    RANDOM_SEQUENCE = "random_sequence"
    SESSION_LOG = "session_log"
    GENERIC_TEXT = "generic_text"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(slots=True)
class Artifact:
    artifact_id: str
    artifact_type: ArtifactType
    source_path: str | None
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        *,
        artifact_type: ArtifactType,
        content: str,
        source_path: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> "Artifact":
        return cls(
            artifact_id=f"art-{uuid4().hex[:12]}",
            artifact_type=artifact_type,
            source_path=source_path,
            content=content,
            metadata=metadata or {},
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["artifact_type"] = self.artifact_type.value
        return data


@dataclass(slots=True)
class Evidence:
    evidence_id: str
    kind: str
    location: str | None
    summary: str
    raw_value: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        *,
        kind: str,
        summary: str,
        location: str | None = None,
        raw_value: Any = None,
        metadata: dict[str, Any] | None = None,
    ) -> "Evidence":
        return cls(
            evidence_id=f"evi-{uuid4().hex[:12]}",
            kind=kind,
            location=location,
            summary=summary,
            raw_value=raw_value,
            metadata=metadata or {},
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Finding:
    finding_id: str
    title: str
    description: str
    severity: Severity
    confidence: float
    analyzer: str
    recommendation: str
    evidence: list[Evidence] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        *,
        title: str,
        description: str,
        severity: Severity,
        confidence: float,
        analyzer: str,
        recommendation: str,
        evidence: list[Evidence] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> "Finding":
        return cls(
            finding_id=f"find-{uuid4().hex[:12]}",
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            analyzer=analyzer,
            recommendation=recommendation,
            evidence=evidence or [],
            metadata=metadata or {},
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass(slots=True)
class AnalysisResult:
    analyzer_name: str
    artifact: Artifact
    summary: str
    evidence: list[Evidence] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "analyzer_name": self.analyzer_name,
            "artifact": self.artifact.to_dict(),
            "summary": self.summary,
            "evidence": [item.to_dict() for item in self.evidence],
            "findings": [item.to_dict() for item in self.findings],
            "metrics": self.metrics,
            "metadata": self.metadata,
        }


@dataclass(slots=True)
class CorrelationResult:
    summary: str
    combined_findings: list[Finding] = field(default_factory=list)
    relationships: list[dict[str, Any]] = field(default_factory=list)
    risk_posture: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "combined_findings": [item.to_dict() for item in self.combined_findings],
            "relationships": self.relationships,
            "risk_posture": self.risk_posture,
        }


@dataclass(slots=True)
class ReportBundle:
    artifacts: list[Artifact]
    analysis_results: list[AnalysisResult]
    correlation_result: CorrelationResult | None
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tool_version: str = "0.2.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifacts": [item.to_dict() for item in self.artifacts],
            "analysis_results": [item.to_dict() for item in self.analysis_results],
            "correlation_result": None if self.correlation_result is None else self.correlation_result.to_dict(),
            "generated_at": self.generated_at,
            "tool_version": self.tool_version,
        }
