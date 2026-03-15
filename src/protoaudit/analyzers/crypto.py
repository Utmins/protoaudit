"""Crypto analyzer migrated from legacy metadata-driven checks."""

from __future__ import annotations

from typing import Any

from protoaudit.core.models import AnalysisResult, Artifact, Evidence


class CryptoAnalyzer:
    name = "crypto"

    def analyze(self, artifact: Artifact) -> AnalysisResult:
        metadata = self._extract_metadata(artifact)

        primitive = str(
            metadata.get("scheme_type")
            or metadata.get("primitive")
            or metadata.get("generator_family")
            or "unknown"
        )
        aggregate = primitive in {"aggregate_signature", "multi_signature", "threshold_signature"}
        proof_of_possession = self._boolish(self._coalesce(
            metadata.get("proof_of_possession"),
            self._get_nested(metadata, "controls.proof_of_possession"),
        ))
        accepts_untrusted_pubkeys = self._boolish(self._coalesce(
            metadata.get("accepts_untrusted_pubkeys"),
            self._get_nested(metadata, "trust.accepts_untrusted_pubkeys"),
        ))
        domain_separation = self._boolish(self._coalesce(
            metadata.get("domain_separation"),
            self._get_nested(metadata, "controls.domain_separation"),
        ))
        binds_participants = self._boolish(self._coalesce(
            metadata.get("verifier_binds_participants"),
            self._get_nested(metadata, "verification.binds_participants"),
        ))
        binds_message_context = self._boolish(self._coalesce(
            metadata.get("binds_message_context"),
            self._get_nested(metadata, "verification.binds_message_context"),
        ))

        capabilities = {
            "primitive": primitive,
            "aggregate_support": aggregate,
            "proof_of_possession_required": proof_of_possession,
            "accepts_untrusted_pubkeys": accepts_untrusted_pubkeys,
            "domain_separation": domain_separation,
            "verifier_binds_participants": binds_participants,
            "binds_message_context": binds_message_context,
        }
        evidence = [
            Evidence.create(
                kind="crypto.metadata",
                summary="Normalized crypto metadata prepared for rule evaluation.",
                raw_value=metadata,
            ),
            Evidence.create(
                kind="crypto.capabilities",
                summary="Derived design assumptions and trust-boundary capabilities.",
                raw_value=capabilities,
            ),
        ]

        return AnalysisResult(
            analyzer_name=self.name,
            artifact=artifact,
            summary=self._build_summary(primitive, aggregate, proof_of_possession, accepts_untrusted_pubkeys, domain_separation, binds_participants),
            evidence=evidence,
            metrics=capabilities,
            metadata={"status": "migrated-phase4.2"},
        )

    def _extract_metadata(self, artifact: Artifact) -> dict[str, Any]:
        parsed = artifact.metadata.get("parsed")
        if isinstance(parsed, dict):
            return parsed
        return {"raw_text": artifact.content}

    def _get_nested(self, data: dict[str, Any], path: str, default: Any = None) -> Any:
        current: Any = data
        for part in path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return default
        return current

    def _coalesce(self, *values: Any) -> Any:
        for value in values:
            if value is not None:
                return value
        return None

    def _boolish(self, value: Any) -> bool | None:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"true", "yes", "1", "present", "enabled"}:
                return True
            if lowered in {"false", "no", "0", "missing", "disabled"}:
                return False
        return None

    def _build_summary(
        self,
        primitive: str,
        aggregate: bool | None,
        pop: bool | None,
        accepts_untrusted_pubkeys: bool | None,
        domain_separation: bool | None,
        binds_participants: bool | None,
    ) -> str:
        parts = [f"Primitive: {primitive}"]
        if aggregate is True:
            parts.append("aggregate or multi-party support detected")
        if pop is False:
            parts.append("proof-of-possession appears to be absent")
        if accepts_untrusted_pubkeys is True:
            parts.append("untrusted public keys appear to be accepted")
        if domain_separation is False:
            parts.append("domain separation appears absent")
        if binds_participants is False:
            parts.append("verifier may not bind participant set")
        return "; ".join(parts) + "."
