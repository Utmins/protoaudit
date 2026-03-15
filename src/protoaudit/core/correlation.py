"""Cross-analyzer correlation layer."""

from __future__ import annotations

from protoaudit.core.models import AnalysisResult, CorrelationResult, Finding, Severity


class CorrelationEngine:
    def correlate(self, results: list[AnalysisResult]) -> CorrelationResult:
        if not results:
            return CorrelationResult(summary="No analysis results available for correlation.", risk_posture="unknown")

        protocol_result = next((r for r in results if r.analyzer_name == "protocol"), None)
        crypto_result = next((r for r in results if r.analyzer_name == "crypto"), None)
        randomness_result = next((r for r in results if r.analyzer_name == "randomness"), None)

        combined_findings: list[Finding] = []
        relationships: list[dict[str, str]] = []

        if protocol_result and randomness_result:
            repeated_ratio = float(randomness_result.metrics.get("repeated_ratio", 0.0))
            protocol_transcript = any(item.kind == "protocol.transcript" for item in protocol_result.evidence)
            if repeated_ratio > 0 and protocol_transcript:
                relationships.append({
                    "source": "protocol",
                    "target": "randomness",
                    "title": "Protocol behavior may depend on weak randomness",
                })
                combined_findings.append(
                    Finding.create(
                        title="Protocol behavior may depend on weak randomness",
                        description="Repeated or low-variance outputs in randomness analysis align with observed interactive protocol behavior.",
                        severity=Severity.MEDIUM,
                        confidence=0.8,
                        analyzer="correlation",
                        recommendation="Review challenge generation and replay resistance across the interactive flow.",
                        evidence=protocol_result.evidence[:1] + randomness_result.evidence[:1],
                        metadata={"relationship": "protocol-randomness"},
                    )
                )

        if protocol_result and crypto_result and crypto_result.findings:
            relationships.append({
                "source": "protocol",
                "target": "crypto",
                "title": "Protocol should be reviewed alongside crypto controls",
            })
            combined_findings.append(
                Finding.create(
                    title="Protocol should be reviewed alongside crypto controls",
                    description="Interactive protocol handling exists in a system that also exposes design-level cryptographic weaknesses.",
                    severity=Severity.MEDIUM,
                    confidence=0.75,
                    analyzer="correlation",
                    recommendation="Review transcript binding, participant trust, and cryptographic validation as one system rather than isolated layers.",
                    evidence=protocol_result.evidence[:1] + crypto_result.evidence[:1],
                    metadata={"relationship": "protocol-crypto"},
                )
            )

        if crypto_result and randomness_result and crypto_result.findings and randomness_result.findings:
            relationships.append({
                "source": "crypto",
                "target": "randomness",
                "title": "Multiple trust-boundary weaknesses",
            })
            combined_findings.append(
                Finding.create(
                    title="Multiple trust-boundary weaknesses",
                    description="The target appears to have both cryptographic design issues and randomness quality concerns.",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    analyzer="correlation",
                    recommendation="Treat cryptographic design review and randomness review as a combined remediation track.",
                    evidence=crypto_result.evidence[:1] + randomness_result.evidence[:1],
                    metadata={"relationship": "crypto-randomness"},
                )
            )

        risk_posture = "elevated" if combined_findings else "limited-signals"
        summary = (
            "Correlation identified cross-module relationships." if combined_findings
            else "No cross-module relationships were strong enough to elevate risk posture."
        )
        return CorrelationResult(
            summary=summary,
            combined_findings=combined_findings,
            relationships=relationships,
            risk_posture=risk_posture,
        )
