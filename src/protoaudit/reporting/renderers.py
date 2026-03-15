"""Renderers for normalized report bundles."""

from __future__ import annotations

import html
import json

from protoaudit.core.models import Finding, ReportBundle


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def render_console_summary(bundle: ReportBundle) -> str:
    result = bundle.analysis_results[0]
    lines = [
        "=== PROTOAUDIT SUMMARY ===",
        f"Analyzer: {result.analyzer_name}",
        f"Artifact: {result.artifact.source_path or '<memory>'}",
        f"Summary: {result.summary}",
        f"Evidence count: {len(result.evidence)}",
        f"Finding count: {len(result.findings)}",
    ]
    if result.findings:
        lines.append("Top findings:")
        for finding in sorted(result.findings, key=lambda item: SEVERITY_ORDER[item.severity.value], reverse=True)[:5]:
            lines.append(f"- [{finding.severity.value.upper()}] {finding.title}")
    if bundle.correlation_result and bundle.correlation_result.combined_findings:
        lines.append(f"Correlation findings: {len(bundle.correlation_result.combined_findings)}")
        lines.append(f"Risk posture: {bundle.correlation_result.risk_posture}")
    return "\n".join(lines)


def render_json(bundle: ReportBundle) -> str:
    return json.dumps(bundle.to_dict(), indent=2, ensure_ascii=False)


def render_markdown(bundle: ReportBundle) -> str:
    lines = ["# ProtoAudit Report", "", f"**Generated:** {bundle.generated_at}", ""]
    for result in bundle.analysis_results:
        lines.extend([
            f"## Analyzer: {result.analyzer_name}",
            "",
            f"**Artifact:** `{result.artifact.source_path or '<memory>'}`",
            "",
            f"### Summary\n{result.summary}",
            "",
            "### Findings",
            "",
        ])
        findings = sorted(result.findings, key=lambda item: SEVERITY_ORDER[item.severity.value], reverse=True)
        if not findings:
            lines.append("No findings were emitted.")
            lines.append("")
            continue
        for index, finding in enumerate(findings, start=1):
            lines.extend(_render_finding(index, finding))
    if bundle.correlation_result:
        lines.extend([
            "## Correlation",
            "",
            bundle.correlation_result.summary,
            "",
            f"**Risk posture:** `{bundle.correlation_result.risk_posture}`",
            "",
        ])
        if bundle.correlation_result.combined_findings:
            for index, finding in enumerate(bundle.correlation_result.combined_findings, start=1):
                lines.extend(_render_finding(index, finding))
    return "\n".join(lines)


def _render_finding(index: int, finding: Finding) -> list[str]:
    rows = [
        f"#### {index}. {finding.title}",
        f"- Severity: **{finding.severity.value}**",
        f"- Confidence: **{finding.confidence:.2f}**",
        f"- Description: {finding.description}",
        f"- Recommendation: {finding.recommendation}",
    ]
    if finding.evidence:
        rows.append("- Evidence:")
        for item in finding.evidence:
            rows.append(f"  - `{item.kind}`: {item.summary}")
    rows.append("")
    return rows


def render_html(bundle: ReportBundle) -> str:
    markdown = render_markdown(bundle)
    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>ProtoAudit Report</title>"
        "<style>body{font-family:Arial,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;line-height:1.5}"
        "code{background:#f3f3f3;padding:.1rem .25rem}pre{white-space:pre-wrap}</style></head>"
        f"<body><pre>{html.escape(markdown)}</pre></body></html>"
    )
