"""Command-line entry point for protoaudit."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from protoaudit.core.config import FrameworkConfig
from protoaudit.core.engine import AnalysisEngine
from protoaudit.core.io import load_artifact_from_path
from protoaudit.core.models import AnalysisResult, Artifact, ArtifactType, ReportBundle
from protoaudit.core.plugin_loader import PluginManager
from protoaudit.reporting.renderers import render_console_summary, render_html, render_json, render_markdown
from protoaudit.toolkit.extraction import extract_candidate_blocks, extract_json_objects
from protoaudit.toolkit.fuzzing import generate_mutations
from protoaudit.toolkit.replay import build_replay_plan
from protoaudit.toolkit.transcript import parse_transcript


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="protoaudit",
        description="Defensive protocol, crypto, and randomness analysis framework.",
    )
    parser.add_argument("--config", type=Path, help="Optional JSON/YAML config file.")
    parser.add_argument("--profile", choices=["default", "strict", "research"], default="default")
    parser.add_argument("--plugin", action="append", default=[], help="Enable one or more runtime plugins by name or module spec.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="Run an analyzer against an input artifact.")
    analyze_sub = analyze.add_subparsers(dest="analyzer", required=True)
    for name in ("protocol", "crypto", "randomness"):
        p = analyze_sub.add_parser(name, help=f"Run the {name} analyzer.")
        p.add_argument("input", type=Path, help="Input file to analyze.")
        p.add_argument("--format", choices=["console", "json", "markdown", "html"], default="console")
        p.add_argument("--out", type=Path)

    correlate = subparsers.add_parser("correlate", help="Run correlation on normalized result files.")
    correlate.add_argument("input", nargs="+", type=Path, help="One or more normalized JSON result bundles.")
    correlate.add_argument("--format", choices=["console", "json", "markdown", "html"], default="console")
    correlate.add_argument("--out", type=Path)

    transcript = subparsers.add_parser("transcript", help="Transcript utilities.")
    transcript_sub = transcript.add_subparsers(dest="transcript_command", required=True)
    transcript_parse = transcript_sub.add_parser("parse", help="Parse a transcript input.")
    transcript_parse.add_argument("input", type=Path)

    replay = subparsers.add_parser("replay", help="Replay utilities.")
    replay_sub = replay.add_subparsers(dest="replay_command", required=True)
    replay_build = replay_sub.add_parser("build", help="Build a replay plan from an input artifact.")
    replay_build.add_argument("input", type=Path)

    fuzz = subparsers.add_parser("fuzz", help="Fuzzing helpers.")
    fuzz_sub = fuzz.add_subparsers(dest="fuzz_command", required=True)
    fuzz_generate = fuzz_sub.add_parser("generate", help="Generate defensive fuzzing mutations.")
    fuzz_generate.add_argument("input", type=Path)

    extract = subparsers.add_parser("extract", help="Extract candidate artifacts from raw text.")
    extract_sub = extract.add_subparsers(dest="extract_command", required=True)
    extract_blocks = extract_sub.add_parser("blocks", help="Extract candidate text blocks.")
    extract_blocks.add_argument("input", type=Path)
    extract_json = extract_sub.add_parser("json", help="Extract embedded JSON objects.")
    extract_json.add_argument("input", type=Path)

    plugins = subparsers.add_parser("plugins", help="Inspect runtime plugin loading.")
    plugins_sub = plugins.add_subparsers(dest="plugins_command", required=True)
    plugins_list = plugins_sub.add_parser("list", help="List active runtime plugins.")
    plugins_list.add_argument("--format", choices=["json", "console"], default="console")

    return parser


def _render_bundle(bundle: ReportBundle, output_format: str) -> str:
    if output_format == "json":
        return render_json(bundle)
    if output_format == "markdown":
        return render_markdown(bundle)
    if output_format == "html":
        return render_html(bundle)
    return render_console_summary(bundle)


def _emit(text: str, out: Path | None) -> None:
    if out:
        out.write_text(text, encoding="utf-8")
    else:
        print(text)


def _build_config(args: argparse.Namespace) -> FrameworkConfig:
    overrides = None
    if getattr(args, "plugin", None):
        overrides = {"plugins": {"enabled": list(args.plugin)}}
    return FrameworkConfig.from_sources(path=args.config, profile=args.profile, overrides=overrides)


def _run_analyze(args: argparse.Namespace) -> int:
    artifact_type = {
        "protocol": ArtifactType.PROTOCOL_TRACE,
        "crypto": ArtifactType.CRYPTO_METADATA,
        "randomness": ArtifactType.RANDOM_SEQUENCE,
    }[args.analyzer]

    config = _build_config(args)
    artifact = load_artifact_from_path(args.input, artifact_type=artifact_type, config=config)
    engine = AnalysisEngine(config=config)
    bundle = engine.analyze(artifact=artifact, analyzer_name=args.analyzer)
    _emit(_render_bundle(bundle, args.format), args.out)
    return 0


def _result_from_dict(data: dict[str, Any]) -> AnalysisResult:
    result = data["analysis_results"][0]
    artifact_data = result["artifact"]
    artifact = Artifact.create(
        artifact_type=ArtifactType(artifact_data["artifact_type"]),
        content=artifact_data.get("content", ""),
        source_path=artifact_data.get("source_path"),
        metadata=artifact_data.get("metadata", {}),
    )
    evidence = []
    from protoaudit.core.models import Evidence, Finding, Severity
    for item in result.get("evidence", []):
        evidence.append(Evidence(
            evidence_id=item.get("evidence_id", "evi-imported"),
            kind=item["kind"],
            location=item.get("location"),
            summary=item["summary"],
            raw_value=item.get("raw_value"),
            metadata=item.get("metadata", {}),
        ))
    findings = []
    for item in result.get("findings", []):
        findings.append(Finding(
            finding_id=item.get("finding_id", "find-imported"),
            title=item["title"],
            description=item["description"],
            severity=Severity(item["severity"]),
            confidence=float(item.get("confidence", 0.0)),
            analyzer=item.get("analyzer", result["analyzer_name"]),
            recommendation=item.get("recommendation", ""),
            evidence=[],
            metadata=item.get("metadata", {}),
        ))
    return AnalysisResult(
        analyzer_name=result["analyzer_name"],
        artifact=artifact,
        summary=result["summary"],
        evidence=evidence,
        findings=findings,
        metrics=result.get("metrics", {}),
        metadata=result.get("metadata", {}),
    )


def _run_correlate(args: argparse.Namespace) -> int:
    config = _build_config(args)
    engine = AnalysisEngine(config=config)
    results: list[AnalysisResult] = []
    for path in args.input:
        data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        results.append(_result_from_dict(data))
    bundle = engine.correlate_results(results)
    _emit(_render_bundle(bundle, args.format), args.out)
    return 0


def _run_transcript(args: argparse.Namespace) -> int:
    parsed = parse_transcript(args.input.read_text(encoding="utf-8"))
    print(json.dumps(parsed.to_dict(), indent=2, ensure_ascii=False))
    return 0


def _run_replay(args: argparse.Namespace) -> int:
    plan = build_replay_plan(args.input.read_text(encoding="utf-8"))
    print(json.dumps(plan, indent=2, ensure_ascii=False))
    return 0


def _run_fuzz(args: argparse.Namespace) -> int:
    mutations = generate_mutations(args.input.read_text(encoding="utf-8").strip())
    print(json.dumps({"mutation_count": len(mutations), "mutations": mutations}, indent=2, ensure_ascii=False))
    return 0


def _run_extract(args: argparse.Namespace) -> int:
    raw_text = args.input.read_text(encoding="utf-8")
    if args.extract_command == "blocks":
        print(json.dumps({"block_count": len(extract_candidate_blocks(raw_text)), "blocks": extract_candidate_blocks(raw_text)}, indent=2, ensure_ascii=False))
        return 0
    if args.extract_command == "json":
        objects = extract_json_objects(raw_text)
        print(json.dumps({"object_count": len(objects), "objects": objects}, indent=2, ensure_ascii=False))
        return 0
    return 2




def _run_plugins(args: argparse.Namespace) -> int:
    config = _build_config(args)
    manager = PluginManager(config=config)
    payload = {
        "plugin_count": len(manager.plugins),
        "plugins": manager.plugin_metadata(),
    }
    if args.format == "json":
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0
    print(f"Active plugins: {payload['plugin_count']}")
    for plugin in payload["plugins"]:
        print(f"- {plugin['name']} [{plugin['source']}] applies_to={plugin['applies_to']}")
        if plugin["description"]:
            print(f"  {plugin['description']}")
    return 0

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "analyze":
        return _run_analyze(args)
    if args.command == "correlate":
        return _run_correlate(args)
    if args.command == "transcript":
        return _run_transcript(args)
    if args.command == "replay":
        return _run_replay(args)
    if args.command == "fuzz":
        return _run_fuzz(args)
    if args.command == "extract":
        return _run_extract(args)
    if args.command == "plugins":
        return _run_plugins(args)

    parser.error("Unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
