# ProtoAudit

![Python](https://img.shields.io/badge/python-3.10+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-research--tool-orange)

ProtoAudit is a modular defensive framework for analyzing protocol behavior, cryptographic metadata, and randomness patterns — with practical utilities for transcript parsing, replay planning, fuzzing, extraction, and report rendering.

It is built for research-style inspection of protocol transcripts and related artifacts, not for stealthy scanning or offensive automation. The current version emphasizes rule-driven findings, cross-analyzer correlation, and realistic transcript handling.

## Current status

This repository now includes a working **Phase 4.3 migration baseline**:
- shared domain model and execution pipeline
- protocol / crypto / randomness analyzers
- protocol phase inference, state tracking, and handshake detection
- normalized Python rules with config-aware thresholds
- deeper artifact I/O and config loading
- transcript, replay, fuzzing, and extraction helpers
- console / JSON / Markdown / HTML reporting

Phase 5 is now enabled:
- runtime plugin loading
- built-in enrichment plugins
- plugin inspection via CLI

## Package and CLI

- Python package: `protoaudit`
- CLI: `protoaudit`

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
pytest
protoaudit --help
```

## Quick example

Analyze a realistic transcript:

```bash
protoaudit analyze protocol examples/transcripts/sample_transcript.txt --profile strict
```

Analyze bundled metadata examples:

```bash
protoaudit analyze crypto examples/crypto/sample_crypto.txt --format markdown
protoaudit analyze randomness examples/randomness/sample_randomness.txt --format json
```

Use a config file:

```bash
protoaudit --config examples/config.strict.json analyze protocol examples/transcripts/sample_transcript.txt
```

## Repository layout

```text
src/protoaudit/
  core/        shared models, engine, config, I/O, rules, correlation
  analyzers/   protocol, crypto, randomness analyzers
  toolkit/     transcript parsing, replay, fuzzing, extraction helpers
  rules/       normalized Python rules
  plugins/     optional extension points with runtime loading
  reporting/   console, JSON, Markdown, HTML renderers
```

## Command surface

```bash
protoaudit analyze protocol <input>
protoaudit analyze crypto <input>
protoaudit analyze randomness <input>
protoaudit correlate <result.json> [more_result.json ...]
protoaudit transcript parse <input>
protoaudit replay build <input>
protoaudit fuzz generate <input>
protoaudit extract blocks <input>
protoaudit extract json <input>
protoaudit plugins list
```

## Recommended first reads

- `docs/QUICKSTART.md`
- `docs/ARCHITECTURE.md`
- `docs/ANALYZERS.md`
- `docs/CONFIGURATION.md`
- `examples/demo_walkthrough.md`

## License

MIT


## Plugin quick start

```bash
protoaudit plugins list
protoaudit --config examples/config.plugins.json analyze protocol examples/protocol/retry_loop_case_study/session.txt --format json
```

See `docs/PLUGINS.md` for the runtime loading model.


## Additional Protocol Case Studies

ProtoAudit now ships with multiple protocol mini case studies under `examples/protocol/`:

- `retry_loop_case_study/` — incomplete authentication flow with challenge and proof reuse across retries
- `cached_handshake_material_case_study/` — apparently successful resumptions that reuse challenge material and session identifiers
- `structured_pairing_retry_case_study/` — structured JSON protocol script showing repeated challenge material in a pairing workflow

These cases are useful both as demo inputs and as regression fixtures for the protocol analyzer.
