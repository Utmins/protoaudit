# Phase 4.2 Mapping Report

This report records how the legacy archives map into the canonical `protoaudit` repo and what changed during the second migration tranche.

## Legacy → Target Mapping

| Legacy source | New target | Status | Notes |
|---|---|---:|---|
| `mini_security_framework/security_framework/modules/protocol.py` | `src/protoaudit/analyzers/protocol.py` | partial | Early analyzer logic replaced by normalized transcript-centric analyzer. |
| `mini_security_framework/security_framework/modules/crypto.py` | `src/protoaudit/analyzers/crypto.py` | partial | Legacy metadata checks normalized into shared metrics/evidence model. |
| `mini_security_framework/security_framework/modules/rng.py` | `src/protoaudit/analyzers/randomness.py` | partial | RNG heuristics preserved and expanded. |
| `mini_security_framework_v2/security_framework/models.py` | `src/protoaudit/core/models.py` | migrated | Shared domain model kept and expanded into artifact/result/report bundle types. |
| `mini_security_framework_v2/security_framework/reporting.py` | `src/protoaudit/reporting/renderers.py` | migrated | Reporting normalized to console/json/markdown/html renderers. |
| `mini_security_framework_v3/security_framework/io_utils.py` | `src/protoaudit/core/io.py` | migrated | Structured file loading preserved; Phase 4.2 adds structured dumping and type inference. |
| `mini_security_framework_v3/security_framework/correlation.py` | `src/protoaudit/core/correlation.py` | migrated | Correlation logic preserved and converted to normalized findings. |
| `mini_security_framework_v3/security_framework/rule_loader.py` | `src/protoaudit/core/rule_engine.py` | partial | Old JSON loader replaced with Python rule contract. Plugin loading deferred to Phase 5. |
| `mini_security_framework_v3/security_framework/plugin_api.py` | `src/protoaudit/core/plugin_api.py` | deferred | Contract exists, runtime loading deferred to Phase 5. |
| `final_security_framework/security_framework/modules/protocol.py` | `src/protoaudit/analyzers/protocol.py`, `src/protoaudit/toolkit/replay.py` | partial | Structured step/script semantics preserved; active socket execution intentionally not migrated. |
| `final_security_framework/security_framework/modules/crypto.py` | `src/protoaudit/analyzers/crypto.py`, `src/protoaudit/rules/crypto_rules.py` | migrated | Metadata-driven risk logic split into analyzer + rules. |
| `final_security_framework/security_framework/modules/rng.py` | `src/protoaudit/analyzers/randomness.py`, `src/protoaudit/rules/randomness_rules.py` | migrated | Recovery-feasibility and metadata-based leakage logic preserved. |
| `final_security_framework/security_framework/rules/crypto_rules.py` | `src/protoaudit/rules/crypto_rules.py` | migrated | Rule IDs preserved and expanded. |
| `final_security_framework/security_framework/rules/rng_rules.py` | `src/protoaudit/rules/randomness_rules.py` | migrated | Deterministic/custom RNG logic preserved and expanded. |
| `universal_tools/protocol_audit_client.py` | `src/protoaudit/toolkit/transcript.py`, `src/protoaudit/toolkit/replay.py`, `src/protoaudit/analyzers/protocol.py` | partial | Parsing, replay-plan, repeated-value thinking migrated; live network audit client intentionally deferred. |
| `universal_tools/crypto_protocol_checker.py` | `src/protoaudit/analyzers/crypto.py`, `src/protoaudit/rules/crypto_rules.py` | partial | Defensive framing preserved; full markdown-only standalone CLI not migrated. |
| `universal_tools/rng_leakage_analyzer.py` | `src/protoaudit/analyzers/randomness.py`, `src/protoaudit/rules/randomness_rules.py` | migrated | Entropy/diversity/prefix/truncation logic migrated. |
| `ctf_protocol_analysis_toolkit/toolkit/transcript.py` | `src/protoaudit/toolkit/transcript.py` | migrated | Save/parse story merged into normalized transcript helper. |
| `ctf_protocol_analysis_toolkit/toolkit/fuzzing.py` | `src/protoaudit/toolkit/fuzzing.py` | migrated | Lightweight mutation helper expanded. |
| `ctf_protocol_analysis_toolkit/toolkit/protocol.py` | `src/protoaudit/toolkit/replay.py`, `src/protoaudit/cli.py` | partial | Saved-transcript replay idea preserved; raw socket client intentionally not migrated. |
| `ctf_protocol_analysis_toolkit/toolkit/randomness.py` | `src/protoaudit/analyzers/randomness.py` | migrated | Entropy calculation subsumed by analyzer. |

## Second Migration Tranche Summary

Phase 4.2 focused on **depth**, not breadth:

- strengthened `core/io.py` with structured load/dump and type inference
- expanded `protocol.py` with repeated challenge-value detection and message-shape summaries
- expanded `crypto.py` to expose domain-separation and participant-binding metrics
- expanded `randomness.py` with truncation/state-recovery reasoning
- expanded protocol/crypto/randomness rules based on final framework + universal tools
- improved `toolkit/` with JSON-object extraction and saved-transcript replay support
- added extraction CLI commands
- added test coverage for I/O, toolkit, and stronger analyzer/rule behavior

## Deferred to Phase 5

- runtime plugin loading
- optional live protocol client / active socket audit mode
- more sophisticated config profiles
- deeper docs and contributor guidance
