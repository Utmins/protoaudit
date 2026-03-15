# Case Studies

## Protocol Analyzer — Challenge Reuse Retry Loop

Path:

```text
examples/protocol/retry_loop_case_study/
```

This mini case study demonstrates a realistic authentication retry flow where the same challenge and proof material appear across multiple attempts.

Why it matters:

- shows transcript parsing on timestamped client/server traffic
- triggers message state tracking and phase inference
- demonstrates handshake detection and incomplete-handshake reporting
- produces multiple protocol findings from one compact capture

Recommended command:

```bash
protoaudit analyze protocol examples/protocol/retry_loop_case_study/session.txt --format markdown
```

Expected findings include:

- Challenge-like field observed
- Repeated protocol responses detected
- Challenge-like values repeat across messages
- Handshake-like flow appears incomplete
- Repeated protocol phase loop observed

## Protocol Analyzer — Cached Handshake Material Across Successful Sessions

Path:

```text
examples/protocol/cached_handshake_material_case_study/
```

This case study models a resume-style handshake that completes successfully twice while reusing the same challenge tuple and session identifier.

Why it matters:

- shows that ProtoAudit can flag deterministic behavior even when the handshake completes
- demonstrates repeated-response detection on a realistic server-side message pattern
- highlights challenge reuse in session-resumption style flows

Recommended command:

```bash
protoaudit analyze protocol examples/protocol/cached_handshake_material_case_study/session.txt --format markdown
```

Expected findings include:

- Challenge-like field observed
- Repeated protocol responses detected
- Challenge-like values repeat across messages
- Repeated protocol phase loop observed

## Protocol Analyzer — Structured Device Pairing Retry Loop

Path:

```text
examples/protocol/structured_pairing_retry_case_study/
```

This case uses structured JSON steps instead of a raw transcript and shows that ProtoAudit can reason over protocol harness fixtures and replay-style artifacts.

Why it matters:

- exercises structured script parsing rather than only transcript parsing
- validates message state tracking and phase inference on step-based protocol descriptions
- demonstrates repeated challenge and retry-loop behavior in onboarding flows

Recommended command:

```bash
protoaudit analyze protocol examples/protocol/structured_pairing_retry_case_study/script.json --format markdown
```

Expected findings include:

- Challenge-like field observed
- Repeated protocol responses detected
- Challenge-like values repeat across messages
- Handshake-like flow appears incomplete
- Repeated protocol phase loop observed
