# Case Studies

These examples are meant to show how ProtoAudit behaves on realistic protocol artifacts rather than toy one-line inputs.

## Summary matrix

| Case study | Input | Scenario | Typical findings |
|---|---|---|---|
| `retry_loop_case_study/` | transcript | authentication retry with repeated challenge and proof | repeated responses, challenge reuse, incomplete handshake, phase loop |
| `cached_handshake_material_case_study/` | transcript | successful-looking resumed handshake reusing session material | repeated responses, challenge reuse, repeated phase loop |
| `structured_pairing_retry_case_study/` | structured JSON script | onboarding / pairing retry reusing challenge, token, and proof | repeated responses, challenge reuse, incomplete handshake, phase loop |

---

## Protocol Analyzer — Challenge Reuse Retry Loop

Path:

```text
examples/protocol/retry_loop_case_study/
```

Scenario:
A client attempts an authentication flow, receives a challenge, responds, is told to retry, and then receives the same challenge again. The follow-up proof also repeats, and the flow never reaches completion.

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

---

## Protocol Analyzer — Cached Handshake Material Across Successful Sessions

Path:

```text
examples/protocol/cached_handshake_material_case_study/
```

Scenario:
Two resume-style handshake sessions appear to complete successfully, but they reuse the same challenge tuple, proof, and session identifier. The flow looks healthy unless you inspect freshness.

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

---

## Protocol Analyzer — Structured Device Pairing Retry Loop

Path:

```text
examples/protocol/structured_pairing_retry_case_study/
```

Scenario:
A device onboarding / pairing workflow is described as structured JSON rather than a raw transcript. Across retries, the same challenge, token, and proof are reused, and the handshake remains incomplete.

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
