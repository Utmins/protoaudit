# Mini Case Study — Cached Handshake Material Across Successful Sessions

This case models a gateway that completes two nominally successful challenge-response handshakes, but appears to reuse the same ticket, nonce, proof material, and session identifier across both sessions.

## Scenario

An edge-connected device reconnects after a short link interruption. The server responds with what looks like a normal resume-style handshake, but every server-side control message is identical across both sessions, including the challenge tuple and final session identifier.

This is not proof of a break by itself. It is a realistic analysis case showing how ProtoAudit surfaces deterministic or cache-heavy behavior that deserves validation in session resumption logic.

## Run it

```bash
protoaudit analyze protocol examples/protocol/cached_handshake_material_case_study/session.txt --format markdown
```

## What ProtoAudit should detect

- challenge-like fields are present
- repeated protocol responses appear across both successful sessions
- challenge-like values repeat across messages
- the inferred handshake is complete
- the protocol state machine loops through the same phases multiple times

## Why this case is useful

This example demonstrates a realistic false-comfort scenario: the flow appears successful, yet the analyzer still highlights determinism that can undermine freshness assumptions during session resumption.

## Expected highlights

- Handshake style: `challenge-response`
- Handshake complete: `true`
- Repeated challenge-like value count: `4`
- Repeated response ratio: `0.5`
- Phase loop count: `5`
