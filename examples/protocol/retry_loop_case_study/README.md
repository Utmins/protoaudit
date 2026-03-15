# Mini Case Study — Challenge Reuse Across Authentication Retries

This example simulates a compact challenge-response authentication flow captured from a client repeatedly retrying against the same gateway.

## Scenario

A mobile client starts an authentication exchange, receives a challenge, sends a proof, and then receives an `AUTH_RETRY` response. On the second attempt, the gateway issues the **same** challenge value and the client produces the **same** proof again. The transcript ends without an acknowledgement or completion message.

This is not presented as proof of a vulnerability by itself. It is a realistic research example showing how ProtoAudit highlights replay-prone or determinism-heavy behavior that deserves review.

## Run it

```bash
protoaudit analyze protocol examples/protocol/retry_loop_case_study/session.txt --format markdown
```

## What ProtoAudit should detect

- challenge-like fields are present
- repeated challenge values are reused across attempts
- repeated protocol responses appear across server-side retry messages
- the inferred handshake is incomplete
- the protocol state machine loops through the same phases multiple times

## Why this case is useful

This example is stronger than a toy transcript because it combines multiple realistic signals in one compact flow:

1. **retry semantics** rather than a single static request/response pair
2. **challenge reuse** across repeated attempts
3. **deterministic proof reuse** under the same challenge
4. **missing completion phase** despite multiple rounds
5. **state-loop evidence** that supports follow-up replay testing

## Expected highlights

- Handshake style: `challenge-response`
- Handshake complete: `false`
- Repeated challenge-like value count: `1`
- Phase loop count: `4`
- Repeated response ratio: `0.5`

See also:

- `protocol_report.json`
- `protocol_report.md`
