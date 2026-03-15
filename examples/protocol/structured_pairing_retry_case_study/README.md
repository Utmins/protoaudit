# Mini Case Study — Structured Device Pairing Retry Loop

This case uses ProtoAudit's structured protocol-script input rather than a raw transcript. It models a device onboarding flow where the pairing service retries the exchange, but the challenge and token material remain fixed across attempts.

## Scenario

A low-power sensor enters a pairing workflow. The service emits a challenge and token, receives a proof, and returns a retry status because upstream processing is delayed. On the second attempt, the pairing service reuses the exact same challenge and token values instead of issuing fresh material.

This case is useful because it exercises the protocol analyzer's script semantics and state tracking, not just free-form transcript parsing.

## Run it

```bash
protoaudit analyze protocol examples/protocol/structured_pairing_retry_case_study/script.json --format markdown
```

## What ProtoAudit should detect

- challenge-like fields are present
- repeated protocol responses are visible in the structured script
- challenge-like values repeat across steps
- the inferred handshake is incomplete
- the protocol state machine loops through the same phases multiple times

## Why this case is useful

This example proves the framework is not limited to raw text transcripts. It can also normalize and inspect structured protocol descriptions that show up in design docs, harnesses, or replay fixtures.

## Expected highlights

- Handshake style: `challenge-response`
- Handshake complete: `false`
- Repeated challenge-like value count: `4`
- Repeated response ratio: `0.5`
- Phase loop count: `4`
