# ProtoAudit Report

**Generated:** 2026-03-14T22:31:45.250396+00:00

## Analyzer: protocol

**Artifact:** `examples/protocol/structured_pairing_retry_case_study/script.json`

### Summary
Processed 10 protocol messages; extracted 4 challenge-like indicators; observed 5 repeated server responses; detected 4 repeated challenge-like values; inferred challenge-response handshake; handshake incomplete.

### Findings

#### 1. Challenge-like values repeat across messages
- Severity: **medium**
- Confidence: **0.90**
- Description: A value labeled as a challenge, nonce, token, or similar field appears to repeat across messages.
- Recommendation: Validate freshness guarantees and confirm whether these fields are truly session-unique rather than labels for static identifiers.
- Evidence:
  - `protocol.transcript`: Normalized protocol transcript available for downstream rules.
  - `protocol.parser_summary`: Protocol transcript summary and extracted indicators.
  - `protocol.state_tracking`: Inferred protocol phases and state transitions.
  - `protocol.script`: Input artifact contains a structured protocol script.

#### 2. Repeated protocol phase loop observed
- Severity: **medium**
- Confidence: **0.78**
- Description: The inferred state machine revisits the same transition patterns multiple times, which can indicate retries, loops, or replay-prone behavior.
- Recommendation: Review whether repeated state transitions are expected for retries or whether challenge/response material is being reused across attempts.
- Evidence:
  - `protocol.transcript`: Normalized protocol transcript available for downstream rules.
  - `protocol.parser_summary`: Protocol transcript summary and extracted indicators.
  - `protocol.state_tracking`: Inferred protocol phases and state transitions.

#### 3. Repeated protocol responses detected
- Severity: **low**
- Confidence: **0.80**
- Description: Repeated inbound responses may indicate deterministic server behavior, weak challenge handling, or limited transcript variability.
- Recommendation: Replay the same interaction under controlled conditions and verify whether deterministic responses are expected.
- Evidence:
  - `protocol.transcript`: Normalized protocol transcript available for downstream rules.
  - `protocol.parser_summary`: Protocol transcript summary and extracted indicators.

#### 4. Handshake-like flow appears incomplete
- Severity: **low**
- Confidence: **0.76**
- Description: The transcript contains a recognizable handshake pattern, but it does not appear to reach an acknowledgement or completion phase.
- Recommendation: Confirm whether the capture is truncated or whether the protocol genuinely permits partial handshakes without explicit completion.
- Evidence:
  - `protocol.transcript`: Normalized protocol transcript available for downstream rules.
  - `protocol.parser_summary`: Protocol transcript summary and extracted indicators.
  - `protocol.state_tracking`: Inferred protocol phases and state transitions.

#### 5. Challenge-like field observed
- Severity: **info**
- Confidence: **0.90**
- Description: The transcript or script contains challenge-like fields that may require replay-resistance and binding review.
- Recommendation: Review challenge generation, binding, and nonce lifecycle assumptions in the protocol flow.
- Evidence:
  - `protocol.transcript`: Normalized protocol transcript available for downstream rules.
  - `protocol.parser_summary`: Protocol transcript summary and extracted indicators.

## Correlation

No cross-module relationships were strong enough to elevate risk posture.

**Risk posture:** `limited-signals`
