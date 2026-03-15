# ProtoAudit Example Walkthrough

## Parse a transcript

```bash
protoaudit transcript parse examples/transcripts/sample_transcript.txt
```

## Run protocol analysis

```bash
protoaudit analyze protocol examples/transcripts/sample_transcript.txt --profile strict
```

Expected signals:
- repeated challenge values
- repeated responses
- challenge-response handshake detection
- repeated phase loop detection

## Run crypto analysis

```bash
protoaudit analyze crypto examples/crypto/sample_crypto.txt --format markdown
```

Expected signals:
- missing proof of possession
- missing domain separation
- missing participant binding

## Run randomness analysis

```bash
protoaudit analyze randomness examples/randomness/sample_randomness.txt --format json
```
