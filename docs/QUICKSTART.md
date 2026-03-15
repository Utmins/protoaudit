# Quickstart

## 1. Install and verify

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
pytest
```

## 2. Run the most useful first example

```bash
protoaudit analyze protocol examples/protocol/retry_loop_case_study/session.txt --profile strict
```

What this gives you:

- timestamped client/server transcript parsing
- protocol phase inference
- repeated challenge / response detection
- incomplete-handshake reporting
- retry-loop detection

## 3. Parse the same transcript directly

```bash
protoaudit transcript parse examples/protocol/retry_loop_case_study/session.txt
```

## 4. Try the structured protocol example

```bash
protoaudit analyze protocol examples/protocol/structured_pairing_retry_case_study/script.json --format markdown
```

## 5. Try config-driven analysis

```bash
protoaudit --config examples/config.strict.json analyze protocol examples/transcripts/sample_transcript.txt
```

## 6. Try plugin-enabled analysis

```bash
protoaudit plugins list
protoaudit --config examples/config.plugins.json analyze protocol examples/protocol/retry_loop_case_study/session.txt --format json
```
