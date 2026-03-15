# Quickstart

Install and test:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
pytest
```

Run a realistic protocol example:

```bash
protoaudit analyze protocol examples/transcripts/sample_transcript.txt --profile strict
```

Parse the same transcript:

```bash
protoaudit transcript parse examples/transcripts/sample_transcript.txt
```

Use a config file:

```bash
protoaudit --config examples/config.strict.json analyze protocol examples/transcripts/sample_transcript.txt
```

## Plugin quick check

```bash
protoaudit plugins list
protoaudit --config examples/config.plugins.json analyze protocol examples/protocol/retry_loop_case_study/session.txt
```
