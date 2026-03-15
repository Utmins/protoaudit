# Contributing

Thanks for contributing.

## Principles

- keep the shared domain model coherent
- do not let analyzer logic leak into CLI or reporting
- prefer normalized findings over ad hoc text output
- preserve the framework-first, toolkit-on-top architecture

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
pytest
```

## Pull request expectations

- clear scope
- tests for meaningful logic changes
- no silent architecture drift
- update docs when interfaces change
