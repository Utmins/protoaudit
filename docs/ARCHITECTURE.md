# Architecture

`protoaudit` follows a framework-first, toolkit-on-top design.

## Pipeline

```text
Raw Input
  -> core.io
  -> Artifact
  -> analyzer
  -> AnalysisResult
  -> rule engine
  -> correlation
  -> ReportBundle
  -> reporting / CLI
```

## Layer boundaries

- `core/` owns shared execution and models
- `analyzers/` generate normalized analysis results
- `toolkit/` provides practical utilities on top of framework primitives
- `rules/` converts evidence into normalized findings
- `reporting/` renders output without embedding analysis logic

## Plugin Manager

The runtime plugin manager loads built-in plugins, explicit module specs, or installed entry points after rule evaluation and before final bundle rendering.
