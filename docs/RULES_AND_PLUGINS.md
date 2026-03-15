# Rules and Plugins

## Rules

Rules are Python objects evaluated against normalized `AnalysisResult` objects.

## Plugins

Plugins are optional enrichers and adapters that should not become the primary execution model.


## Runtime plugins

Rules create findings. Plugins enrich normalized `AnalysisResult` objects after rules have run.
