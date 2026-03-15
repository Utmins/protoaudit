# Runtime Plugins

ProtoAudit Phase 5 enables runtime plugin loading.

## Supported loading modes

1. Built-in plugins by short name
2. Explicit module specs in the form `package.module:ClassName`
3. Installed entry points under the `protoaudit.plugins` group

## Built-in plugins

- `json-lines` — marks results that passed through the plugin pipeline
- `finding-tags` — derives compact tags from emitted findings

## CLI usage

```bash
protoaudit plugins list
protoaudit --plugin json-lines --plugin finding-tags plugins list --format json
```

## Config usage

```json
{
  "enable_plugins": true,
  "plugins": {
    "enabled": ["json-lines", "finding-tags"]
  }
}
```

## Notes

Plugins are enrichment hooks. They do not replace analyzers or rules. The current plugin interface operates on normalized `AnalysisResult` objects after rules have run.
