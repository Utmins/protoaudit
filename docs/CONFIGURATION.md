# Configuration

ProtoAudit supports lightweight configuration through JSON or YAML files plus profile selection.

## Profiles

Built-in profiles:
- `default`
- `strict`
- `research`

The strict profile lowers some thresholds so repeated responses and phase loops are surfaced sooner.

## Example

```bash
protoaudit --config examples/config.strict.json analyze protocol examples/transcripts/sample_transcript.txt
```

## Supported top-level keys

- `profile`
- `enable_rules`
- `enable_correlation`
- `default_output_format`
- `thresholds`
- `rule_policy`
- `io`
- `analyzer_settings`

## Rule policy

```json
{
  "rule_policy": {
    "disabled_rule_ids": ["PROTO-002"],
    "enabled_rule_ids": []
  }
}
```

## I/O settings

```json
{
  "io": {
    "recursive": true,
    "max_file_size_bytes": 5000000,
    "structured_suffixes": [".json", ".yaml", ".yml"]
  }
}
```
