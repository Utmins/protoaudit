"""Artifact I/O and normalization helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import json
import re

from protoaudit.core.config import FrameworkConfig
from protoaudit.core.models import Artifact, ArtifactType

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None


TRANSCRIPT_LINE_RE = re.compile(r"^\s*(?:\[[^\]]+\]\s*)?(?:[A-Za-z0-9_-]+\s*->\s*[A-Za-z0-9_-]+\s*:|send:|recv:|tx:|rx:|<|>)")
SUPPORTED_STRUCTURED_SUFFIXES = {".json", ".yaml", ".yml"}


def load_structured_file(path: str | Path) -> Any:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Input file not found: {file_path}")
    suffix = file_path.suffix.lower()
    content = file_path.read_text(encoding="utf-8")
    if suffix == ".json":
        return json.loads(content)
    if suffix in {".yaml", ".yml"}:
        if yaml is None:
            raise RuntimeError("PyYAML is required to read YAML inputs")
        return yaml.safe_load(content)
    raise ValueError(f"Unsupported file format: {suffix}")


def dump_structured_file(path: str | Path, data: Any) -> None:
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    suffix = file_path.suffix.lower()
    if suffix == ".json":
        file_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return
    if suffix in {".yaml", ".yml"}:
        if yaml is None:
            raise RuntimeError("PyYAML is required to write YAML outputs")
        file_path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
        return
    raise ValueError(f"Unsupported output format: {suffix}")


def infer_artifact_type(path: str | Path, parsed: Any | None = None, content: str | None = None) -> ArtifactType:
    file_path = Path(path)
    lower_name = file_path.name.lower()
    if isinstance(parsed, dict):
        if isinstance(parsed.get("steps"), list):
            return ArtifactType.PROTOCOL_TRACE
        if parsed.get("samples") or parsed.get("observed_outputs"):
            return ArtifactType.RANDOM_SEQUENCE
        if isinstance(parsed.get("artifacts"), list):
            return ArtifactType.SESSION_LOG
        metadata = parsed.get("metadata") if isinstance(parsed.get("metadata"), dict) else parsed
        keys = set(metadata.keys()) if isinstance(metadata, dict) else set()
        if keys & {"scheme_type", "proof_of_possession", "accepts_untrusted_pubkeys", "domain_separation"}:
            return ArtifactType.CRYPTO_METADATA
    if any(token in lower_name for token in ("transcript", "session", "replay", "handshake")):
        return ArtifactType.TRANSCRIPT
    if any(token in lower_name for token in ("rng", "random", "nonce", "challenge")):
        return ArtifactType.RANDOM_SEQUENCE
    if any(token in lower_name for token in ("crypto", "signature", "scheme")):
        return ArtifactType.CRYPTO_METADATA
    if file_path.suffix.lower() in SUPPORTED_STRUCTURED_SUFFIXES and isinstance(parsed, dict):
        return ArtifactType.PROTOCOL_TRACE
    if content and _looks_like_transcript(content):
        return ArtifactType.TRANSCRIPT
    return ArtifactType.GENERIC_TEXT


def load_artifact_from_path(
    path: str | Path,
    *,
    artifact_type: ArtifactType | None = None,
    config: FrameworkConfig | None = None,
) -> Artifact:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Input file not found: {file_path}")
    cfg = config or FrameworkConfig()
    if file_path.stat().st_size > cfg.io.max_file_size_bytes:
        raise ValueError(f"Input file exceeds configured size limit: {file_path}")
    content = file_path.read_text(encoding="utf-8")
    metadata: dict[str, Any] = {
        "filename": file_path.name,
        "suffix": file_path.suffix.lower(),
        "size_bytes": file_path.stat().st_size,
        "line_count": len(content.splitlines()),
        "looks_like_transcript": _looks_like_transcript(content),
    }

    parsed: Any | None = None
    suffix = file_path.suffix.lower()
    if suffix in set(cfg.io.structured_suffixes):
        parsed = load_structured_file(file_path)
        metadata["parsed"] = parsed

    resolved_type = artifact_type or infer_artifact_type(file_path, parsed, content)
    return Artifact.create(
        artifact_type=resolved_type,
        content=content,
        source_path=str(file_path),
        metadata=metadata,
    )


def load_artifacts_from_path(
    path: str | Path,
    *,
    artifact_type: ArtifactType | None = None,
    config: FrameworkConfig | None = None,
) -> list[Artifact]:
    file_path = Path(path)
    cfg = config or FrameworkConfig()
    if file_path.is_file():
        artifact = load_artifact_from_path(file_path, artifact_type=artifact_type, config=cfg)
        parsed = artifact.metadata.get("parsed")
        if isinstance(parsed, dict) and isinstance(parsed.get("artifacts"), list):
            return _artifacts_from_manifest(parsed, source_path=str(file_path))
        return [artifact]

    if not file_path.is_dir():
        raise FileNotFoundError(f"Input path not found: {file_path}")

    globber = file_path.rglob if cfg.io.recursive else file_path.glob
    artifacts: list[Artifact] = []
    for child in sorted(globber("*")):
        if child.is_file():
            artifacts.append(load_artifact_from_path(child, artifact_type=artifact_type, config=cfg))
    return artifacts


def _artifacts_from_manifest(manifest: dict[str, Any], *, source_path: str | None = None) -> list[Artifact]:
    artifacts: list[Artifact] = []
    for item in manifest.get("artifacts", []):
        if not isinstance(item, dict):
            continue
        artifact_name = item.get("artifact_type", "generic_text")
        try:
            kind = ArtifactType(artifact_name)
        except Exception:
            kind = ArtifactType.GENERIC_TEXT
        artifacts.append(
            Artifact.create(
                artifact_type=kind,
                content=str(item.get("content", "")),
                source_path=source_path,
                metadata=dict(item.get("metadata", {})),
            )
        )
    return artifacts


def _looks_like_transcript(content: str) -> bool:
    lines = [line for line in content.splitlines() if line.strip()]
    if not lines:
        return False
    matched = sum(1 for line in lines[:10] if TRANSCRIPT_LINE_RE.match(line))
    return matched >= max(1, min(3, len(lines[:10]) // 2 or 1))
