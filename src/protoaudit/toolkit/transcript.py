"""Transcript parsing helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
import re
from typing import Any


JSON_OBJECT_RE = re.compile(r"\{.*\}")
TIMESTAMP_PREFIX_RE = re.compile(r"^\s*\[(?P<ts>[^\]]+)\]\s*(?P<body>.*)$")
ARROW_DIRECTION_RE = re.compile(
    r"^(?P<src>[A-Za-z0-9_-]+)\s*->\s*(?P<dst>[A-Za-z0-9_-]+)\s*:\s*(?P<payload>.*)$"
)

OUTBOUND_HINTS = {"c", "client", "cli", "tx", "out", "requester"}
INBOUND_HINTS = {"s", "server", "srv", "rx", "in", "responder"}


@dataclass(slots=True)
class TranscriptEntry:
    direction: str
    text: str
    parsed: dict[str, Any] | None = None
    line_number: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ParsedTranscript:
    entries: list[TranscriptEntry] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"entry_count": len(self.entries), "entries": [asdict(entry) for entry in self.entries]}


def _strip_timestamp_prefix(line: str) -> tuple[str, dict[str, Any]]:
    match = TIMESTAMP_PREFIX_RE.match(line)
    if not match:
        return line.strip(), {}
    body = match.group("body").strip()
    return body, {"timestamp": match.group("ts")}


def _direction_from_arrow(src: str, dst: str) -> str:
    src_norm = src.strip().lower()
    dst_norm = dst.strip().lower()
    if src_norm in OUTBOUND_HINTS or dst_norm in INBOUND_HINTS:
        return "out"
    if src_norm in INBOUND_HINTS or dst_norm in OUTBOUND_HINTS:
        return "in"
    return "unknown"


def _infer_direction(line: str) -> tuple[str, str, dict[str, Any]]:
    stripped, metadata = _strip_timestamp_prefix(line)
    prefixes = {
        "send:": "out",
        "recv:": "in",
        "tx:": "out",
        "rx:": "in",
        ">": "out",
        "<": "in",
    }
    lowered = stripped.lower()
    for prefix, direction in prefixes.items():
        if lowered.startswith(prefix):
            return direction, stripped[len(prefix):].strip(), metadata

    arrow = ARROW_DIRECTION_RE.match(stripped)
    if arrow:
        src = arrow.group("src")
        dst = arrow.group("dst")
        payload = arrow.group("payload").strip()
        metadata.update({"source": src, "destination": dst})
        return _direction_from_arrow(src, dst), payload, metadata

    return "unknown", stripped, metadata


def _try_parse_json(text: str) -> dict[str, Any] | None:
    candidate = text.strip()
    if not candidate:
        return None
    if candidate.startswith("{") and candidate.endswith("}"):
        try:
            parsed = json.loads(candidate)
            return parsed if isinstance(parsed, dict) else None
        except Exception:
            return None
    match = JSON_OBJECT_RE.search(candidate)
    if not match:
        return None
    try:
        parsed = json.loads(match.group(0))
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


def parse_transcript(raw_text: str) -> ParsedTranscript:
    entries: list[TranscriptEntry] = []
    for index, line in enumerate(raw_text.splitlines(), start=1):
        if not line.strip():
            continue
        direction, text, metadata = _infer_direction(line)
        entries.append(
            TranscriptEntry(
                direction=direction,
                text=text,
                parsed=_try_parse_json(text),
                line_number=index,
                metadata=metadata,
            )
        )
    return ParsedTranscript(entries=entries)


def save_transcript(entries: list[dict[str, Any]], path: str = "transcript.json") -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(entries, handle, indent=2, ensure_ascii=False)
