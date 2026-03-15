"""Replay-building helpers."""

from __future__ import annotations

import json
from typing import Any

from protoaudit.toolkit.transcript import parse_transcript


def build_replay_plan(raw_text: str) -> dict[str, object]:
    try:
        parsed_json = json.loads(raw_text)
        if isinstance(parsed_json, list):
            return _from_saved_transcript(parsed_json)
    except Exception:
        pass

    parsed = parse_transcript(raw_text)
    steps: list[dict[str, object]] = []
    for entry in parsed.entries:
        if entry.direction == "out":
            steps.append({"action": "send", "data": entry.text, "line_number": entry.line_number})
        elif entry.direction == "in":
            steps.append({"action": "expect", "data": entry.text, "line_number": entry.line_number})
    return {
        "status": "ready",
        "message_count": len(parsed.entries),
        "steps": steps,
    }


def _from_saved_transcript(items: list[dict[str, Any]]) -> dict[str, object]:
    steps: list[dict[str, object]] = []
    for index, item in enumerate(items, start=1):
        if "send" in item:
            steps.append({"action": "send", "data": item["send"], "line_number": index})
        if "recv" in item:
            steps.append({"action": "expect", "data": item["recv"], "line_number": index})
    return {"status": "ready", "message_count": len(items), "steps": steps}
