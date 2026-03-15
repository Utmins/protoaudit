"""Artifact extraction helpers."""

from __future__ import annotations

import json
import re
from typing import Any


JSON_BLOCK_RE = re.compile(r"\{[^\n]*\}|\{(?:.|\n)*?\}", re.MULTILINE)


def extract_candidate_blocks(raw_text: str) -> list[str]:
    blocks = [block.strip() for block in raw_text.split("\n\n") if block.strip()]
    for match in JSON_BLOCK_RE.finditer(raw_text):
        candidate = match.group(0).strip()
        if candidate and candidate not in blocks:
            blocks.append(candidate)
    return blocks


def extract_json_objects(raw_text: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for block in extract_candidate_blocks(raw_text):
        try:
            parsed = json.loads(block)
        except Exception:
            continue
        if isinstance(parsed, dict):
            results.append(parsed)
    return results
