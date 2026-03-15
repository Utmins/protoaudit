"""Protocol analyzer migrated from the stronger legacy audit logic."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from protoaudit.core.config import FrameworkConfig
from protoaudit.core.models import AnalysisResult, Artifact, Evidence
from protoaudit.toolkit.transcript import parse_transcript


CHALLENGE_KEYS = {
    "challenge",
    "nonce",
    "ticket",
    "token",
    "session_id",
    "request_id",
    "proof",
    "seed_hint",
}
PHASE_KEYWORDS = {
    "hello": "hello",
    "clienthello": "hello",
    "serverhello": "hello",
    "challenge": "challenge",
    "nonce": "challenge",
    "response": "response",
    "proof": "response",
    "auth": "auth",
    "ack": "ack",
    "success": "complete",
    "ok": "complete",
    "finish": "complete",
    "complete": "complete",
}


class ProtocolAnalyzer:
    name = "protocol"

    def __init__(self, config: FrameworkConfig | None = None) -> None:
        self.config = config or FrameworkConfig()

    def analyze(self, artifact: Artifact) -> AnalysisResult:
        parsed = artifact.metadata.get("parsed")
        script_steps: list[dict[str, Any]] = []
        transcript_entries: list[dict[str, Any]] = []
        extracted_indicators: list[dict[str, Any]] = []
        response_values: list[str] = []

        if isinstance(parsed, dict) and isinstance(parsed.get("steps"), list):
            script_steps = [step for step in parsed["steps"] if isinstance(step, dict)]
            transcript_entries = self._script_to_transcript(script_steps)
        else:
            transcript = parse_transcript(artifact.content)
            transcript_entries = [
                {
                    "direction": item.direction,
                    "text": item.text,
                    "parsed": item.parsed,
                    "line_number": item.line_number,
                    "metadata": item.metadata,
                }
                for item in transcript.entries
            ]

        for entry in transcript_entries:
            text = str(entry.get("text", ""))
            parsed_payload = entry.get("parsed")
            if isinstance(parsed_payload, dict):
                extracted = {k: v for k, v in parsed_payload.items() if k in CHALLENGE_KEYS}
                if extracted:
                    extracted_indicators.append(extracted)
            else:
                extracted = self._extract_inline_indicators(text)
                if extracted:
                    extracted_indicators.append(extracted)
            if entry.get("direction") == "in":
                response_values.append(text)

        response_counter = Counter(response_values)
        repeated_responses = sum(count - 1 for count in response_counter.values() if count > 1)
        repeated_response_examples = [value for value, count in response_counter.items() if count > 1][:5]

        challenge_pairs = self._flatten_indicators(extracted_indicators)
        challenge_counter = Counter(challenge_pairs)
        repeated_challenge_values = {
            key: value for (key, value), count in challenge_counter.items() if count > 1
        }

        message_shapes = Counter(self._message_shape(entry.get("parsed"), str(entry.get("text", ""))) for entry in transcript_entries)
        phase_sequence = [self._infer_phase(entry.get("parsed"), str(entry.get("text", ""))) for entry in transcript_entries]
        phase_counts = Counter(phase_sequence)
        transitions = self._build_state_transitions(phase_sequence)
        transition_counts = Counter(transitions)
        handshake_style, handshake_complete = self._detect_handshake(phase_sequence)
        loop_count = sum(count - 1 for count in transition_counts.values() if count > 1)

        parser_summary = {
            "message_count": len(transcript_entries),
            "input_messages": sum(1 for item in transcript_entries if item.get("direction") == "out"),
            "output_messages": sum(1 for item in transcript_entries if item.get("direction") == "in"),
            "indicators": {key: True for indicator in extracted_indicators for key in indicator.keys()},
            "message_shapes": dict(message_shapes),
            "phase_counts": dict(phase_counts),
            "handshake_style": handshake_style,
            "handshake_complete": handshake_complete,
        }

        evidence = [
            Evidence.create(
                kind="protocol.transcript",
                summary="Normalized protocol transcript available for downstream rules.",
                raw_value=transcript_entries,
            ),
            Evidence.create(
                kind="protocol.parser_summary",
                summary="Protocol transcript summary and extracted indicators.",
                raw_value=parser_summary,
            ),
            Evidence.create(
                kind="protocol.state_tracking",
                summary="Inferred protocol phases and state transitions.",
                raw_value={
                    "phase_sequence": phase_sequence,
                    "transitions": transitions,
                    "transition_counts": dict(transition_counts),
                    "loop_count": loop_count,
                },
            ),
        ]
        if script_steps:
            evidence.append(
                Evidence.create(
                    kind="protocol.script",
                    summary="Input artifact contains a structured protocol script.",
                    raw_value={"step_count": len(script_steps)},
                )
            )
        if extracted_indicators:
            evidence.append(
                Evidence.create(
                    kind="protocol.challenge_indicators",
                    summary="Challenge-like fields were extracted from transcript content.",
                    raw_value=extracted_indicators,
                )
            )
        if repeated_response_examples:
            evidence.append(
                Evidence.create(
                    kind="protocol.repeated_responses",
                    summary="Repeated inbound responses were observed.",
                    raw_value={"examples": repeated_response_examples, "count": repeated_responses},
                )
            )
        if repeated_challenge_values:
            evidence.append(
                Evidence.create(
                    kind="protocol.repeated_challenge_values",
                    summary="One or more challenge-like values repeated across messages.",
                    raw_value=repeated_challenge_values,
                )
            )
        if handshake_style != "none":
            evidence.append(
                Evidence.create(
                    kind="protocol.handshake",
                    summary="Handshake-like pattern inferred from transcript.",
                    raw_value={"style": handshake_style, "complete": handshake_complete},
                )
            )

        response_ratio = 0.0 if not response_values else repeated_responses / len(response_values)
        return AnalysisResult(
            analyzer_name=self.name,
            artifact=artifact,
            summary=self._build_summary(parser_summary, extracted_indicators, repeated_responses, repeated_challenge_values, handshake_style, handshake_complete),
            evidence=evidence,
            metrics={
                "message_count": len(transcript_entries),
                "script_step_count": len(script_steps),
                "challenge_indicator_count": len(extracted_indicators),
                "repeated_response_count": repeated_responses,
                "repeated_response_ratio": response_ratio,
                "unique_response_count": len(response_counter),
                "repeated_challenge_value_count": len(repeated_challenge_values),
                "phase_counts": dict(phase_counts),
                "phase_loop_count": loop_count,
                "state_transition_count": len(transitions),
                "handshake_detected": handshake_style != "none",
                "handshake_style": handshake_style,
                "handshake_complete": handshake_complete,
            },
            metadata={
                "status": "migrated-phase4.3",
                "transcript_entries": len(transcript_entries),
            },
        )

    def _build_summary(
        self,
        parser_summary: dict[str, Any],
        indicators: list[dict[str, Any]],
        repeated_responses: int,
        repeated_challenge_values: dict[str, Any],
        handshake_style: str,
        handshake_complete: bool,
    ) -> str:
        parts = [f"Processed {parser_summary['message_count']} protocol messages"]
        if indicators:
            parts.append(f"extracted {len(indicators)} challenge-like indicators")
        if repeated_responses:
            parts.append(f"observed {repeated_responses} repeated server responses")
        if repeated_challenge_values:
            parts.append(f"detected {len(repeated_challenge_values)} repeated challenge-like values")
        if handshake_style != "none":
            parts.append(f"inferred {handshake_style} handshake")
            parts.append("handshake complete" if handshake_complete else "handshake incomplete")
        return "; ".join(parts) + "."

    def _script_to_transcript(self, steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for index, step in enumerate(steps, start=1):
            action = str(step.get("action", "unknown"))
            if action.startswith("send"):
                payload = step.get("data", "")
                parsed = payload if isinstance(payload, dict) else None
                if not isinstance(payload, str):
                    payload = json.dumps(payload, ensure_ascii=False)
                entries.append({"direction": "out", "text": payload, "parsed": parsed, "step": index, "action": action})
            elif action.startswith("recv"):
                data = step.get("expect")
                parsed = data if isinstance(data, dict) else None
                text = data if isinstance(data, str) else step.get("marker", "") or step.get("data", "")
                if not isinstance(text, str):
                    text = json.dumps(text, ensure_ascii=False)
                entries.append({"direction": "in", "text": str(text), "parsed": parsed, "step": index, "action": action})
        return entries

    def _message_shape(self, parsed_payload: Any, text: str) -> str:
        if isinstance(parsed_payload, dict):
            return "json:" + ",".join(sorted(parsed_payload.keys()))
        if text.startswith("{") and text.endswith("}"):
            return "json-like"
        return f"text:{min(len(text), 32)}"

    def _flatten_indicators(self, extracted_indicators: list[dict[str, Any]]) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        for indicator in extracted_indicators:
            for key, value in indicator.items():
                pairs.append((str(key), json.dumps(value, sort_keys=True, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)))
        return pairs

    def _extract_inline_indicators(self, text: str) -> dict[str, str]:
        tokens = text.replace(":", " ").split()
        found: dict[str, str] = {}
        for index, token in enumerate(tokens[:-1]):
            lowered = token.lower()
            if lowered in CHALLENGE_KEYS:
                found[lowered] = tokens[index + 1]
        return found

    def _infer_phase(self, parsed_payload: Any, text: str) -> str:
        if isinstance(parsed_payload, dict):
            joined = " ".join(str(key) for key in parsed_payload.keys()) + " " + " ".join(str(value) for value in parsed_payload.values())
        else:
            joined = text
        lowered = joined.lower()
        for key, phase in PHASE_KEYWORDS.items():
            if key in lowered:
                return phase
        return "data"

    def _build_state_transitions(self, phase_sequence: list[str]) -> list[str]:
        transitions: list[str] = []
        previous: str | None = None
        for phase in phase_sequence:
            if previous is not None:
                transitions.append(f"{previous}->{phase}")
            previous = phase
        return transitions

    def _detect_handshake(self, phases: list[str]) -> tuple[str, bool]:
        joined = ",".join(phases)
        if "hello" in phases and "challenge" in phases and "response" in phases:
            complete = any(phase in {"ack", "complete", "auth"} for phase in phases[phases.index("response") + 1:])
            return "challenge-response", complete
        if phases[:2] == ["hello", "hello"] and any(phase in {"auth", "complete", "ack"} for phase in phases[2:]):
            return "hello-negotiation", True
        if "auth" in phases:
            return "auth-flow", any(phase in {"complete", "ack"} for phase in phases[phases.index("auth") + 1:])
        return "none", False
