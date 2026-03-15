"""Randomness analyzer migrated from the legacy RNG leakage analyzer."""

from __future__ import annotations

from collections import Counter
import math
import statistics
from typing import Any

from protoaudit.core.models import AnalysisResult, Artifact, Evidence


class RandomnessAnalyzer:
    name = "randomness"

    def analyze(self, artifact: Artifact) -> AnalysisResult:
        data = self._extract_data(artifact)
        metadata = data.get("metadata", {}) if isinstance(data.get("metadata"), dict) else {}
        samples_raw = data.get("samples") or data.get("observed_outputs") or artifact.content.split()
        sample_encoding = str(metadata.get("sample_encoding", "hex"))

        normalized_samples = self._normalize_samples(samples_raw, sample_encoding)
        unique_ratio = len({sample.hex() for sample in normalized_samples}) / len(normalized_samples) if normalized_samples else 0.0
        repeated_ratio = self._repeated_ratio(normalized_samples)
        entropies = [self._shannon_entropy_bytes(sample) for sample in normalized_samples] if normalized_samples else [0.0]
        mean_entropy = statistics.mean(entropies)
        prefix_bits = self._longest_common_prefix_bits(normalized_samples)

        hidden_bits = metadata.get("hidden_bits")
        leaked_bits = metadata.get("revealed_state_related_bits_per_sample") or metadata.get("leaked_bits")
        deterministic = bool(metadata.get("deterministic_outputs", False) or metadata.get("deterministic_nonce_or_challenge", False))
        uses_custom_rng = bool(metadata.get("uses_custom_rng", False))
        state_bits = metadata.get("state_bits")
        output_bits = metadata.get("output_bits")
        truncated = bool(metadata.get("samples_are_truncated", False))
        recovery_feasibility = self._assess_recovery(state_bits, leaked_bits)

        evidence = [
            Evidence.create(
                kind="randomness.samples",
                summary="Normalized randomness samples prepared for heuristic checks.",
                raw_value={
                    "sample_count": len(normalized_samples),
                    "sample_encoding": sample_encoding,
                },
            ),
            Evidence.create(
                kind="randomness.metrics",
                summary="Derived randomness quality metrics.",
                raw_value={
                    "unique_ratio": unique_ratio,
                    "repeated_ratio": repeated_ratio,
                    "mean_entropy": mean_entropy,
                    "longest_common_prefix_bits": prefix_bits,
                    "hidden_bits": hidden_bits,
                    "leaked_bits": leaked_bits,
                    "state_bits": state_bits,
                    "output_bits": output_bits,
                    "samples_are_truncated": truncated,
                    "deterministic_outputs": deterministic,
                    "uses_custom_rng": uses_custom_rng,
                    "recovery_feasibility": recovery_feasibility,
                },
            ),
        ]

        return AnalysisResult(
            analyzer_name=self.name,
            artifact=artifact,
            summary=self._build_summary(len(normalized_samples), unique_ratio, repeated_ratio, prefix_bits, recovery_feasibility),
            evidence=evidence,
            metrics={
                "sample_count": len(normalized_samples),
                "unique_ratio": unique_ratio,
                "repeated_ratio": repeated_ratio,
                "mean_entropy": mean_entropy,
                "longest_common_prefix_bits": prefix_bits,
                "deterministic_outputs": deterministic,
                "uses_custom_rng": uses_custom_rng,
                "hidden_bits": hidden_bits,
                "revealed_state_related_bits_per_sample": leaked_bits,
                "state_bits": state_bits,
                "output_bits": output_bits,
                "samples_are_truncated": truncated,
                "recovery_feasibility": recovery_feasibility,
            },
            metadata={"status": "migrated-phase4.2"},
        )

    def _extract_data(self, artifact: Artifact) -> dict[str, Any]:
        parsed = artifact.metadata.get("parsed")
        if isinstance(parsed, dict):
            return parsed
        tokens = artifact.content.split()
        return {"samples": tokens, "metadata": {"sample_encoding": "utf-8"}}

    def _normalize_samples(self, samples: list[Any], encoding: str) -> list[bytes]:
        normalized: list[bytes] = []
        for item in samples:
            text = str(item)
            if encoding == "hex":
                try:
                    normalized.append(bytes.fromhex(text))
                    continue
                except ValueError:
                    normalized.append(text.encode("utf-8", errors="replace"))
                    continue
            normalized.append(text.encode("utf-8", errors="replace"))
        return normalized

    def _repeated_ratio(self, samples: list[bytes]) -> float:
        if not samples:
            return 0.0
        counts = Counter(samples)
        repeats = sum(count - 1 for count in counts.values() if count > 1)
        return repeats / len(samples)

    def _shannon_entropy_bytes(self, data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        total = len(data)
        entropy = 0.0
        for count in counts.values():
            probability = count / total
            entropy -= probability * math.log2(probability)
        return entropy

    def _longest_common_prefix_bits(self, samples: list[bytes]) -> int:
        if len(samples) < 2:
            return 0
        shortest = min(len(sample) for sample in samples)
        prefix_bits = 0
        for index in range(shortest):
            values = {sample[index] for sample in samples}
            if len(values) == 1:
                prefix_bits += 8
                continue
            for bit in range(7, -1, -1):
                mask = 1 << bit
                bit_values = {(sample[index] & mask) != 0 for sample in samples}
                if len(bit_values) == 1:
                    prefix_bits += 1
                else:
                    return prefix_bits
        return prefix_bits

    def _assess_recovery(self, state_bits: Any, leaked_bits: Any) -> str:
        if not isinstance(state_bits, (int, float)) or not isinstance(leaked_bits, (int, float)) or not state_bits:
            return "unknown"
        ratio = leaked_bits / state_bits
        if ratio >= 0.75:
            return "high"
        if ratio >= 0.50:
            return "moderate"
        return "low"

    def _build_summary(self, sample_count: int, unique_ratio: float, repeated_ratio: float, prefix_bits: int, recovery: str) -> str:
        return (
            f"Processed {sample_count} samples; unique ratio={unique_ratio:.2f}; "
            f"repeated ratio={repeated_ratio:.2f}; longest common prefix={prefix_bits} bits; "
            f"state-recovery feasibility={recovery}."
        )
