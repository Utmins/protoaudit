"""Defensive fuzzing helpers."""

from __future__ import annotations

import string


def generate_mutations(seed: str) -> list[str]:
    boundary = "A" * max(len(seed), 1)
    mutations = [
        seed,
        seed[::-1],
        seed.upper(),
        seed.lower(),
        f"{seed}\x00",
        f"{seed}{seed}",
        " " + seed,
        seed + " ",
        seed + "\n",
        "",
        boundary,
        ''.join(ch for ch in seed if ch in string.printable),
    ]
    # preserve order while deduplicating
    return list(dict.fromkeys(mutations))
