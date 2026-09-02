"""
Mask & Hybrid Attack Strategies - HashSentry
==============================================
Mask attack: structured brute-force with placeholder tokens.
Hybrid attack: dictionary word base + mask-generated suffix (or prefix).
"""

import itertools
import os
import string
from typing import Generator, Iterable, List, Optional, Union
from hashsentry.strategies.base import BaseStrategy

MASK_CHARSETS = {
    "?l": string.ascii_lowercase,
    "?u": string.ascii_uppercase,
    "?d": string.digits,
    "?s": "!@#$%^&*()-_=+[]{}|;:,.<>?",
    "?h": "0123456789abcdef",
    "?H": "0123456789ABCDEF",
    "?a": string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?",
}


def parse_mask(mask: str) -> List[str]:
    """
    Parse a mask string like '?u?l?l?d?d' or 'Admin?d?d!' into a list of charset strings.
    Literal '??' is treated as a literal single '?'.
    """
    positions: List[str] = []
    i = 0
    while i < len(mask):
        if mask[i] == "?" and i + 1 < len(mask):
            token = mask[i : i + 2]
            if token == "??":
                positions.append("?")
                i += 2
            elif token in MASK_CHARSETS:
                positions.append(MASK_CHARSETS[token])
                i += 2
            else:
                # Unknown placeholder, treat first '?' as literal
                positions.append(mask[i])
                i += 1
        else:
            positions.append(mask[i])
            i += 1
    return positions


def mask_attack_candidates(mask: str) -> Generator[str, None, None]:
    """Generator yielding every candidate string matching the mask."""
    positions = parse_mask(mask)
    if not positions:
        return
    for combo in itertools.product(*positions):
        yield "".join(combo)


def hybrid_candidates(words: Iterable[str], suffix_mask: str) -> Generator[str, None, None]:
    """Generator yielding each dictionary word with every mask-based suffix appended."""
    suffixes = list(mask_attack_candidates(suffix_mask))
    for word in words:
        w = word.strip()
        if not w:
            continue
        for suffix in suffixes:
            yield w + suffix


class MaskStrategy(BaseStrategy):
    """
    Candidate generator for mask-based attacks.
    """

    def __init__(self, mask: str):
        super().__init__(name="Mask Attack")
        self.mask = mask
        self._positions = parse_mask(mask)

    def estimated_total(self) -> Optional[int]:
        if not self._positions:
            return 0
        total = 1
        for p in self._positions:
            total *= len(p)
        return total

    def candidates(self) -> Generator[str, None, None]:
        for candidate in mask_attack_candidates(self.mask):
            yield candidate


class HybridStrategy(BaseStrategy):
    """
    Candidate generator for hybrid attacks: Base word(s) + Mask suffix.
    """

    def __init__(self, base_words: Union[str, List[str]], suffix_mask: str = "?d?d?d?d"):
        super().__init__(name="Hybrid Attack")
        if isinstance(base_words, str):
            self.base_words = [w.strip() for w in base_words.replace(",", " ").split() if w.strip()]
        else:
            self.base_words = [w.strip() for w in base_words if w.strip()]
        self.suffix_mask = suffix_mask
        self._suffix_positions = parse_mask(suffix_mask)

    def estimated_total(self) -> Optional[int]:
        suffix_count = 1
        for p in self._suffix_positions:
            suffix_count *= len(p)
        return len(self.base_words) * suffix_count

    def candidates(self) -> Generator[str, None, None]:
        for candidate in hybrid_candidates(self.base_words, self.suffix_mask):
            yield candidate
