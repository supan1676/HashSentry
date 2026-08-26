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
    Candidate generator for hybrid attacks: Dictionary word + Mask suffix.
    """

    def __init__(self, wordlist: Union[str, List[str]], suffix_mask: str = "?d?d?d?d"):
        super().__init__(name="Hybrid Attack")
        self.wordlist_source = wordlist
        self.suffix_mask = suffix_mask
        self._suffix_positions = parse_mask(suffix_mask)

    def _get_base_words(self) -> List[str]:
        if isinstance(self.wordlist_source, list):
            return [w.strip() for w in self.wordlist_source if w.strip()]
        if isinstance(self.wordlist_source, str):
            if not os.path.exists(self.wordlist_source):
                raise FileNotFoundError(f"Wordlist not found: {self.wordlist_source}")
            with open(self.wordlist_source, "r", encoding="utf-8", errors="ignore") as f:
                return [line.strip() for line in f if line.strip()]
        return []

    def estimated_total(self) -> Optional[int]:
        words = self._get_base_words()
        suffix_count = 1
        for p in self._suffix_positions:
            suffix_count *= len(p)
        return len(words) * suffix_count

    def candidates(self) -> Generator[str, None, None]:
        words = self._get_base_words()
        for candidate in hybrid_candidates(words, self.suffix_mask):
            yield candidate
