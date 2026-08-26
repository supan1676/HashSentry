"""
Rule-Based Mutation Engine - HashSentry
=======================================
Applies realistic human mutation patterns to dictionary words:
capitalization variants, year/digit suffixes, leetspeak, reversals, and combinations.
"""

import os
from typing import Generator, Iterable, List, Optional, Set, Union
from hashsentry.strategies.base import BaseStrategy

LEET_MAP = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}

COMMON_SUFFIXES = [
    "1", "12", "123", "1234", "!", "01", "2020", "2021", "2022", "2023", "2024", "2025", "2026",
    "@", "#", "$", "00", "07", "69", "99", "123!"
]

COMMON_PREFIXES = [
    "1", "!", "@", "2024", "2025", "the", "The"
]


def leetspeak(word: str) -> str:
    """Transform word using standard leetspeak substitutions."""
    return "".join(LEET_MAP.get(c.lower(), c) for c in word)


def apply_rules(word: str) -> Set[str]:
    """Return the set of the base word plus its mutated variants."""
    variants: Set[str] = set()
    if not word:
        return variants

    # Basic casing
    variants.add(word)
    variants.add(word.lower())
    variants.add(word.upper())
    variants.add(word.capitalize())
    variants.add(word.swapcase())

    # Reversal
    variants.add(word[::-1])

    # Leetspeak variations
    leet = leetspeak(word)
    variants.add(leet)
    variants.add(leetspeak(word.capitalize()))
    variants.add(leet.upper())

    # Suffixes on original and capitalized
    for base in (word, word.capitalize(), word.lower()):
        for suffix in COMMON_SUFFIXES:
            variants.add(base + suffix)

    # Simple prefixes
    for prefix in COMMON_PREFIXES:
        variants.add(prefix + word)
        variants.add(prefix + word.capitalize())

    return variants


def mutated_wordlist(words: Iterable[str]) -> Generator[str, None, None]:
    """Generator yielding every unique mutated variant across an iterable of base words."""
    seen: Set[str] = set()
    for word in words:
        w = word.strip()
        if not w:
            continue
        for variant in apply_rules(w):
            if variant not in seen:
                seen.add(variant)
                yield variant


class RulesStrategy(BaseStrategy):
    """
    Applies rule-based mutations across a base wordlist or word generator.
    """

    def __init__(self, wordlist: Union[str, List[str]]):
        super().__init__(name="Dictionary + Rules")
        self.wordlist_source = wordlist

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
        # Approximate: on average ~30-40 mutations per unique word
        try:
            base_count = len(self._get_base_words())
            return base_count * 35
        except Exception:
            return None

    def candidates(self) -> Generator[str, None, None]:
        base_words = self._get_base_words()
        for candidate in mutated_wordlist(base_words):
            yield candidate
