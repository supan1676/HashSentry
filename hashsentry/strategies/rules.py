"""
Rule-Based Mutation Engine - HashSentry
=======================================
Applies realistic human mutation patterns to seed words completely in-memory:
capitalization variants, year/digit suffixes, leetspeak, reversals, and combinations.
"""

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

DEFAULT_CORE_SEEDS = [
    "password", "admin", "welcome", "football", "dragon", "baseball",
    "master", "sunshine", "princess", "superman", "shadow", "freedom",
    "computer", "summer", "winter", "access", "secret", "hello",
    "test", "pass", "login", "trustno1", "matrix", "ninja", "security"
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
    Applies rule-based mutations across in-memory base seed words.
    """

    def __init__(self, base_words: Optional[Union[str, List[str]]] = None):
        super().__init__(name="Smart Rules Mutation")
        if base_words is None:
            self._seeds = list(DEFAULT_CORE_SEEDS)
        elif isinstance(base_words, str):
            self._seeds = [w.strip() for w in base_words.replace(",", " ").split() if w.strip()]
            if not self._seeds:
                self._seeds = list(DEFAULT_CORE_SEEDS)
        else:
            self._seeds = [w.strip() for w in base_words if w.strip()]
            if not self._seeds:
                self._seeds = list(DEFAULT_CORE_SEEDS)

    def estimated_total(self) -> Optional[int]:
        # On average ~35 unique mutations per unique seed word
        return len(self._seeds) * 35

    def candidates(self) -> Generator[str, None, None]:
        for candidate in mutated_wordlist(self._seeds):
            yield candidate
