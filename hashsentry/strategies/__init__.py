"""
Strategies module for HashSentry.
Exports all in-memory streaming attack strategies and common interfaces.
"""

from hashsentry.strategies.base import BaseStrategy
from hashsentry.strategies.brute_force import BruteForceStrategy
from hashsentry.strategies.pattern import (
    CHARSET_ALL_PRINTABLE,
    CHARSET_ALPHANUMERIC,
    CHARSET_DIGITS,
    CHARSET_LETTERS,
    CHARSET_LOWER_NUM,
    CHARSET_SYMBOLS,
    PatternStrategy,
)
from hashsentry.strategies.rules import RulesStrategy, apply_rules, mutated_wordlist
from hashsentry.strategies.mask_hybrid import (
    MaskStrategy,
    HybridStrategy,
    parse_mask,
    mask_attack_candidates,
    hybrid_candidates,
)

__all__ = [
    "BaseStrategy",
    "PatternStrategy",
    "BruteForceStrategy",
    "RulesStrategy",
    "MaskStrategy",
    "HybridStrategy",
    "CHARSET_ALL_PRINTABLE",
    "CHARSET_ALPHANUMERIC",
    "CHARSET_LOWER_NUM",
    "CHARSET_LETTERS",
    "CHARSET_DIGITS",
    "CHARSET_SYMBOLS",
    "apply_rules",
    "mutated_wordlist",
    "parse_mask",
    "mask_attack_candidates",
    "hybrid_candidates",
]
