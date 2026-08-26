"""
Strategies module for HashSentry.
Exports all attack strategies and common interfaces.
"""

from hashsentry.strategies.base import BaseStrategy
from hashsentry.strategies.brute_force import BruteForceStrategy
from hashsentry.strategies.dictionary import DictionaryStrategy
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
    "BruteForceStrategy",
    "DictionaryStrategy",
    "RulesStrategy",
    "MaskStrategy",
    "HybridStrategy",
    "apply_rules",
    "mutated_wordlist",
    "parse_mask",
    "mask_attack_candidates",
    "hybrid_candidates",
]
