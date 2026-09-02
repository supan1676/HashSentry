"""
Unit tests for in-memory attack strategies.
"""

from hashsentry.strategies.brute_force import BruteForceStrategy
from hashsentry.strategies.pattern import (
    CHARSET_ALL_PRINTABLE,
    CHARSET_DIGITS,
    CHARSET_LOWER_NUM,
    PatternStrategy,
)
from hashsentry.strategies.mask_hybrid import HybridStrategy, MaskStrategy, parse_mask
from hashsentry.strategies.rules import RulesStrategy, apply_rules, leetspeak


def test_brute_force_strategy():
    strat = BruteForceStrategy(charset="ab", min_length=1, max_length=2)
    assert strat.estimated_total() == 6  # 2^1 + 2^2 = 2 + 4 = 6
    cands = list(strat.candidates())
    assert cands == ["a", "b", "aa", "ab", "ba", "bb"]


def test_pattern_strategy_with_prefix():
    strat = PatternStrategy(base_prefix="bante", charset="ab", min_suffix_len=1, max_suffix_len=2)
    assert strat.estimated_total() == 6  # 2^1 + 2^2 = 6
    cands = list(strat.candidates())
    assert cands == ["bantea", "banteb", "banteaa", "banteab", "banteba", "bantebb"]


def test_pattern_strategy_full_ascii():
    strat = PatternStrategy(base_prefix="test", charset=CHARSET_DIGITS, min_suffix_len=1, max_suffix_len=1)
    assert strat.estimated_total() == 10
    cands = list(strat.candidates())
    assert len(cands) == 10
    assert "test0" in cands
    assert "test9" in cands


def test_rules_strategy():
    res = apply_rules("dragon")
    assert "dragon" in res
    assert "Dragon" in res
    assert "DRAGON" in res
    assert "nogard" in res
    assert "dr4g0n" in res
    assert "Dragon2025" in res
    assert "Dragon!" in res

    strat = RulesStrategy(base_words=["dragon"])
    cands = list(strat.candidates())
    assert "Dragon2025" in cands


def test_mask_parser():
    tokens = parse_mask("?u?l?d!")
    assert len(tokens) == 4
    assert tokens[0] == "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    assert tokens[1] == "abcdefghijklmnopqrstuvwxyz"
    assert tokens[2] == "0123456789"
    assert tokens[3] == "!"


def test_mask_strategy():
    strat = MaskStrategy(mask="?d?d")
    assert strat.estimated_total() == 100
    cands = list(strat.candidates())
    assert len(cands) == 100
    assert "00" in cands
    assert "99" in cands


def test_hybrid_strategy():
    strat = HybridStrategy(base_words=["pin"], suffix_mask="?d?d")
    assert strat.estimated_total() == 100
    cands = list(strat.candidates())
    assert len(cands) == 100
    assert "pin00" in cands
    assert "pin99" in cands
