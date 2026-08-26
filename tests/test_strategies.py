"""
Unit tests for attack strategies.
"""

from hashsentry.strategies.brute_force import BruteForceStrategy
from hashsentry.strategies.dictionary import DictionaryStrategy
from hashsentry.strategies.mask_hybrid import HybridStrategy, MaskStrategy, parse_mask
from hashsentry.strategies.rules import RulesStrategy, apply_rules, leetspeak


def test_brute_force_strategy():
    strat = BruteForceStrategy(charset="ab", min_length=1, max_length=2)
    assert strat.estimated_total() == 6  # 2^1 + 2^2 = 2 + 4 = 6
    cands = list(strat.candidates())
    assert cands == ["a", "b", "aa", "ab", "ba", "bb"]


def test_dictionary_strategy():
    words = ["admin", "password", "root"]
    strat = DictionaryStrategy(wordlist=words)
    assert strat.estimated_total() == 3
    assert list(strat.candidates()) == words


def test_rules_strategy():
    res = apply_rules("dragon")
    assert "dragon" in res
    assert "Dragon" in res
    assert "DRAGON" in res
    assert "nogard" in res
    assert "dr4g0n" in res
    assert "Dragon2025" in res
    assert "Dragon!" in res

    strat = RulesStrategy(wordlist=["dragon"])
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
    strat = HybridStrategy(wordlist=["pin"], suffix_mask="?d?d")
    assert strat.estimated_total() == 100
    cands = list(strat.candidates())
    assert len(cands) == 100
    assert "pin00" in cands
    assert "pin99" in cands
