"""
Unit tests for Strength Scorer and Policy Checking (Phase 6).
"""

from hashsentry.reporting.scorer import (
    PolicyRule,
    calculate_entropy,
    check_policy,
    detect_patterns,
    score_password,
)


def test_entropy_calculation():
    assert calculate_entropy("") == 0.0
    # Digits only (pool 10) vs Full ascii (pool 94)
    ent_num = calculate_entropy("123456")
    ent_complex = calculate_entropy("A1!b2@")
    assert ent_complex > ent_num


def test_pattern_detection():
    assert "keyboard walk" in detect_patterns("qwerty123")
    assert "name/word + year" in detect_patterns("Football2024")
    assert "repeated single character" in detect_patterns("111111")
    assert "numeric-only PIN/password" in detect_patterns("987654")


def test_policy_check():
    rule = PolicyRule(min_length=10, require_special=True)
    violations = check_policy("Short1!", rule)
    assert any("below minimum requirement" in v for v in violations)

    compliant = check_policy("ValidPassword123!", rule)
    assert len(compliant) == 0


def test_scoring_levels():
    # Dictionary hit -> CRITICAL
    crit = score_password("password", strategy_used="Dictionary")
    assert crit.rating == "CRITICAL"

    # Mutated rule hit -> WEAK
    weak = score_password("Football2025", strategy_used="Dictionary + Rules")
    assert weak.rating == "WEAK"

    # Strong long password
    strong = score_password("Xy#99_kL$p2!vQ9", strategy_used="Exhaustive Brute-Force")
    assert strong.rating in ("STRONG", "MODERATE")
