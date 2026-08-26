"""
Unit tests for Guess Prioritizer (Phase 4).
"""

from hashsentry.core.prioritizer import GuessPrioritizer, estimate_likelihood_score


def test_score_ranking():
    # Common password should score significantly higher than random junk
    score_pwd = estimate_likelihood_score("password")
    score_common = estimate_likelihood_score("Football2024")
    score_random = estimate_likelihood_score("x9#qZ!1v")

    assert score_pwd > score_random
    assert score_common > score_random


def test_prioritizer_reorder():
    prioritizer = GuessPrioritizer(buffer_size=100)
    raw = ["xkz912", "password", "q1w2e3r4", "Admin2025"]
    prioritized = list(prioritizer.prioritize_stream(raw))

    # "password" or "Admin2025" should emerge before "xkz912"
    assert prioritized.index("password") < prioritized.index("xkz912")
    assert prioritized.index("Admin2025") < prioritized.index("xkz912")
