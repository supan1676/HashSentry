"""
Guess Prioritizer - HashSentry (Phase 4)
=========================================
Orders candidates by statistical likelihood and human password patterns.
Critical for slow-hash attacks where exhaustive search is impractical.
Uses statistical frequency lists, pattern heuristics, and buffer-based priority queuing.
"""

import heapq
import re
from typing import Generator, Iterable, List, Optional, Set

# Top high-frequency password seeds and tokens
TOP_FREQUENCY_PASSWORDS = [
    "password", "123456", "12345678", "123456789", "qwerty", "abc123", "monkey",
    "1234567", "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master",
    "sunshine", "ashley", "football", "bailey", "shadow", "superman", "princess",
    "password1", "123123", "admin", "welcome", "hello", "starwars", "mustang",
    "access", "696969", "batman", "test", "pass", "killer", "hockey", "ranger",
    "soccer", "cheese", "robert", "freedom", "computer", "whatever", "summer",
    "winter", "diamond", "phoenix", "ninja", "cookie", "guitar", "chelsea",
]

COMMON_YEARS = {str(y) for y in range(1970, 2030)}


def estimate_likelihood_score(candidate: str) -> float:
    """
    Calculate a likelihood score for candidate (higher score = more likely password).
    Factors:
      - Direct match in top frequency list (+100)
      - Common year suffix (+20)
      - Standard capitalization pattern (Capitalized + digits) (+15)
      - Low complexity/length (6-12 chars) (+10)
      - All lowercase + digits (+10)
      - Contains common word substring (+15)
      - Excessive non-standard symbols or extreme length (-5)
    """
    score = 0.0
    c_lower = candidate.lower()

    if c_lower in TOP_FREQUENCY_PASSWORDS:
        score += 100.0

    length = len(candidate)
    if 6 <= length <= 10:
        score += 15.0
    elif 4 <= length <= 14:
        score += 10.0
    else:
        score += 2.0

    # Human pattern: Capitalized word followed by 1-4 digits
    if re.match(r"^[A-Z][a-z]+[0-9]{1,4}$", candidate):
        score += 25.0
    elif re.match(r"^[a-z]+[0-9]{1,4}$", candidate):
        score += 20.0

    # Common year check
    for year in COMMON_YEARS:
        if candidate.endswith(year):
            score += 15.0
            break

    # Exclamation mark / simple symbol ending
    if candidate.endswith("!") or candidate.endswith("123!"):
        score += 10.0

    # All lowercase simple word
    if candidate.isalpha() and candidate.islower() and len(candidate) <= 8:
        score += 12.0

    # Top keyword substring
    for kw in ("pass", "admin", "love", "root", "user", "guest", "secret", "master"):
        if kw in c_lower:
            score += 8.0
            break

    return score


class GuessPrioritizer:
    """
    Prioritizes candidate password streams by reordering them based on estimated likelihood.
    Uses sliding buffer prioritization for streaming generators to prevent high memory usage.
    """

    def __init__(self, buffer_size: int = 5000):
        self.buffer_size = buffer_size

    def prioritize_list(self, candidates: List[str]) -> List[str]:
        """Sort an in-memory list in descending order of likelihood score."""
        return sorted(candidates, key=estimate_likelihood_score, reverse=True)

    def prioritize_stream(self, generator: Iterable[str]) -> Generator[str, None, None]:
        """
        Takes an arbitrary candidate generator and streams items prioritized via a sliding min-heap.
        Maintains at most `buffer_size` elements in memory.
        """
        seen: Set[str] = set()
        heap: List[tuple] = []
        counter = 0  # tie-breaker for heap stability

        for candidate in generator:
            if candidate in seen:
                continue
            seen.add(candidate)

            # Max-heap behavior in Python heapq by using negative score
            score = estimate_likelihood_score(candidate)
            heapq.heappush(heap, (-score, counter, candidate))
            counter += 1

            if len(heap) >= self.buffer_size:
                _, _, top_candidate = heapq.heappop(heap)
                yield top_candidate

        # Drain remaining candidates in priority order
        while heap:
            _, _, top_candidate = heapq.heappop(heap)
            yield top_candidate
