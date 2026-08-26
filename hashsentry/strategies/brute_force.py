"""
Brute-force candidate generation strategy.
"""

import itertools
import string
from typing import Generator, Optional
from hashsentry.strategies.base import BaseStrategy


class BruteForceStrategy(BaseStrategy):
    """
    Generates all combinations of characters from a given charset
    across lengths from min_length to max_length.
    """

    def __init__(
        self,
        charset: str = string.ascii_lowercase + string.digits,
        min_length: int = 1,
        max_length: int = 4,
    ):
        super().__init__(name="Brute-Force")
        self.charset = charset
        self.min_length = max(1, min_length)
        self.max_length = max(self.min_length, max_length)

    def estimated_total(self) -> Optional[int]:
        c_len = len(self.charset)
        if c_len == 0:
            return 0
        total = 0
        for length in range(self.min_length, self.max_length + 1):
            total += c_len**length
        return total

    def candidates(self) -> Generator[str, None, None]:
        for length in range(self.min_length, self.max_length + 1):
            for combo in itertools.product(self.charset, repeat=length):
                yield "".join(combo)
