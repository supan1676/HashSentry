"""
Pattern & Combinatorial Stream Strategy - HashSentry
=====================================================
Generates in-memory candidate combinations with zero disk storage (O(1) memory).
Appends every combination of selected character sets (A-Z, a-z, 0-9, special symbols)
to an optional base string (e.g. 'bante').
"""

import itertools
import string
from typing import Generator, Optional
from hashsentry.strategies.base import BaseStrategy

# Standard character set presets
CHARSET_ALL_PRINTABLE = string.ascii_letters + string.digits + string.punctuation  # 94 chars
CHARSET_ALPHANUMERIC = string.ascii_letters + string.digits                        # 62 chars
CHARSET_LOWER_NUM = string.ascii_lowercase + string.digits                         # 36 chars
CHARSET_LETTERS = string.ascii_letters                                             # 52 chars
CHARSET_DIGITS = string.digits                                                     # 10 chars
CHARSET_SYMBOLS = string.punctuation                                               # 32 chars


class PatternStrategy(BaseStrategy):
    """
    In-memory generator streaming Cartesian product combinations across length ranges.
    Can be used with a base prefix (e.g. 'bante') or without any prefix for full combinations.
    """

    def __init__(
        self,
        base_prefix: str = "",
        charset: str = CHARSET_ALL_PRINTABLE,
        min_suffix_len: int = 1,
        max_suffix_len: int = 2,
    ):
        super().__init__(name="Pattern Streaming")
        self.base_prefix = base_prefix
        self.charset = charset if charset else CHARSET_ALL_PRINTABLE
        self.min_suffix_len = max(0, min_suffix_len)
        self.max_suffix_len = max(self.min_suffix_len, max_suffix_len)

    def estimated_total(self) -> Optional[int]:
        c_len = len(self.charset)
        if c_len == 0:
            return 1 if self.min_suffix_len == 0 and self.base_prefix else 0
        total = 0
        if self.min_suffix_len == 0 and self.base_prefix:
            total += 1
        start_len = max(1, self.min_suffix_len)
        for length in range(start_len, self.max_suffix_len + 1):
            total += c_len**length
        return total

    def candidates(self) -> Generator[str, None, None]:
        # If min_suffix_len is 0 and there is a base prefix, yield base prefix first
        if self.min_suffix_len == 0 and self.base_prefix:
            yield self.base_prefix

        start_len = max(1, self.min_suffix_len)
        for length in range(start_len, self.max_suffix_len + 1):
            for combo in itertools.product(self.charset, repeat=length):
                yield f"{self.base_prefix}{''.join(combo)}"
