"""
Dictionary-based candidate generation strategy.
"""

import os
from typing import Generator, List, Optional, Union
from hashsentry.strategies.base import BaseStrategy


class DictionaryStrategy(BaseStrategy):
    """
    Yields words from a wordlist file or an in-memory word list.
    """

    def __init__(self, wordlist: Union[str, List[str]]):
        super().__init__(name="Dictionary")
        self.wordlist_source = wordlist
        self._cached_count: Optional[int] = None

    def estimated_total(self) -> Optional[int]:
        if self._cached_count is not None:
            return self._cached_count

        if isinstance(self.wordlist_source, list):
            self._cached_count = len(self.wordlist_source)
            return self._cached_count

        if isinstance(self.wordlist_source, str) and os.path.exists(self.wordlist_source):
            count = 0
            with open(self.wordlist_source, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.strip():
                        count += 1
            self._cached_count = count
            return self._cached_count

        return None

    def candidates(self) -> Generator[str, None, None]:
        if isinstance(self.wordlist_source, list):
            for word in self.wordlist_source:
                w = word.strip()
                if w:
                    yield w
        elif isinstance(self.wordlist_source, str):
            if not os.path.exists(self.wordlist_source):
                raise FileNotFoundError(f"Wordlist not found: {self.wordlist_source}")
            with open(self.wordlist_source, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    w = line.strip()
                    if w:
                        yield w
