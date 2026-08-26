"""
Base interfaces and protocols for attack strategies.
"""

from abc import ABC, abstractmethod
from typing import Generator, Optional


class BaseStrategy(ABC):
    """
    Abstract Base Class for all candidate generation strategies.
    Strategies are pure candidate generators decoupled from hash testing.
    """

    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def candidates(self) -> Generator[str, None, None]:
        """Yield candidate password strings."""
        pass

    @abstractmethod
    def estimated_total(self) -> Optional[int]:
        """Return the estimated total number of candidates, or None if unknown."""
        pass
