"""
Hash Handler Layer (Factory Pattern) - HashSentry
===================================================
Decouples candidate verification from candidate generation.
FastHashHandler: recompute and compare.
SlowHashHandler: delegated verification via native crypto algorithms.
"""

from abc import ABC, abstractmethod
from hashsentry.core.hasher import (
    FAST_HASH_PROFILES,
    normalize_algo_name,
    verify_fast_hash,
    verify_slow_hash,
)

SLOW_HASH_FAMILIES = {"bcrypt", "argon2", "scrypt"}


class BaseHashHandler(ABC):
    """Abstract interface for hash verification handlers."""

    def __init__(self, algorithm: str, is_slow: bool = False):
        self.algorithm = algorithm
        self.is_slow = is_slow

    @abstractmethod
    def verify(self, candidate: str, target_hash: str) -> bool:
        """Verify whether candidate matches the target hash."""
        pass


class FastHashHandler(BaseHashHandler):
    """Handler for fast unsalted/cryptographic hashes (MD5, SHA family, NTLM, MD4)."""

    def __init__(self, profile: str = "sha256"):
        super().__init__(algorithm=profile, is_slow=False)
        self.profile = normalize_algo_name(profile)

    def verify(self, candidate: str, target_hash: str) -> bool:
        return verify_fast_hash(candidate, target_hash, self.profile)


class SlowHashHandler(BaseHashHandler):
    """Handler for slow/salted hashes (bcrypt, Argon2, scrypt)."""

    def __init__(self, algorithm: str):
        super().__init__(algorithm=algorithm, is_slow=True)
        self.algorithm_norm = normalize_algo_name(algorithm)

    def verify(self, candidate: str, target_hash: str) -> bool:
        return verify_slow_hash(candidate, target_hash, self.algorithm_norm)


def get_handler(algo_name: str) -> BaseHashHandler:
    """
    Factory function to instantiate the correct HashHandler for a given algorithm name.
    """
    norm = normalize_algo_name(algo_name)
    if norm in SLOW_HASH_FAMILIES:
        return SlowHashHandler(algorithm=norm)
    if norm in FAST_HASH_PROFILES:
        return FastHashHandler(profile=norm)
    # Default to fast hash profile if not explicitly recognized as slow
    return FastHashHandler(profile=norm)
