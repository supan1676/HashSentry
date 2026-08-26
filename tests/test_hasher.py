"""
Unit tests for Fast and Slow Hash computation and verification.
"""

import pytest
from hashsentry.core.hasher import (
    hash_password,
    verify_fast_hash,
    verify_bcrypt,
    verify_argon2,
    verify_scrypt,
    verify_slow_hash,
    HAS_BCRYPT,
    HAS_ARGON2,
)

try:
    import bcrypt
except ImportError:
    bcrypt = None

try:
    from argon2 import PasswordHasher
except ImportError:
    PasswordHasher = None


def test_fast_hash_md5():
    assert hash_password("password", "md5") == "5f4dcc3b5aa765d61d8327deb882cf99"
    assert verify_fast_hash("password", "5f4dcc3b5aa765d61d8327deb882cf99", "md5")
    assert not verify_fast_hash("wrong", "5f4dcc3b5aa765d61d8327deb882cf99", "md5")


def test_fast_hash_sha1():
    expected = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    assert hash_password("password", "sha1") == expected
    assert verify_fast_hash("password", expected, "sha1")


def test_fast_hash_sha256():
    expected = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    assert hash_password("password", "sha256") == expected
    assert verify_fast_hash("password", expected, "sha256")


def test_fast_hash_sha512():
    digest = hash_password("password", "sha512")
    assert len(digest) == 128
    assert verify_fast_hash("password", digest, "sha512")


def test_slow_hash_bcrypt():
    if not HAS_BCRYPT:
        pytest.skip("bcrypt not installed")
    # Generate fresh bcrypt hash
    salt = bcrypt.gensalt(rounds=4)
    hashed = bcrypt.hashpw(b"secret123", salt).decode("utf-8")

    assert verify_bcrypt("secret123", hashed)
    assert not verify_bcrypt("wrongpassword", hashed)
    assert verify_slow_hash("secret123", hashed, "bcrypt")


def test_slow_hash_argon2():
    if not HAS_ARGON2:
        pytest.skip("argon2 not installed")
    ph = PasswordHasher(time_cost=1, memory_cost=512, parallelism=1)
    hashed = ph.hash("secret123")

    assert verify_argon2("secret123", hashed)
    assert not verify_argon2("wrongpassword", hashed)
    assert verify_slow_hash("secret123", hashed, "argon2")
