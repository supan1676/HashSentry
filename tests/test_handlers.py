"""
Unit tests for Hash Handlers and Factory.
"""

from hashsentry.core.handlers import FastHashHandler, SlowHashHandler, get_handler
from hashsentry.core.hasher import hash_password


def test_fast_hash_handler():
    handler = get_handler("sha256")
    assert isinstance(handler, FastHashHandler)
    assert not handler.is_slow

    target = hash_password("mypassword123", "sha256")
    assert handler.verify("mypassword123", target)
    assert not handler.verify("wrong", target)


def test_slow_hash_handler_factory():
    handler_bcrypt = get_handler("bcrypt")
    assert isinstance(handler_bcrypt, SlowHashHandler)
    assert handler_bcrypt.is_slow

    handler_argon2 = get_handler("argon2")
    assert isinstance(handler_argon2, SlowHashHandler)
    assert handler_argon2.is_slow
