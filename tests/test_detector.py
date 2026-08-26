"""
Unit tests for Hash Type Detector.
"""

from hashsentry.core.detector import detect_hash_type


def test_detect_bcrypt():
    res = detect_hash_type("$2b$12$KIXQ7hR8mF3n9qzXO5tYbeh2sN0V8pR1cL4jW6xT99a6k2h3")
    assert any("bcrypt" in name for name, _ in res)
    assert res[0][1] == "high"


def test_detect_argon2():
    res = detect_hash_type("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdN3ubmF")
    assert any("argon2" in name for name, _ in res)
    assert res[0][1] == "high"


def test_detect_md5_ntlm_ambiguous():
    res = detect_hash_type("72c430cbf240a47a9f7d9a7d6a6fc36a")
    names = [name for name, _ in res]
    assert "MD5" in names
    assert "NTLM" in names
    assert res[0][1] == "ambiguous"


def test_detect_sha1():
    res = detect_hash_type("fd1fa8af619ee320f1fab31824616394cc62716a")
    assert res[0][0] == "SHA-1"
    assert res[0][1] == "high"


def test_detect_sha256():
    res = detect_hash_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    names = [name for name, _ in res]
    assert "SHA-256" in names


def test_detect_sha512():
    res = detect_hash_type("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
    names = [name for name, _ in res]
    assert "SHA-512" in names


def test_detect_unknown():
    res = detect_hash_type("not_a_valid_hash_format!!")
    assert res[0][0] == "unknown"
    assert res[0][1] == "none"
