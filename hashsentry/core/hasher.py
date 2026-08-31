"""
Hashing and Verification Engine - HashSentry
==============================================
Provides computation for fast unsalted/fast hashes (MD5, SHA-1, SHA-2, MD4, NTLM)
and verification for slow/salted hashes (bcrypt, Argon2, scrypt).
"""

import base64
import hashlib
from typing import Optional, Tuple

try:
    import bcrypt

    HAS_BCRYPT = True
except ImportError:
    HAS_BCRYPT = False

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import InvalidHashError, VerifyMismatchError

    HAS_ARGON2 = True
    _ARGON2_HASHER = PasswordHasher()
except ImportError:
    HAS_ARGON2 = False
    _ARGON2_HASHER = None


# Profile definitions: (hashlib_algo_name, encoding)
FAST_HASH_PROFILES = {
    "md5": ("md5", "utf-8"),
    "sha1": ("sha1", "utf-8"),
    "sha224": ("sha224", "utf-8"),
    "sha256": ("sha256", "utf-8"),
    "sha384": ("sha384", "utf-8"),
    "sha512": ("sha512", "utf-8"),
    "sha3_224": ("sha3_224", "utf-8"),
    "sha3_256": ("sha3_256", "utf-8"),
    "sha3_384": ("sha3_384", "utf-8"),
    "sha3_512": ("sha3_512", "utf-8"),
    "md4": ("md4", "utf-8"),
    "ntlm": ("md4", "utf-16-le"),
}


def normalize_algo_name(name: str) -> str:
    """Normalize algorithm name strings to profile keys."""
    n = name.lower().strip().replace("-", "").replace("_", "")
    if n in ("md5", "ntlm", "md4"):
        return n
    if n in ("sha1", "sha224", "sha256", "sha384", "sha512"):
        return n
    if n.startswith("sha3"):
        # e.g. sha3256 -> sha3_256
        suffix = n[4:]
        return f"sha3_{suffix}"
    if n.startswith("bcrypt"):
        return "bcrypt"
    if n.startswith("argon2"):
        return "argon2"
    if n.startswith("scrypt"):
        return "scrypt"
    return n


def hash_password(password: str, profile: str = "sha256") -> str:
    """
    Hash a plaintext password with the given fast hash profile and return hex digest.
    """
    p_key = normalize_algo_name(profile)
    if p_key not in FAST_HASH_PROFILES:
        raise ValueError(f"Unknown fast hash profile: '{profile}'")

    algo_name, encoding = FAST_HASH_PROFILES[p_key]
    try:
        h = hashlib.new(algo_name)
    except ValueError:
        # Fallback for MD4 on Windows / modern OpenSSL if hashlib.new fails
        if algo_name == "md4":
            raise ValueError(
                f"Algorithm '{algo_name}' is not supported by this OpenSSL build."
            )
        raise ValueError(f"Algorithm '{algo_name}' is not available in hashlib.")

    h.update(password.encode(encoding))
    return h.hexdigest()


def verify_fast_hash(candidate: str, target_hash: str, profile: str = "sha256") -> bool:
    """Compare candidate's fast hash against target hash in a case-insensitive manner."""
    try:
        digest = hash_password(candidate, profile)
        return digest.lower() == target_hash.lower().strip()
    except Exception:
        return False


def verify_bcrypt(candidate: str, target_hash: str) -> bool:
    """Verify a password candidate against a bcrypt hash."""
    if not HAS_BCRYPT:
        raise RuntimeError("bcrypt library is not installed. Install via `pip install bcrypt`.")
    try:
        pwd_bytes = candidate.encode("utf-8")
        hash_bytes = target_hash.strip().encode("utf-8")
        return bcrypt.checkpw(pwd_bytes, hash_bytes)
    except Exception:
        return False


def verify_argon2(candidate: str, target_hash: str) -> bool:
    """Verify a password candidate against an Argon2 hash string."""
    if not HAS_ARGON2 or _ARGON2_HASHER is None:
        raise RuntimeError(
            "argon2-cffi library is not installed. Install via `pip install argon2-cffi`."
        )
    try:
        _ARGON2_HASHER.verify(target_hash.strip(), candidate)
        return True
    except (VerifyMismatchError, InvalidHashError):
        return False
    except Exception:
        return False


def parse_scrypt_hash(hash_str: str) -> Optional[Tuple[int, int, int, bytes, bytes]]:
    """
    Parse a standard formatted scrypt string:
    $scrypt$ln=14,r=8,p=1$<salt_b64>$<hash_b64> or $7$<params><salt>$<hash>
    Returns (n, r, p, salt_bytes, expected_hash_bytes) or None
    """
    try:
        h = hash_str.strip()
        if h.startswith("$scrypt$"):
            parts = h.split("$")[2:]  # ['ln=14,r=8,p=1', 'salt', 'hash']
            if len(parts) != 3:
                return None
            params_str, salt_b64, hash_b64 = parts
            params = {}
            for item in params_str.split(","):
                k, v = item.split("=")
                params[k.strip()] = int(v.strip())
            ln = params.get("ln", 14)
            n = 2**ln
            r = params.get("r", 8)
            p = params.get("p", 1)
            salt = base64.b64decode(salt_b64)
            expected = base64.b64decode(hash_b64)
            return (n, r, p, salt, expected)
    except Exception:
        return None


def verify_scrypt(candidate: str, target_hash: str) -> bool:
    """Verify password candidate against an scrypt hash string."""
    parsed = parse_scrypt_hash(target_hash)
    if not parsed:
        return False
    n, r, p, salt, expected_hash = parsed
    try:
        derived = hashlib.scrypt(
            candidate.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            maxmem=0,
            dklen=len(expected_hash),
        )
        return derived == expected_hash
    except Exception:
        return False


def verify_slow_hash(candidate: str, target_hash: str, algo: str) -> bool:
    """Route slow hash verification to the appropriate algorithm handler."""
    norm = normalize_algo_name(algo)
    if norm == "bcrypt":
        return verify_bcrypt(candidate, target_hash)
    if norm == "argon2":
        return verify_argon2(candidate, target_hash)
    if norm == "scrypt":
        return verify_scrypt(candidate, target_hash)
    raise ValueError(f"Unsupported slow hash algorithm: {algo}")
