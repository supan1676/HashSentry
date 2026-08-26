"""
Hash Type Detector - HashSentry
================================
Identifies likely hash algorithm(s) from format (prefixes, delimiters, length, and charsets).
Distinguishes between self-describing formats (high confidence) and bare hex digests (ambiguous).
"""

import re
from typing import List, Tuple

# Self-describing formats with specific signatures/prefixes
PREFIX_PATTERNS = [
    (r"^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$", "bcrypt"),
    (r"^\$2[abxy]\$", "bcrypt"),
    (r"^\$argon2(id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$", "argon2"),
    (r"^\$argon2(id|i|d)\$", "argon2"),
    (r"^\$7\$[./A-Za-z0-9]+", "scrypt"),
    (r"^\$scrypt\$[./A-Za-z0-9]+", "scrypt"),
    (r"^\$6\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{86}$", "sha512crypt (Linux shadow)"),
    (r"^\$6\$", "sha512crypt (Linux shadow)"),
    (r"^\$5\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{43}$", "sha256crypt (Linux shadow)"),
    (r"^\$5\$", "sha256crypt (Linux shadow)"),
    (r"^\$1\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{22}$", "md5crypt (Linux shadow)"),
    (r"^\$1\$", "md5crypt (Linux shadow)"),
    (r"^\$P\$[./0-9A-Za-z]{31}$", "phpass (WordPress/phpBB)"),
    (r"^\$H\$[./0-9A-Za-z]{31}$", "phpass (WordPress/phpBB)"),
    (r"^\$P\$", "phpass (WordPress/phpBB)"),
    (r"^\$H\$", "phpass (WordPress/phpBB)"),
]

# Bare hex digests classified by hex character length
HEX_LENGTH_PATTERNS = {
    32: ["MD5", "NTLM", "MD4"],
    40: ["SHA-1"],
    56: ["SHA-224", "SHA3-224"],
    64: ["SHA-256", "SHA3-256", "BLAKE2s-256"],
    96: ["SHA-384", "SHA3-384"],
    128: ["SHA-512", "SHA3-512", "BLAKE2b-512"],
}


def detect_hash_type(hash_string: str) -> List[Tuple[str, str]]:
    """
    Analyzes a given hash string and returns a list of candidate (algorithm_name, confidence).
    Confidence is:
      - 'high': Self-describing prefix match or unambiguous digest length
      - 'ambiguous': Digest length matches multiple plausible algorithms (e.g. 32 hex chars -> MD5, NTLM, MD4)
      - 'low': Delimited or format-unusual pattern
      - 'none': Unrecognized format
    """
    h = hash_string.strip()
    if not h:
        return [("unknown", "none")]

    # Check self-describing prefixes
    for pattern, name in PREFIX_PATTERNS:
        if re.match(pattern, h, re.IGNORECASE):
            return [(name, "high")]

    # Check for salt-delimited formats (e.g. hash:salt or username:hash)
    if ":" in h and not h.startswith("$"):
        parts = h.split(":")
        # Check if first or second part is hex
        sub_types = []
        for i, p in enumerate(parts):
            if re.fullmatch(r"[a-fA-F0-9]+", p):
                cand = HEX_LENGTH_PATTERNS.get(len(p))
                if cand:
                    sub_types.append(f"part {i+1} resembles {cand[0]}")
        sub_desc = f"salt-separated format ({len(parts)} parts"
        if sub_types:
            sub_desc += f": {', '.join(sub_types)}"
        sub_desc += ")"
        return [(sub_desc, "low")]

    # Check bare hex strings
    if re.fullmatch(r"[a-fA-F0-9]+", h):
        length = len(h)
        candidates = HEX_LENGTH_PATTERNS.get(length)
        if candidates:
            confidence = "high" if len(candidates) == 1 else "ambiguous"
            return [(name, confidence) for name in candidates]

    return [("unknown", "none")]
