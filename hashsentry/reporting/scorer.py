"""
Password Strength Scorer & Policy Compliance - HashSentry (Phase 6)
=====================================================================
Calculates security ratings, entropy, pattern recognition (e.g. name+year, keyboard walk),
and audits against organizational password policy requirements.
"""

from dataclasses import dataclass, field
import math
import re
from typing import List, Optional

KEYBOARD_WALKS = [
    "qwerty", "asdfgh", "zxcvbn", "123456", "654321", "qazwsx", "wsxedc", "password"
]


@dataclass
class PolicyRule:
    min_length: int = 12
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digits: bool = True
    require_special: bool = True
    disallow_common_words: bool = True


@dataclass
class StrengthScore:
    rating: str  # CRITICAL, WEAK, MODERATE, STRONG, NOT_CRACKED
    score: int  # 0 to 100
    entropy_bits: float
    detected_patterns: List[str] = field(default_factory=list)
    policy_violations: List[str] = field(default_factory=list)
    is_policy_compliant: bool = True
    reasoning: str = ""


def calculate_entropy(password: str) -> float:
    """Calculate Shannon entropy bits for the password based on used character pool."""
    if not password:
        return 0.0

    pool_size = 0
    if any(c.islower() for c in password):
        pool_size += 26
    if any(c.isupper() for c in password):
        pool_size += 26
    if any(c.isdigit() for c in password):
        pool_size += 10
    if any(not c.isalnum() for c in password):
        pool_size += 32

    if pool_size == 0:
        return 0.0

    return len(password) * math.log2(pool_size)


def detect_patterns(password: str) -> List[str]:
    """Identify weak human composition patterns."""
    patterns = []
    p_lower = password.lower()

    # Keyboard walks
    for walk in KEYBOARD_WALKS:
        if walk in p_lower:
            patterns.append("keyboard walk")
            break

    # Name / Word + Year (e.g. Summer2024, Football2025)
    if re.search(r"^[A-Za-z]+(19\d\d|20\d\d)$", password):
        patterns.append("name/word + year")

    # Word + simple digits (e.g. dragon123)
    elif re.search(r"^[A-Za-z]+[0-9]{1,4}$", password):
        patterns.append("word + digits")

    # Simple leetspeak (e.g. p4ssw0rd)
    if re.search(r"[013457]", password) and re.search(r"[a-zA-Z]", password):
        if any(w in p_lower for w in ["p4ss", "adm1n", "l0ve", "dr4g0n", "m4st3r"]):
            patterns.append("simple leetspeak substitution")

    # Single repeated character (e.g. 111111, aaaaaa)
    if len(password) >= 4 and len(set(password)) == 1:
        patterns.append("repeated single character")

    # Only digits
    if password.isdigit():
        patterns.append("numeric-only PIN/password")

    return patterns


def check_policy(password: str, policy: Optional[PolicyRule] = None) -> List[str]:
    """Audit password against security policy rules."""
    if policy is None:
        policy = PolicyRule()

    violations = []
    if len(password) < policy.min_length:
        violations.append(f"Length {len(password)} is below minimum requirement of {policy.min_length}")

    if policy.require_uppercase and not any(c.isupper() for c in password):
        violations.append("Missing uppercase letter (A-Z)")

    if policy.require_lowercase and not any(c.islower() for c in password):
        violations.append("Missing lowercase letter (a-z)")

    if policy.require_digits and not any(c.isdigit() for c in password):
        violations.append("Missing numerical digit (0-9)")

    if policy.require_special and not any(not c.isalnum() for c in password):
        violations.append("Missing special character (!@#$%^&*...)")

    return violations


def score_password(
    password: Optional[str],
    strategy_used: str = "",
    attempts: int = 0,
    elapsed_seconds: float = 0.0,
    policy: Optional[PolicyRule] = None,
) -> StrengthScore:
    """
    Score the security strength of a recovered or unrecovered password.
    """
    if password is None:
        return StrengthScore(
            rating="NOT_CRACKED",
            score=85,
            entropy_bits=0.0,
            detected_patterns=[],
            policy_violations=[],
            is_policy_compliant=True,
            reasoning=f"Not recovered within {attempts:,} attempts and {elapsed_seconds:.2f}s of testing.",
        )

    entropy = calculate_entropy(password)
    patterns = detect_patterns(password)
    violations = check_policy(password, policy)
    is_compliant = len(violations) == 0

    # Base score computation (0-100)
    score = min(100, int(entropy * 1.2))

    strat_lower = strategy_used.lower()
    if "dictionary" in strat_lower and "rules" not in strat_lower:
        rating = "CRITICAL"
        score = min(score, 15)
        reason = "Found directly in standard weak password dictionary."
    elif "rules" in strat_lower or "mutat" in strat_lower:
        rating = "WEAK"
        score = min(score, 35)
        reason = "Found via mutated dictionary word (simple substitution, casing, or suffix)."
    elif "hybrid" in strat_lower:
        rating = "WEAK" if attempts < 100_000 else "MODERATE"
        score = min(score, 50)
        reason = "Recovered using dictionary base with brute-forced suffix."
    elif "mask" in strat_lower:
        rating = "MODERATE"
        score = min(score, 65)
        reason = "Recovered via structural pattern mask attack."
    elif "brute" in strat_lower:
        if len(password) <= 4:
            rating = "CRITICAL"
            score = min(score, 20)
            reason = "Short length allowed rapid recovery via exhaustive brute-force."
        elif len(password) <= 6:
            rating = "WEAK"
            score = min(score, 40)
            reason = "Exhaustive brute-force recovered password due to limited length."
        else:
            rating = "MODERATE"
            score = min(score, 70)
            reason = "Recovered via deep exhaustive search."
    else:
        if score < 30:
            rating = "CRITICAL"
        elif score < 50:
            rating = "WEAK"
        elif score < 75:
            rating = "MODERATE"
        else:
            rating = "STRONG"
        reason = f"Evaluated based on password entropy ({entropy:.1f} bits)."

    return StrengthScore(
        rating=rating,
        score=score,
        entropy_bits=entropy,
        detected_patterns=patterns,
        policy_violations=violations,
        is_policy_compliant=is_compliant,
        reasoning=reason,
    )
