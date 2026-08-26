"""
Report Exporter - HashSentry (Phase 6)
=======================================
Exports security audit reports in CSV, JSON, and Human-Readable Text formats.
Includes strength scoring, timing, speed, attempts, and policy compliance details.
"""

import csv
from dataclasses import asdict
import json
import os
import time
from typing import Any, Dict, List, Optional
from hashsentry.execution.manager import CrackResult
from hashsentry.reporting.scorer import StrengthScore, score_password


def mask_password_display(password: Optional[str]) -> str:
    """Mask password for safe screen/report display (e.g. 'fo******')."""
    if not password:
        return "<not recovered>"
    if len(password) <= 2:
        return "*" * len(password)
    return password[0:2] + "*" * max(4, len(password) - 2)


def build_audit_record(result: CrackResult, score: Optional[StrengthScore] = None) -> Dict[str, Any]:
    """Assemble a unified record dict for a crack result."""
    if score is None:
        score = score_password(
            result.password,
            strategy_used=result.strategy_name,
            attempts=result.attempts,
            elapsed_seconds=result.elapsed_seconds,
        )

    return {
        "target_hash": result.target_hash,
        "algorithm": result.algorithm,
        "status": "CRACKED" if result.found else ("INTERRUPTED" if result.interrupted else "EXHAUSTED"),
        "password_masked": mask_password_display(result.password),
        "password_plain": result.password if result.password else "",
        "strategy": result.strategy_name,
        "attempts": result.attempts,
        "elapsed_seconds": round(result.elapsed_seconds, 3),
        "speed_hps": round(result.speed, 1),
        "strength_rating": score.rating,
        "score_0_to_100": score.score,
        "entropy_bits": round(score.entropy_bits, 1),
        "patterns_detected": ", ".join(score.detected_patterns) if score.detected_patterns else "none",
        "policy_compliant": "YES" if score.is_policy_compliant else "NO",
        "policy_violations": "; ".join(score.policy_violations) if score.policy_violations else "none",
        "reasoning": score.reasoning,
    }


def export_csv(records: List[Dict[str, Any]], filepath: str) -> str:
    """Export audit records to a CSV file."""
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    fieldnames = [
        "target_hash",
        "algorithm",
        "status",
        "password_masked",
        "password_plain",
        "strategy",
        "attempts",
        "elapsed_seconds",
        "speed_hps",
        "strength_rating",
        "score_0_to_100",
        "entropy_bits",
        "patterns_detected",
        "policy_compliant",
        "policy_violations",
        "reasoning",
    ]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in records:
            writer.writerow(r)
    return filepath


def export_json(records: List[Dict[str, Any]], filepath: str) -> str:
    """Export audit records to a JSON file."""
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    report_data = {
        "tool": "HashSentry",
        "version": "1.0.0",
        "export_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_hashes": len(records),
        "cracked_count": sum(1 for r in records if r["status"] == "CRACKED"),
        "records": records,
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)
    return filepath


def export_text(records: List[Dict[str, Any]], filepath: str) -> str:
    """Export a human-readable text audit report."""
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    total = len(records)
    cracked = sum(1 for r in records if r["status"] == "CRACKED")
    pct = (cracked / total * 100) if total > 0 else 0.0

    lines = [
        "=" * 70,
        "                  HASHSENTRY SECURITY AUDIT REPORT",
        "=" * 70,
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"Total Hashes Audited: {total}",
        f"Successfully Recovered: {cracked} ({pct:.1f}%)",
        "-" * 70,
        "",
    ]

    for i, r in enumerate(records, 1):
        lines.extend([
            f"[{i}] Hash: {r['target_hash']}",
            f"    Algorithm:      {r['algorithm']}",
            f"    Status:         {r['status']}",
            f"    Password:       {r['password_masked']}",
            f"    Strategy:       {r['strategy']}",
            f"    Attempts/Time:  {r['attempts']:,} attempts in {r['elapsed_seconds']}s ({r['speed_hps']:,} H/s)",
            f"    Strength:       {r['strength_rating']} (Score: {r['score_0_to_100']}/100, Entropy: {r['entropy_bits']} bits)",
            f"    Patterns:       {r['patterns_detected']}",
            f"    Policy Pass:    {r['policy_compliant']} ({r['policy_violations']})",
            f"    Assessment:     {r['reasoning']}",
            "",
        ])

    lines.append("=" * 70)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return filepath
