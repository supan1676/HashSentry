"""
Session and Checkpointing Store - HashSentry (Phase 5)
======================================================
Persists in-progress run state to flat-file JSON so long runs can be interrupted
and resumed without data loss. Implements atomic writes to prevent corruption (NFR-3).
"""

import json
import os
import tempfile
import time
from typing import Any, Dict, List, Optional

CHECKPOINTS_DIR = "checkpoints"


def _ensure_checkpoints_dir(base_dir: str = CHECKPOINTS_DIR) -> str:
    """Ensure directory exists and return absolute path."""
    os.makedirs(base_dir, exist_ok=True)
    return base_dir


def get_checkpoint_path(run_id: str, base_dir: str = CHECKPOINTS_DIR) -> str:
    """Return the file path for a run's checkpoint."""
    _ensure_checkpoints_dir(base_dir)
    safe_id = "".join(c for c in run_id if c.isalnum() or c in ("-", "_"))
    return os.path.join(base_dir, f"{safe_id}.json")


def save_checkpoint(
    run_id: str,
    target_hash: str,
    algorithm: str,
    strategy_name: str,
    strategy_params: Dict[str, Any],
    attempts: int,
    elapsed_seconds: float,
    last_candidate: Optional[str] = None,
    base_dir: str = CHECKPOINTS_DIR,
) -> str:
    """
    Atomically save run state to a JSON checkpoint file.
    """
    _ensure_checkpoints_dir(base_dir)
    target_file = get_checkpoint_path(run_id, base_dir)

    data = {
        "run_id": run_id,
        "target_hash": target_hash,
        "algorithm": algorithm,
        "strategy_name": strategy_name,
        "strategy_params": strategy_params,
        "attempts": attempts,
        "elapsed_seconds": elapsed_seconds,
        "last_candidate": last_candidate,
        "timestamp": time.time(),
        "date_saved": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    # Atomic write pattern: write to temp file in same dir, then replace
    dir_name = os.path.dirname(target_file)
    with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False, encoding="utf-8") as tf:
        json.dump(data, tf, indent=2)
        temp_name = tf.name

    os.replace(temp_name, target_file)
    return target_file


def load_checkpoint(run_id: str, base_dir: str = CHECKPOINTS_DIR) -> Optional[Dict[str, Any]]:
    """Load checkpoint data by run ID, or return None if not found or corrupted."""
    path = get_checkpoint_path(run_id, base_dir)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def list_checkpoints(base_dir: str = CHECKPOINTS_DIR) -> List[Dict[str, Any]]:
    """List all saved checkpoints ordered by timestamp descending."""
    _ensure_checkpoints_dir(base_dir)
    checkpoints = []
    if not os.path.exists(base_dir):
        return checkpoints

    for fname in os.listdir(base_dir):
        if fname.endswith(".json"):
            path = os.path.join(base_dir, fname)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict) and "run_id" in data:
                        checkpoints.append(data)
            except Exception:
                continue

    checkpoints.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
    return checkpoints


def delete_checkpoint(run_id: str, base_dir: str = CHECKPOINTS_DIR) -> bool:
    """Delete a checkpoint file upon successful completion."""
    path = get_checkpoint_path(run_id, base_dir)
    if os.path.exists(path):
        try:
            os.remove(path)
            return True
        except OSError:
            return False
    return False
