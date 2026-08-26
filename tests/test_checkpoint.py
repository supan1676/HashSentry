"""
Unit tests for Checkpoint and Resumable Session Store (Phase 5).
"""

import os
import shutil
import tempfile
from hashsentry.execution.checkpoint import (
    delete_checkpoint,
    list_checkpoints,
    load_checkpoint,
    save_checkpoint,
)


def test_checkpoint_lifecycle():
    temp_dir = tempfile.mkdtemp()
    try:
        run_id = "test_run_12345"
        target_hash = "5f4dcc3b5aa765d61d8327deb882cf99"

        # Save checkpoint
        saved_path = save_checkpoint(
            run_id=run_id,
            target_hash=target_hash,
            algorithm="md5",
            strategy_name="Brute-Force",
            strategy_params={"charset": "abc", "max_length": 3},
            attempts=500,
            elapsed_seconds=1.25,
            last_candidate="ab",
            base_dir=temp_dir,
        )

        assert os.path.exists(saved_path)

        # Load checkpoint
        loaded = load_checkpoint(run_id, base_dir=temp_dir)
        assert loaded is not None
        assert loaded["run_id"] == run_id
        assert loaded["attempts"] == 500
        assert loaded["last_candidate"] == "ab"

        # List checkpoints
        all_cps = list_checkpoints(base_dir=temp_dir)
        assert len(all_cps) == 1
        assert all_cps[0]["run_id"] == run_id

        # Delete checkpoint
        assert delete_checkpoint(run_id, base_dir=temp_dir)
        assert load_checkpoint(run_id, base_dir=temp_dir) is None

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
