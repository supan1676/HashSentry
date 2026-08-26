"""
Unit tests for Report Exporter (Phase 6).
"""

import json
import os
import shutil
import tempfile
from hashsentry.execution.manager import CrackResult
from hashsentry.reporting.exporter import (
    build_audit_record,
    export_csv,
    export_json,
    export_text,
    mask_password_display,
)


def test_password_masking():
    assert mask_password_display("password") == "pa******"
    assert mask_password_display("ab") == "**"
    assert mask_password_display(None) == "<not recovered>"


def test_export_formats():
    temp_dir = tempfile.mkdtemp()
    try:
        dummy_result = CrackResult(
            found=True,
            password="Football2025",
            attempts=1204,
            elapsed_seconds=0.45,
            strategy_name="Dictionary + Rules",
            algorithm="sha256",
            target_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        records = [build_audit_record(dummy_result)]

        # CSV Export
        csv_file = os.path.join(temp_dir, "test_report.csv")
        export_csv(records, csv_file)
        assert os.path.exists(csv_file)
        with open(csv_file, "r", encoding="utf-8") as f:
            content = f.read()
            assert "Football2025" in content
            assert "CRACKED" in content

        # JSON Export
        json_file = os.path.join(temp_dir, "test_report.json")
        export_json(records, json_file)
        assert os.path.exists(json_file)
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert data["total_hashes"] == 1
            assert data["cracked_count"] == 1

        # Text Export
        txt_file = os.path.join(temp_dir, "test_report.txt")
        export_text(records, txt_file)
        assert os.path.exists(txt_file)
        with open(txt_file, "r", encoding="utf-8") as f:
            txt_content = f.read()
            assert "HASHSENTRY SECURITY AUDIT REPORT" in txt_content

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
