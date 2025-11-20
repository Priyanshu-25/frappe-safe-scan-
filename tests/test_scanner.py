import frappe_safe_scan
from pathlib import Path

def test_scan_detects_insecure_file():
    results = frappe_safe_scan.scan_directory(".")
    assert any("sample_insecure.py" in k for k in results), "Should detect insecure file"
