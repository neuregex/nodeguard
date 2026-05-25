"""Tests for the Scanner orchestrator and Report aggregation."""

from __future__ import annotations

from pathlib import Path

import pytest

from nodeguard.config import Config
from nodeguard.report import VerdictLabel
from nodeguard.scanner import Scanner


def test_benign_target_yields_clean_verdict(benign_fixture: Path) -> None:
    scanner = Scanner()
    report = scanner.scan(benign_fixture)

    assert report.verdict.label == VerdictLabel.CLEAN
    assert report.findings == []
    assert report.recommendation == "install"
    assert "L0" in report.scan.layers_run
    assert "L1" in report.scan.layers_run


def test_malicious_target_yields_malicious_verdict(malicious_fixture: Path) -> None:
    scanner = Scanner()
    report = scanner.scan(malicious_fixture)

    assert report.verdict.label == VerdictLabel.MALICIOUS
    assert report.recommendation == "do_not_install"
    assert report.findings, "Expected findings"


def test_scanner_raises_on_missing_target(tmp_path: Path) -> None:
    scanner = Scanner()
    with pytest.raises(FileNotFoundError):
        scanner.scan(tmp_path / "does-not-exist")


def test_report_to_json_roundtrip(benign_fixture: Path) -> None:
    """Report must serialize to JSON cleanly."""
    scanner = Scanner()
    report = scanner.scan(benign_fixture)
    payload = report.to_json()
    assert "schema_version" in payload
    assert "nodeguard" in payload


def test_report_to_markdown_includes_verdict(benign_fixture: Path) -> None:
    scanner = Scanner()
    report = scanner.scan(benign_fixture)
    md = report.to_markdown()
    assert "verdict" in md.lower()
    assert "clean" in md.lower()


def test_layer_selection_via_config(benign_fixture: Path) -> None:
    """Restricting to Layer 0 should skip Layer 1."""
    cfg = Config()
    cfg.scanner.default_layers = "0"
    scanner = Scanner(config=cfg)
    report = scanner.scan(benign_fixture)
    assert report.scan.layers_run == ["L0"]
