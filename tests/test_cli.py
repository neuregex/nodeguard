"""Tests for the CLI."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from nodesafe.cli import main


def test_version_flag() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "nodesafe" in result.output


def test_doctor_command() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["doctor"])
    assert result.exit_code == 0
    assert "nodesafe" in result.output


def test_scan_benign_exits_zero(benign_fixture: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(benign_fixture)])
    assert result.exit_code == 0
    assert "clean" in result.output.lower()


def test_scan_malicious_exits_nonzero(malicious_fixture: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(malicious_fixture)])
    assert result.exit_code != 0
    assert "malicious" in result.output.lower()


def test_scan_json_output(benign_fixture: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(benign_fixture), "--format", "json"])
    assert result.exit_code == 0
    assert "schema_version" in result.output


def test_scan_fail_on_none(malicious_fixture: Path) -> None:
    """--fail-on none should always exit 0 even for malicious targets."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(malicious_fixture), "--fail-on", "none"])
    assert result.exit_code == 0
