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


def test_batch_mode_scans_each_subdir(
    tmp_path: Path, benign_fixture: Path, malicious_fixture: Path
) -> None:
    """--batch over a parent with one benign + one malicious subdir produces both verdicts."""
    import shutil

    parent = tmp_path / "custom_nodes"
    parent.mkdir()
    shutil.copytree(benign_fixture, parent / "benign_node")
    shutil.copytree(malicious_fixture, parent / "malicious_node")

    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(parent), "--batch"])
    # malicious in the batch -> non-zero exit per --fail-on suspicious default
    assert result.exit_code != 0
    assert "benign_node" in result.output
    assert "malicious_node" in result.output
    assert "Worst verdict" in result.output


def test_batch_mode_json_output(tmp_path: Path, benign_fixture: Path) -> None:
    """--batch with --format json emits a JSON array."""
    import json
    import shutil

    parent = tmp_path / "custom_nodes"
    parent.mkdir()
    shutil.copytree(benign_fixture, parent / "benign_one")
    shutil.copytree(benign_fixture, parent / "benign_two")

    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(parent), "--batch", "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert isinstance(payload, list)
    assert len(payload) == 2
    names = {entry["node"] for entry in payload}
    assert names == {"benign_one", "benign_two"}


def test_batch_mode_empty_dir_warns(tmp_path: Path) -> None:
    """--batch on an empty directory exits 0 with a warning."""
    empty = tmp_path / "no_nodes"
    empty.mkdir()
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(empty), "--batch"])
    assert result.exit_code == 0
    assert "no subdirectories" in result.output.lower()
