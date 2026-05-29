"""Tests for the workflow auditor (parser + analyzers + CLI subcommand)."""

from __future__ import annotations

import json
import struct
import zlib
from pathlib import Path

import pytest
from click.testing import CliRunner

from nodesafe.cli import main
from nodesafe.report import Severity, VerdictLabel
from nodesafe.workflow import (
    Workflow,
    WorkflowParseError,
    WorkflowScanner,
    parse_workflow,
)
from nodesafe.workflow.analyzers import pattern_findings, url_findings
from nodesafe.workflow.extractors import concatenated_widget_text, extract_urls

# --- fixtures --------------------------------------------------------


@pytest.fixture
def benign_workflow() -> Path:
    return Path(__file__).parent / "fixtures" / "benign" / "workflows" / "sdxl_basic.json"


@pytest.fixture
def malicious_workflow_json() -> Path:
    return (
        Path(__file__).parent
        / "fixtures"
        / "malicious"
        / "workflows"
        / "synthetic_workflow_malicious.json"
    )


@pytest.fixture
def malicious_workflow_png() -> Path:
    return (
        Path(__file__).parent
        / "fixtures"
        / "malicious"
        / "workflows"
        / "synthetic_workflow_malicious.png"
    )


# --- parser tests ---------------------------------------------------


def test_parse_ui_form_json(benign_workflow: Path) -> None:
    wf = parse_workflow(benign_workflow)
    assert wf.form == "ui"
    assert len(wf.nodes) == 5
    assert "CheckpointLoaderSimple" in wf.node_types()
    assert "KSampler" in wf.node_types()


def test_parse_prompt_form_json(tmp_path: Path) -> None:
    """Prompt form is a dict keyed by node IDs, each having class_type + inputs."""
    payload = {
        "1": {"class_type": "CLIPTextEncode", "inputs": {"text": "a cat"}},
        "2": {"class_type": "HTTPRequest", "inputs": {"url": "https://example.com"}},
    }
    p = tmp_path / "prompt.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    wf = parse_workflow(p)
    assert wf.form == "prompt"
    assert len(wf.nodes) == 2
    assert {n.type for n in wf.nodes} == {"CLIPTextEncode", "HTTPRequest"}


def test_parse_png_with_workflow_chunk(malicious_workflow_png: Path) -> None:
    wf = parse_workflow(malicious_workflow_png)
    assert wf.form == "ui"
    assert len(wf.nodes) == 2
    assert "ExecutePython" in wf.node_types()


def test_parse_png_without_metadata_raises(tmp_path: Path) -> None:
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = _chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0))
    idat = _chunk(b"IDAT", zlib.compress(b"\x00\x00"))
    iend = _chunk(b"IEND", b"")
    p = tmp_path / "empty.png"
    p.write_bytes(sig + ihdr + idat + iend)
    with pytest.raises(WorkflowParseError):
        parse_workflow(p)


def test_parse_nonexistent_raises() -> None:
    with pytest.raises(WorkflowParseError):
        parse_workflow("/does/not/exist.json")


def test_parse_malformed_json_raises(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text("{ not valid", encoding="utf-8")
    with pytest.raises(WorkflowParseError):
        parse_workflow(p)


# --- extractor tests ------------------------------------------------


def test_iter_string_widgets_returns_only_strings() -> None:
    from nodesafe.workflow.models import WorkflowNode as WN

    wf = Workflow(
        source="t",
        form="ui",
        nodes=[
            WN(id="1", type="X", widget_values=["a string", 42, 3.14, True, "another"]),
            WN(id="2", type="Y", widget_values=[None, "third"]),
        ],
    )
    strings = wf.iter_string_widgets()
    assert len(strings) == 3
    assert all(isinstance(v, str) for _, _, _, v in strings)


def test_concatenated_widget_text_joins_strings(benign_workflow: Path) -> None:
    wf = parse_workflow(benign_workflow)
    text = concatenated_widget_text(wf)
    assert "serene mountain lake" in text


def test_extract_urls_finds_http(tmp_path: Path) -> None:
    payload = {
        "nodes": [
            {"id": 1, "type": "T", "widgets_values": ["see https://example.com/page!"]},
            {"id": 2, "type": "T", "widgets_values": ["no url here"]},
        ],
        "version": 0.4,
    }
    p = tmp_path / "w.json"
    p.write_text(json.dumps(payload))
    wf = parse_workflow(p)
    urls = extract_urls(wf)
    assert len(urls) == 1
    assert urls[0][2] == "https://example.com/page"


# --- analyzer tests -------------------------------------------------


def test_wl1_url_findings_on_malicious(malicious_workflow_json: Path) -> None:
    wf = parse_workflow(malicious_workflow_json)
    findings = url_findings(wf)
    # The test_signatures conftest seeds the malicious_urls.txt with the
    # discord webhook used in the fixture.
    assert findings
    assert all(f.severity == Severity.CRITICAL for f in findings)


def test_wl2_pattern_findings_on_malicious(malicious_workflow_json: Path) -> None:
    wf = parse_workflow(malicious_workflow_json)
    findings = pattern_findings(wf)
    categories = {f.category for f in findings}
    # The fixture combines code_execution (eval, __import__), shell_execution,
    # exfiltration_channel.
    assert "code_execution" in categories or "exfiltration_channel" in categories
    assert findings


def test_benign_workflow_has_no_findings(benign_workflow: Path) -> None:
    wf = parse_workflow(benign_workflow)
    assert url_findings(wf) == []
    assert pattern_findings(wf) == []


# --- scanner tests --------------------------------------------------


def test_scanner_emits_malicious_verdict(malicious_workflow_json: Path) -> None:
    scanner = WorkflowScanner()
    report = scanner.scan(malicious_workflow_json)
    assert report.verdict.label == VerdictLabel.MALICIOUS
    assert report.recommendation == "do_not_install"
    assert report.findings
    assert report.scan.layers_run == ["WL1", "WL2"]


def test_scanner_emits_clean_verdict_on_benign(benign_workflow: Path) -> None:
    scanner = WorkflowScanner()
    report = scanner.scan(benign_workflow)
    assert report.verdict.label == VerdictLabel.CLEAN
    assert report.recommendation == "install"


def test_scanner_handles_png(malicious_workflow_png: Path) -> None:
    scanner = WorkflowScanner()
    report = scanner.scan(malicious_workflow_png)
    assert report.verdict.label == VerdictLabel.MALICIOUS


# --- CLI tests ------------------------------------------------------


def test_cli_scan_workflow_benign_exits_zero(benign_workflow: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["scan-workflow", str(benign_workflow)])
    assert result.exit_code == 0
    assert "clean" in result.output.lower()


def test_cli_scan_workflow_malicious_exits_nonzero(malicious_workflow_json: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["scan-workflow", str(malicious_workflow_json)])
    assert result.exit_code != 0
    assert "malicious" in result.output.lower()


def test_cli_scan_workflow_json_output(benign_workflow: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["scan-workflow", str(benign_workflow), "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["verdict"]["label"] == "clean"


def test_cli_scan_workflow_unparseable_exits_3(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(main, ["scan-workflow", str(bad)])
    assert result.exit_code == 3
    assert "error" in result.output.lower()


# --- helpers --------------------------------------------------------


def _chunk(type_bytes: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + type_bytes
        + data
        + struct.pack(">I", zlib.crc32(type_bytes + data) & 0xFFFFFFFF)
    )
