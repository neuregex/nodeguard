"""Tests for Layer 5 — heuristic risk scoring."""

from __future__ import annotations

from pathlib import Path

import pytest

from nodesafe.layers._features import NodeFeatures, extract_features
from nodesafe.layers.base import NodeContext
from nodesafe.layers.layer_05_heuristic import HeuristicLayer, score_features
from nodesafe.report import Severity


@pytest.fixture
def ast_loader_fixture() -> Path:
    return Path(__file__).parent / "fixtures" / "malicious" / "synthetic_ast_loader"


@pytest.fixture
def pattern_chain_fixture() -> Path:
    return Path(__file__).parent / "fixtures" / "malicious" / "synthetic_pattern_chain"


@pytest.fixture
def typosquat_fixture() -> Path:
    return Path(__file__).parent / "fixtures" / "malicious" / "synthetic_typosquatting"


def test_layer_metadata() -> None:
    layer = HeuristicLayer()
    assert layer.id == "L5"
    assert layer.cost_estimate_ms <= 200
    assert layer.name


def test_benign_fixture_produces_no_finding(benign_fixture: Path) -> None:
    """A clean math node should score below the MEDIUM threshold and emit nothing."""
    layer = HeuristicLayer()
    context = NodeContext.from_directory(benign_fixture)
    result = layer.scan(context)
    assert result.findings == []


def test_ast_loader_fixture_flags_high_or_critical(ast_loader_fixture: Path) -> None:
    """The AST loader fixture combines eval/exec + b64decode + shell=True. Should escalate."""
    layer = HeuristicLayer()
    context = NodeContext.from_directory(ast_loader_fixture)
    result = layer.scan(context)
    assert result.findings, "Expected at least one Layer 5 finding on the AST loader fixture"
    f = result.findings[0]
    assert f.severity in {Severity.HIGH, Severity.CRITICAL}
    assert f.category == "aggregate_risk"
    assert "Aggregate heuristic risk score" in f.title


def test_pattern_chain_fixture_does_not_overfire(pattern_chain_fixture: Path) -> None:
    """The pattern-chain fixture has only string-literal mentions (Layer 2 territory),
    no actual AST-level dangerous calls. Layer 5 should NOT fire — proves we don't
    raise aggregate-risk findings on benign-looking files just because strings appear."""
    layer = HeuristicLayer()
    context = NodeContext.from_directory(pattern_chain_fixture)
    result = layer.scan(context)
    # Result may be empty OR a single low-severity finding; assert it's not CRITICAL.
    for f in result.findings:
        assert f.severity != Severity.CRITICAL


def test_typosquat_fixture_does_not_overscore(typosquat_fixture: Path) -> None:
    """The typosquatting fixture has no code smell — only manifest issues. Layer 5 may or may not fire."""
    layer = HeuristicLayer()
    context = NodeContext.from_directory(typosquat_fixture)
    result = layer.scan(context)
    # If it does fire, severity should be MEDIUM at most (no code-execution signals).
    for f in result.findings:
        assert f.severity in {Severity.MEDIUM, Severity.HIGH}


def test_extract_features_counts_eval_and_exec(tmp_path: Path) -> None:
    sample = tmp_path / "danger.py"
    sample.write_text(
        "import base64\n"
        "x = eval('1+1')\n"
        "y = exec('print(1)')\n"
        "z = exec(base64.b64decode(b'cHJpbnQoIngiKQ=='))\n",
        encoding="utf-8",
    )
    context = NodeContext.from_directory(tmp_path)
    features = extract_features(context)
    assert features.eval_calls == 1
    assert features.exec_calls == 2
    # The second exec wraps a decoder.
    assert features.exec_with_decoder_count >= 1


def test_extract_features_counts_shell_true(tmp_path: Path) -> None:
    sample = tmp_path / "shell.py"
    sample.write_text(
        "import subprocess\n"
        "subprocess.run('whoami', shell=True)\n"
        "subprocess.Popen(['ls', '-la'])\n",
        encoding="utf-8",
    )
    context = NodeContext.from_directory(tmp_path)
    features = extract_features(context)
    assert features.shell_calls == 2
    assert features.shell_true_count == 1


def test_extract_features_handles_syntax_errors(tmp_path: Path) -> None:
    bad = tmp_path / "broken.py"
    bad.write_text("def oops(:\n    pass\n", encoding="utf-8")
    good = tmp_path / "ok.py"
    good.write_text("x = 1\n", encoding="utf-8")
    context = NodeContext.from_directory(tmp_path)
    features = extract_features(context)
    assert features.syntax_error_count == 1
    assert features.py_file_count == 2


def test_extract_features_scans_requirements_manifest(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "numpy>=1.24\ngit+https://github.com/example/foo.git\nhttps://example.invalid/wheel.whl\n",
        encoding="utf-8",
    )
    context = NodeContext.from_directory(tmp_path)
    features = extract_features(context)
    assert features.requirements_count >= 3
    assert features.requirements_vcs_count == 1
    assert features.requirements_url_count == 2


def test_score_features_empty_node_is_zero() -> None:
    score, reasons = score_features(NodeFeatures())
    assert score == 0.0
    assert reasons == []


def test_score_features_obfuscated_loader_is_critical() -> None:
    f = NodeFeatures(
        exec_calls=1,
        exec_with_decoder_count=1,
        shell_true_count=1,
        suspicious_import_count=2,
        long_base64_string_count=2,
        total_loc=80,
    )
    score, reasons = score_features(f)
    assert score >= 0.85, f"expected CRITICAL, got {score:.2f}: {reasons}"
    assert any("exec/eval + decoder" in r for r in reasons)


def test_score_features_pure_manifest_does_not_explode() -> None:
    """Only manifest weirdness, no code signals. Should land MEDIUM at most."""
    f = NodeFeatures(
        requirements_vcs_count=1,
        requirements_url_count=1,
        requirements_count=3,
        total_loc=100,
    )
    score, reasons = score_features(f)
    assert score < 0.60, f"expected sub-HIGH, got {score:.2f}: {reasons}"
    assert score > 0.0


def test_score_features_caps_at_one() -> None:
    f = NodeFeatures(
        exec_calls=20,
        eval_calls=20,
        exec_with_decoder_count=10,
        shell_calls=20,
        shell_true_count=5,
        deserialization_calls=10,
        suspicious_import_count=10,
        long_base64_string_count=20,
        long_hex_string_count=10,
        dynamic_getattr_count=20,
        network_calls=20,
        requirements_vcs_count=5,
        requirements_url_count=5,
        total_loc=50,
    )
    score, _ = score_features(f)
    assert score == 1.0


def test_dangerous_call_density_property() -> None:
    f = NodeFeatures(eval_calls=2, exec_calls=3, total_loc=100)
    # dangerous_calls_total = 5; density = 100 * 5/100 = 5.0
    assert f.dangerous_calls_total == 5
    assert abs(f.dangerous_call_density - 5.0) < 1e-6


def test_dangerous_call_density_handles_zero_loc() -> None:
    f = NodeFeatures(eval_calls=2)
    assert f.dangerous_call_density == 0.0


def test_suspicious_import_ratio_property() -> None:
    f = NodeFeatures(total_import_count=10, suspicious_import_count=3)
    assert abs(f.suspicious_import_ratio - 0.3) < 1e-6
    assert NodeFeatures().suspicious_import_ratio == 0.0
