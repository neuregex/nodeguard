"""Tests for Layer 3 — AST analysis."""

from __future__ import annotations

from pathlib import Path

import pytest

from nodeguard.layers.base import NodeContext
from nodeguard.layers.layer_03_ast import AstLayer
from nodeguard.report import Severity


@pytest.fixture
def ast_fixture() -> Path:
    """Path to the synthetic AST-loader fixture."""
    return Path(__file__).parent / "fixtures" / "malicious" / "synthetic_ast_loader"


def test_layer_metadata() -> None:
    layer = AstLayer()
    assert layer.id == "L3"
    assert layer.cost_estimate_ms <= 200


def test_benign_fixture_produces_no_findings(benign_fixture: Path) -> None:
    """The clean math node should not trip any AST checks."""
    layer = AstLayer()
    context = NodeContext.from_directory(benign_fixture)
    result = layer.scan(context)
    assert result.findings == []


def test_synthetic_ast_loader_triggers_multiple_categories(ast_fixture: Path) -> None:
    layer = AstLayer()
    context = NodeContext.from_directory(ast_fixture)
    result = layer.scan(context)

    assert result.findings, "Expected Layer 3 findings on the synthetic AST loader"

    categories = {f.category for f in result.findings}
    # The fixture is engineered to trip at least these categories.
    for required in {
        "code_execution",
        "shell_execution",
        "unsafe_deserialization",
        "dynamic_attribute_access",
    }:
        assert required in categories, (
            f"Expected category {required!r} in findings, got {sorted(categories)}"
        )


def test_exec_with_b64decode_escalates_to_critical(ast_fixture: Path) -> None:
    """`exec(base64.b64decode(...))` is the obfuscated-loader smell — CRITICAL."""
    layer = AstLayer()
    context = NodeContext.from_directory(ast_fixture)
    result = layer.scan(context)

    critical_code_exec = [
        f
        for f in result.findings
        if f.category == "code_execution" and f.severity == Severity.CRITICAL
    ]
    assert critical_code_exec, (
        "Expected at least one CRITICAL code_execution finding from the exec(b64decode(...)) chain"
    )


def test_subprocess_shell_true_escalates_to_critical(ast_fixture: Path) -> None:
    """`subprocess.run(..., shell=True)` must be CRITICAL, not just HIGH."""
    layer = AstLayer()
    context = NodeContext.from_directory(ast_fixture)
    result = layer.scan(context)

    critical_shell = [
        f
        for f in result.findings
        if f.category == "shell_execution" and f.severity == Severity.CRITICAL
    ]
    assert critical_shell, "Expected a CRITICAL shell_execution finding from shell=True"


def test_findings_carry_line_and_snippet(ast_fixture: Path) -> None:
    """Each finding should carry a line number and a non-empty snippet."""
    layer = AstLayer()
    context = NodeContext.from_directory(ast_fixture)
    result = layer.scan(context)

    for f in result.findings:
        assert f.line is not None and f.line > 0, f"Bad line in finding {f.id}"
        assert f.snippet, f"Empty snippet in finding {f.id}"
        assert f.file, f"Empty file in finding {f.id}"


def test_unparseable_file_does_not_crash(tmp_path: Path) -> None:
    """A `.py` file with a syntax error should be skipped silently."""
    bad = tmp_path / "broken.py"
    bad.write_text("def oops(:\n    pass\n", encoding="utf-8")

    layer = AstLayer()
    context = NodeContext.from_directory(tmp_path)
    result = layer.scan(context)

    # No findings, no exception.
    assert result.findings == []


def test_getattr_with_literal_is_not_flagged(tmp_path: Path) -> None:
    """Static `getattr(obj, "name")` is safe — should NOT trigger Layer 3."""
    sample = tmp_path / "ok.py"
    sample.write_text(
        'class C: pass\nc = C()\nx = getattr(c, "attr", None)\n',
        encoding="utf-8",
    )
    layer = AstLayer()
    context = NodeContext.from_directory(tmp_path)
    result = layer.scan(context)

    assert not any(f.category == "dynamic_attribute_access" for f in result.findings)
