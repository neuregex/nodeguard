"""Tests for Layer 2 — Aho-Corasick pattern matching."""

from __future__ import annotations

from pathlib import Path

import pytest

from nodeguard.data.signatures import PatternCategory, load_pattern_categories
from nodeguard.layers.base import NodeContext
from nodeguard.layers.layer_02_patterns import PatternLayer
from nodeguard.report import Severity


@pytest.fixture
def pattern_fixture(tmp_path: Path) -> Path:
    """Path to the synthetic-pattern-chain fixture."""
    return Path(__file__).parent / "fixtures" / "malicious" / "synthetic_pattern_chain"


def test_load_pattern_categories_returns_curated_set() -> None:
    """The bundled patterns file should load into PatternCategory instances."""
    cats = load_pattern_categories()
    assert cats, "Expected the bundled patterns.json to define categories"

    by_name = {c.name: c for c in cats}
    # Sanity-check a few category names that the test fixture relies on.
    for required in (
        "code_execution",
        "shell_execution",
        "encoded_payload",
        "exfiltration_channel",
        "wallet_paths",
    ):
        assert required in by_name, f"Missing required category {required!r}"
        assert by_name[required].patterns, f"{required!r} category should have patterns"


def test_layer_metadata() -> None:
    layer = PatternLayer()
    assert layer.id == "L2"
    assert layer.cost_estimate_ms <= 200  # Layer 2 must stay cheap


def test_benign_fixture_produces_no_findings(benign_fixture: Path) -> None:
    """The clean fixture should not trip any Layer 2 patterns."""
    layer = PatternLayer()
    context = NodeContext.from_directory(benign_fixture)
    result = layer.scan(context)
    assert result.findings == []


def test_synthetic_pattern_chain_triggers_multiple_categories(
    pattern_fixture: Path,
) -> None:
    """The synthetic fixture mentions patterns from several categories.

    The layer should fire one finding per (pattern, line) pair, and the
    findings should span the expected categories.
    """
    layer = PatternLayer()
    context = NodeContext.from_directory(pattern_fixture)
    result = layer.scan(context)

    assert result.findings, "Expected Layer 2 findings on the synthetic chain"
    categories = {f.category for f in result.findings}
    # The fixture is engineered to mention literals from at least these
    # categories — don't tighten the assertion further so future pattern
    # tweaks don't break tests for cosmetic reasons.
    for required in {"code_execution", "exfiltration_channel"}:
        assert required in categories, (
            f"Expected category {required!r} in findings, got {categories}"
        )


def test_severity_mapping_is_applied() -> None:
    """A category with `severity: critical` should produce CRITICAL findings."""
    # Build a tiny synthetic category to make the test independent of the
    # bundled patterns evolving.
    cat = PatternCategory(
        name="test_critical",
        severity="critical",
        cwe="CWE-200",
        description="test only",
        patterns=["__TEST_CRITICAL_PATTERN__"],
    )
    layer = PatternLayer(categories=[cat])

    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        sample = tmp / "sample.py"
        sample.write_text("x = '__TEST_CRITICAL_PATTERN__'\n", encoding="utf-8")
        context = NodeContext.from_directory(tmp)
        result = layer.scan(context)

    assert result.findings, "Expected the test pattern to be detected"
    assert all(f.severity == Severity.CRITICAL for f in result.findings)
    assert all(f.cwe == "CWE-200" for f in result.findings)


def test_empty_pattern_set_is_a_noop(tmp_path: Path) -> None:
    """Constructing the layer with zero patterns must not crash."""
    layer = PatternLayer(categories=[])
    sample = tmp_path / "x.py"
    sample.write_text("eval('1+1')\n", encoding="utf-8")
    context = NodeContext.from_directory(tmp_path)
    result = layer.scan(context)
    assert result.findings == []


def test_duplicate_match_in_same_line_emits_one_finding(tmp_path: Path) -> None:
    """Two occurrences of the same pattern in one line should report once."""
    cat = PatternCategory(
        name="test_dup",
        severity="medium",
        cwe=None,
        description="",
        patterns=["DUP_TOKEN"],
    )
    layer = PatternLayer(categories=[cat])
    sample = tmp_path / "x.py"
    sample.write_text("a = 'DUP_TOKEN' + 'DUP_TOKEN'\n", encoding="utf-8")
    context = NodeContext.from_directory(tmp_path)
    result = layer.scan(context)
    assert len(result.findings) == 1
