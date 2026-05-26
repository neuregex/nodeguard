"""Tests for Layer 0 — hash matching."""

from __future__ import annotations

from pathlib import Path

from nodesafe.layers.base import NodeContext
from nodesafe.layers.layer_00_hash import HashLayer
from nodesafe.report import Severity


def test_benign_fixture_produces_no_findings(benign_fixture: Path) -> None:
    """A clean node should produce zero hash-match findings."""
    layer = HashLayer()
    context = NodeContext.from_directory(benign_fixture)
    result = layer.scan(context)

    assert result.layer_id == "L0"
    assert result.findings == []


def test_malicious_fixture_is_detected(malicious_fixture: Path) -> None:
    """The synthetic-malicious fixture's hash is registered in the test DB.

    Layer 0 must produce at least one CRITICAL finding pointing at the file.
    """
    layer = HashLayer()
    context = NodeContext.from_directory(malicious_fixture)
    result = layer.scan(context)

    assert result.findings, "Expected at least one hash-match finding"
    critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert critical, "Expected at least one CRITICAL severity finding"
    assert any("synthetic-test" in f.title for f in result.findings)


def test_layer_metadata() -> None:
    """Layer exposes the contract fields used by the orchestrator."""
    layer = HashLayer()
    assert layer.id == "L0"
    assert layer.name == "Hash matching"
    assert layer.cost_estimate_ms <= 100  # Layer 0 must remain cheap
