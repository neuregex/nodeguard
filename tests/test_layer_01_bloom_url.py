"""Tests for Layer 1 — URL membership check."""

from __future__ import annotations

from pathlib import Path

from nodeguard.layers.base import NodeContext
from nodeguard.layers.layer_01_bloom_url import URL_PATTERN, SetURLChecker, UrlLayer
from nodeguard.report import Severity


def test_url_pattern_matches_common_forms() -> None:
    """Sanity check the URL extraction regex."""
    text = "Visit https://example.com/path?x=1 and wss://socket.example.org/ws"
    matches = [m.group(0) for m in URL_PATTERN.finditer(text)]
    assert len(matches) == 2
    assert "https://example.com/path?x=1" in matches


def test_benign_fixture_produces_no_findings(benign_fixture: Path) -> None:
    """A clean node has no flagged URLs."""
    layer = UrlLayer()
    context = NodeContext.from_directory(benign_fixture)
    result = layer.scan(context)
    assert result.findings == []


def test_malicious_fixture_is_detected(malicious_fixture: Path) -> None:
    """The synthetic-malicious fixture references a URL in the test list.

    Layer 1 must produce at least one HIGH-severity finding.
    """
    layer = UrlLayer()
    context = NodeContext.from_directory(malicious_fixture)
    result = layer.scan(context)

    assert result.findings, "Expected at least one URL-match finding"
    assert any(f.severity == Severity.HIGH for f in result.findings)
    assert any("malicious-test-c2" in (f.snippet or "") for f in result.findings)


def test_set_url_checker_normalizes_case_and_trailing_slash() -> None:
    """The checker should treat URL variants consistently."""
    checker = SetURLChecker({"https://example.com/path"})
    assert "https://example.com/path" in checker
    assert "HTTPS://Example.COM/path/" in checker  # case-insensitive + trailing slash
    assert "https://other.example.com/" not in checker


def test_layer_metadata() -> None:
    layer = UrlLayer()
    assert layer.id == "L1"
    assert layer.cost_estimate_ms <= 100  # Layer 1 must remain cheap
