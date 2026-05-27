"""Tests for the obfuscation detectors and their L3 integration."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from nodesafe.layers._obfuscation import (
    compute_whitespace_ratio,
    find_chr_chain_keywords,
    find_high_entropy_strings,
    find_mixed_script_identifiers,
    find_nested_decoder_chain,
    find_string_concat_keywords,
    find_suspicious_identifiers,
    has_mixed_scripts,
    is_suspicious_identifier,
    shannon_entropy,
)
from nodesafe.layers.base import NodeContext
from nodesafe.layers.layer_03_ast import AstLayer
from nodesafe.report import Severity


@pytest.fixture
def obfuscation_fixture() -> Path:
    return Path(__file__).parent / "fixtures" / "malicious" / "synthetic_obfuscation"


# --- unit tests on the pure functions --------------------------------


def test_shannon_entropy_natural_vs_encoded() -> None:
    natural = "hello world this is plain english text"
    encoded = "aB7c+xZ9pQ/L3mNoR4tFhKvWj1eXr2sUoY5/=Tn"
    assert shannon_entropy(natural) < 4.0
    assert shannon_entropy(encoded) > 4.5
    assert shannon_entropy("") == 0.0


def test_whitespace_ratio() -> None:
    spaced = "def foo():\n    return 1\n"
    minified = "def foo():return 1"
    assert compute_whitespace_ratio(spaced) > 0.2
    assert compute_whitespace_ratio(minified) < 0.12
    assert compute_whitespace_ratio("") == 1.0


def test_is_suspicious_identifier_allow_common_names() -> None:
    # Common short names with consonant clusters MUST NOT be flagged.
    for name in ["cmd", "tmp", "ctx", "idx", "src", "dst", "ptr", "pwd"]:
        assert not is_suspicious_identifier(name), name
    # Single letters and normal names also pass.
    for name in ["i", "j", "x", "foo", "_private", "__init__", "normal_var"]:
        assert not is_suspicious_identifier(name), name


def test_is_suspicious_identifier_flags_obfuscation() -> None:
    # All underscores.
    assert is_suspicious_identifier("__")
    assert is_suspicious_identifier("___")
    # Confusable salads.
    assert is_suspicious_identifier("_o0o")
    assert is_suspicious_identifier("_l1l")
    assert is_suspicious_identifier("_1lI")
    # Underscore-prefixed consonant runs.
    assert is_suspicious_identifier("_qq")
    assert is_suspicious_identifier("_zz")


def test_has_mixed_scripts_catches_cyrillic_in_latin() -> None:
    # 'е' is Cyrillic U+0435.
    assert has_mixed_scripts("еval")
    # Pure Latin is fine.
    assert not has_mixed_scripts("eval")
    # Pure Cyrillic is fine (not a homoglyph attack on Latin code).
    assert not has_mixed_scripts("привет")


# --- AST detector tests ---------------------------------------------


def test_find_chr_chain_keywords_detects_eval() -> None:
    tree = ast.parse("x = chr(101) + chr(118) + chr(97) + chr(108)")
    out = find_chr_chain_keywords(tree)
    assert any("eval" in msg for _, _, msg in out)


def test_find_chr_chain_keywords_ignores_short_chains() -> None:
    # Two chrs is not enough to be a keyword chain.
    tree = ast.parse("x = chr(101) + chr(102)")
    assert find_chr_chain_keywords(tree) == []


def test_find_string_concat_keywords_detects_system() -> None:
    tree = ast.parse('x = "s" + "y" + "s" + "t" + "e" + "m"')
    out = find_string_concat_keywords(tree)
    assert any("system" in msg for _, _, msg in out)


def test_find_high_entropy_strings_catches_base64_payload() -> None:
    payload = "aB7c+xZ9pQ/L3mNoR4tFhKvWj1eXr2sUoY5Tn9pZqXkH3vEcRfDmA7tKgWuPbNiOxZ9pQ"
    tree = ast.parse(f'x = "{payload}"')
    out = find_high_entropy_strings(tree)
    assert out, "expected at least one finding on the encoded payload"


def test_find_high_entropy_strings_ignores_short_or_low_entropy() -> None:
    # Short string.
    tree = ast.parse('x = "AB"')
    assert find_high_entropy_strings(tree) == []
    # Long but low entropy (repeated 'a').
    long_low = "a" * 200
    tree = ast.parse(f'x = "{long_low}"')
    assert find_high_entropy_strings(tree) == []


def test_find_nested_decoder_chain() -> None:
    src = "import base64, zlib\nx = zlib.decompress(base64.b64decode(b'eJxLSi0qSk0EAA=='))\n"
    tree = ast.parse(src)
    out = find_nested_decoder_chain(tree)
    assert out, "expected nested decoder chain to be flagged"


def test_find_suspicious_identifiers_skips_normal_code(tmp_path: Path) -> None:
    src = "def compute(value):\n    result = value * 2\n    return result\n"
    tree = ast.parse(src)
    assert find_suspicious_identifiers(tree) == []


def test_find_mixed_script_identifiers_detects_cyrillic() -> None:
    # Note: 'е' here is U+0435 Cyrillic small letter ie.
    tree = ast.parse("еval = 1")
    out = find_mixed_script_identifiers(tree)
    assert out, "expected mixed-script identifier to be flagged"


# --- L3 integration test -------------------------------------------


def test_l3_layer_emits_obfuscation_findings(obfuscation_fixture: Path) -> None:
    layer = AstLayer()
    ctx = NodeContext.from_directory(obfuscation_fixture)
    result = layer.scan(ctx)
    categories = {f.category for f in result.findings}
    # Expect at least one of each major obfuscation family.
    assert "code_obfuscation_chr_chain" in categories
    assert "code_obfuscation_split_concat" in categories
    assert "code_obfuscation_high_entropy" in categories
    assert "code_obfuscation_mixed_script" in categories
    assert "code_obfuscation_suspicious_ident" in categories
    assert "code_obfuscation_decoder_chain" in categories


def test_l3_obfuscation_chr_chain_is_critical(obfuscation_fixture: Path) -> None:
    layer = AstLayer()
    ctx = NodeContext.from_directory(obfuscation_fixture)
    result = layer.scan(ctx)
    crit_chr = [
        f
        for f in result.findings
        if f.category == "code_obfuscation_chr_chain" and f.severity == Severity.CRITICAL
    ]
    assert crit_chr


def test_l3_obfuscation_mixed_script_is_critical(obfuscation_fixture: Path) -> None:
    layer = AstLayer()
    ctx = NodeContext.from_directory(obfuscation_fixture)
    result = layer.scan(ctx)
    crit_mixed = [
        f
        for f in result.findings
        if f.category == "code_obfuscation_mixed_script" and f.severity == Severity.CRITICAL
    ]
    assert crit_mixed


def test_l3_minified_file_flagged(tmp_path: Path) -> None:
    """A file with extremely low whitespace ratio above the size threshold."""
    payload = "x=" + "1+" * 300 + "1\n"  # ~700 chars, almost no whitespace
    f = tmp_path / "minified.py"
    f.write_text(payload, encoding="utf-8")
    layer = AstLayer()
    ctx = NodeContext.from_directory(tmp_path)
    result = layer.scan(ctx)
    cats = {f.category for f in result.findings}
    assert "code_obfuscation_minified" in cats
