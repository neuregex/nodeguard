"""Tests for Layer 4 — typosquatting + OSV."""

from __future__ import annotations

from pathlib import Path

import pytest

from nodesafe.layers.base import NodeContext
from nodesafe.layers.layer_04_typosquatting import (
    TyposquattingLayer,
    _levenshtein,
    _parse_pyproject,
    _parse_requirements,
)
from nodesafe.report import Severity


@pytest.fixture
def typo_fixture() -> Path:
    return Path(__file__).parent / "fixtures" / "malicious" / "synthetic_typosquatting"


@pytest.fixture
def typo_layer() -> TyposquattingLayer:
    """A Layer 4 instance with a tight, deterministic baseline.

    Using a small explicit `top_packages` list keeps the test independent of
    the bundled file and makes the expected findings easy to reason about.
    """
    return TyposquattingLayer(
        top_packages=[
            "requests",
            "numpy",
            "torch",
            "pytorch",  # included so `pythhorch` is at distance 2 from `pytorch`
            "pillow",
            "scipy",
            "matplotlib",
        ],
        osv_enabled=False,
    )


def test_layer_metadata(typo_layer: TyposquattingLayer) -> None:
    assert typo_layer.id == "L4"
    assert typo_layer.cost_estimate_ms <= 200
    assert typo_layer.name


def test_benign_fixture_produces_no_findings(
    benign_fixture: Path, typo_layer: TyposquattingLayer
) -> None:
    context = NodeContext.from_directory(benign_fixture)
    result = typo_layer.scan(context)
    assert result.findings == []


def test_synthetic_fixture_flags_typosquats(
    typo_fixture: Path, typo_layer: TyposquattingLayer
) -> None:
    context = NodeContext.from_directory(typo_fixture)
    result = typo_layer.scan(context)

    flagged = {f.snippet for f in result.findings}
    # Distance 1 — must be flagged.
    assert "requets" in flagged
    assert "numpyy" in flagged
    assert "torcch" in flagged
    # Distance 2 — must be flagged (under cap of 2).
    assert "pythhorch" in flagged


def test_distance_one_typos_are_high_severity(
    typo_fixture: Path, typo_layer: TyposquattingLayer
) -> None:
    context = NodeContext.from_directory(typo_fixture)
    result = typo_layer.scan(context)
    high = [f for f in result.findings if f.severity == Severity.HIGH]
    snippets = {f.snippet for f in high}
    # Distance-1 typos should land in HIGH.
    assert {"requets", "numpyy", "torcch"} <= snippets


def test_distance_two_typos_are_medium_severity(
    typo_fixture: Path, typo_layer: TyposquattingLayer
) -> None:
    context = NodeContext.from_directory(typo_fixture)
    result = typo_layer.scan(context)
    medium = [f for f in result.findings if f.severity == Severity.MEDIUM]
    assert any(f.snippet == "pythhorch" for f in medium)


def test_legitimate_dependencies_not_flagged(
    typo_fixture: Path, typo_layer: TyposquattingLayer
) -> None:
    context = NodeContext.from_directory(typo_fixture)
    result = typo_layer.scan(context)
    flagged = {f.snippet for f in result.findings}
    # `pillow` and `requests[security]` are exact matches to baseline names.
    assert "pillow" not in flagged
    assert "requests" not in flagged


def test_pip_directives_are_ignored(typo_layer: TyposquattingLayer, tmp_path: Path) -> None:
    """Lines like `-r foo.txt`, `--index-url`, and VCS URLs must not break parsing."""
    (tmp_path / "requirements.txt").write_text(
        "\n".join(
            [
                "-r other.txt",
                "--index-url https://example.invalid/simple",
                "-e .",
                "git+https://github.com/example/repo.git",
                "numpy>=1.24",
            ]
        ),
        encoding="utf-8",
    )
    context = NodeContext.from_directory(tmp_path)
    # Should not raise. `numpy` is in baseline — no findings.
    result = typo_layer.scan(context)
    assert result.findings == []


def test_pyproject_dependencies_are_scanned(typo_layer: TyposquattingLayer, tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0"\n'
        'dependencies = ["requets>=2.0", "pillow"]\n'
        "[project.optional-dependencies]\n"
        'extra = ["numpyy"]\n',
        encoding="utf-8",
    )
    context = NodeContext.from_directory(tmp_path)
    result = typo_layer.scan(context)
    flagged = {f.snippet for f in result.findings}
    assert "requets" in flagged
    assert "numpyy" in flagged
    assert "pillow" not in flagged


def test_malformed_requirements_does_not_crash(
    typo_layer: TyposquattingLayer, tmp_path: Path
) -> None:
    (tmp_path / "requirements.txt").write_text(
        "this is not a real requirements line\n@@@@ broken @@@@\n!!\n",
        encoding="utf-8",
    )
    context = NodeContext.from_directory(tmp_path)
    # Must not raise, must not crash. Findings may be empty.
    result = typo_layer.scan(context)
    assert isinstance(result.findings, list)


def test_short_names_not_flagged(typo_layer: TyposquattingLayer, tmp_path: Path) -> None:
    """Names below the min-length threshold (4) must not produce findings."""
    (tmp_path / "requirements.txt").write_text("ab\nxyz\n", encoding="utf-8")
    context = NodeContext.from_directory(tmp_path)
    result = typo_layer.scan(context)
    assert result.findings == []


def test_levenshtein_cap_works() -> None:
    """Internal Levenshtein helper must cap correctly."""
    assert _levenshtein("requests", "requests", 2) == 0
    assert _levenshtein("requests", "requets", 2) == 1
    assert _levenshtein("requests", "reqests", 2) == 1
    # Far apart names — must return None when over the cap.
    assert _levenshtein("matplotlib", "torch", 2) is None


def test_parse_requirements_strips_env_markers() -> None:
    deps = list(
        _parse_requirements(
            "numpy>=1.24; python_version<'3.13'\nrequets==2.31.0\n",
            source_file="requirements.txt",
        )
    )
    names = [d.name for d in deps]
    assert names == ["numpy", "requets"]
    pinned = next(d for d in deps if d.name == "requets")
    assert pinned.version == "2.31.0"


def test_parse_pyproject_reads_optional_extras() -> None:
    deps = list(
        _parse_pyproject(
            b'[project]\nname = "x"\nversion = "0"\n'
            b'dependencies = ["torch>=2.0"]\n'
            b"[project.optional-dependencies]\n"
            b'gpu = ["torcch==2.1.0"]\n',
            source_file="pyproject.toml",
        )
    )
    names = {d.name for d in deps}
    assert names == {"torch", "torcch"}


def test_osv_disabled_makes_no_network_call(
    typo_fixture: Path, typo_layer: TyposquattingLayer
) -> None:
    """The default layer must NOT touch the network."""
    # If OSV were enabled the urlopen call would error in this sandbox.
    # Confirming no `scanner_status` finding is the contract.
    context = NodeContext.from_directory(typo_fixture)
    result = typo_layer.scan(context)
    assert not any(f.category == "scanner_status" for f in result.findings)


def test_osv_enabled_emits_info_finding_on_network_failure(
    typo_fixture: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With OSV enabled but the endpoint unreachable, we emit a single INFO."""
    layer = TyposquattingLayer(
        top_packages=["requests"],
        osv_enabled=True,
        osv_endpoint="http://127.0.0.1:1/unreachable",  # closed port
        osv_timeout_s=0.25,
    )
    context = NodeContext.from_directory(typo_fixture)
    result = layer.scan(context)
    info = [f for f in result.findings if f.category == "scanner_status"]
    assert len(info) >= 1
    assert info[0].severity == Severity.INFO
