"""Loader for the bundled signature databases.

Signatures live as plain-text files at the repo root under `signatures/`:
- `known_malware.jsonl` — one JSON object per line, see schema in
  `signatures/README.md`.
- `malicious_urls.txt` — one URL per line, comments (`#`) and blank lines
  allowed.
- `patterns.json` — categorized patterns for Layer 2 (Aho-Corasick).

The loader is intentionally simple and dependency-free. Resolving the
signatures directory uses an env var (`NODESAFE_SIGNATURES_DIR`) when set,
falling back to the bundled location.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class HashSignature:
    """A single hash-based signature entry."""

    id: str
    name: str
    type: str  # "exact_hash" | "fuzzy_hash" | etc.
    value: str
    category: list[str] = field(default_factory=list)
    severity: str = "high"
    first_seen: str | None = None
    references: list[str] = field(default_factory=list)
    similar_to: str | None = None


@dataclass
class PatternCategory:
    """A category of Layer 2 patterns: a logical grouping with shared severity/CWE."""

    name: str
    severity: str  # "info" | "low" | "medium" | "high" | "critical"
    cwe: str | None
    description: str
    patterns: list[str] = field(default_factory=list)


def _signatures_dir() -> Path:
    """Resolve where signature files live.

    Order of precedence:
    1. NODESAFE_SIGNATURES_DIR env var (used by tests, allows overrides).
    2. Wheel-bundled location (`nodesafe/_bundled_signatures/`) — populated by
       hatch's force-include when building the wheel.
    3. Repo-root `signatures/` directory — used during development install.
    """
    if env := os.environ.get("NODESAFE_SIGNATURES_DIR"):
        return Path(env)

    # 2) Wheel-bundled location: sibling to the `data/` directory inside the
    # installed package.
    bundled = Path(__file__).resolve().parent.parent / "_bundled_signatures"
    if bundled.is_dir():
        return bundled

    # 3) Repo-root walk-up for development installs.
    here = Path(__file__).resolve()
    for parent in [here.parent, *here.parents]:
        candidate = parent / "signatures"
        if candidate.is_dir():
            return candidate

    return Path.cwd() / "signatures"


def load_hash_signatures(path: Path | None = None) -> list[HashSignature]:
    """Load hash signatures from a JSONL file.

    Args:
        path: Optional explicit path. Defaults to bundled `known_malware.jsonl`.

    Returns:
        List of HashSignature, only those with `type` starting with "hash".
    """
    if path is None:
        path = _signatures_dir() / "known_malware.jsonl"

    signatures: list[HashSignature] = []
    if not path.exists():
        return signatures

    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            if data.get("type") in {"exact_hash", "fuzzy_hash"}:
                signatures.append(
                    HashSignature(
                        id=data["id"],
                        name=data.get("name", ""),
                        type=data["type"],
                        value=data["value"],
                        category=data.get("category", []),
                        severity=data.get("severity", "high"),
                        first_seen=data.get("first_seen"),
                        references=data.get("references", []),
                        similar_to=data.get("similar_to"),
                    )
                )

    return signatures


def load_malicious_urls(path: Path | None = None) -> set[str]:
    """Load malicious URLs from a plain text file.

    Format: one URL per line. Lines starting with `#` or empty are ignored.
    """
    if path is None:
        path = _signatures_dir() / "malicious_urls.txt"

    urls: set[str] = set()
    if not path.exists():
        return urls

    with path.open(encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            urls.add(stripped)

    return urls


def load_top_pypi_packages(path: Path | None = None) -> list[str]:
    """Load the curated list of top PyPI package names (typosquatting baseline).

    The file format is plain text, one PEP 503 normalized name per line.
    Lines starting with `#` and blank lines are ignored.

    Args:
        path: Optional explicit path. Defaults to bundled
            `top_pypi_packages.txt`.

    Returns:
        Sorted, deduplicated list of normalized package names.
    """
    if path is None:
        path = _signatures_dir() / "top_pypi_packages.txt"

    names: set[str] = set()
    if not path.exists():
        return []

    with path.open(encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            # PEP 503 normalization: lowercase, runs of [-_.] collapse to a
            # single hyphen.
            normalized = stripped.lower().replace("_", "-").replace(".", "-")
            while "--" in normalized:
                normalized = normalized.replace("--", "-")
            names.add(normalized)

    return sorted(names)


def load_pattern_categories(path: Path | None = None) -> list[PatternCategory]:
    """Load Layer 2 patterns grouped by category.

    The patterns file is a JSON document with a `categories` mapping. Each
    category has a `severity`, optional `cwe`, `description`, and a list of
    `patterns` (literal substrings to search for via Aho-Corasick).

    Args:
        path: Optional explicit path. Defaults to bundled `patterns.json`.

    Returns:
        List of PatternCategory. Empty list if the file is missing.
    """
    if path is None:
        path = _signatures_dir() / "patterns.json"

    if not path.exists():
        return []

    with path.open(encoding="utf-8") as f:
        data = json.load(f)

    categories: list[PatternCategory] = []
    for name, entry in data.get("categories", {}).items():
        categories.append(
            PatternCategory(
                name=name,
                severity=entry.get("severity", "medium"),
                cwe=entry.get("cwe"),
                description=entry.get("description", ""),
                patterns=list(entry.get("patterns", [])),
            )
        )

    return categories
