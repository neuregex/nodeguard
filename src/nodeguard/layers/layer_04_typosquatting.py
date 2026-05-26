"""Layer 4 — Typosquatting + OSV vulnerability check.

This layer reads the dependency declarations of the target node — currently
`requirements.txt` and `pyproject.toml` — and produces two kinds of findings:

1.  **Typosquats.** Each declared dependency is fuzzy-matched against a
    curated list of popular PyPI packages (`signatures/top_pypi_packages.txt`).
    A near-miss (Levenshtein distance 1 or 2, but not zero) raises a finding:
    the maintainer probably typed something they thought was a popular
    package and ended up at an impostor.

2.  **Known CVEs.** If the user has opted in to network calls (off by default
    for hermetic test runs and air-gapped environments), the OSV.dev API is
    queried for each `(name, version)` pair. Each returned vulnerability
    becomes a finding with severity inferred from CVSS where available.

Design notes:

- Pure stdlib parsing for both manifest formats. We deliberately avoid
  pulling in `pip-requirements-parser` or `tomlkit` — `tomli` is already
  a runtime dep and `requirements.txt` syntax is small enough to handle
  inline. Robustness to malformed manifests is more important than
  exhaustiveness; this layer should never crash a scan.
- `rapidfuzz` is the matcher. Cheap, C-accelerated Levenshtein. We fall
  back to a pure-Python implementation if `rapidfuzz` isn't installed so
  the layer remains importable.
- OSV queries are off by default to keep `nodeguard scan` hermetic.
  Enable with `vulnerability_db.primary = "osv"` *and* an explicit flag
  through `TyposquattingLayer(osv_enabled=True)` (set by the Scanner once
  we wire the config through). We never block on network — failures are
  swallowed and a single INFO finding is emitted to explain.
"""

from __future__ import annotations

import json
import re
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass
from typing import ClassVar

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from nodeguard.data.signatures import load_top_pypi_packages
from nodeguard.layers.base import Layer, LayerResult, NodeContext
from nodeguard.report import Finding, Severity

try:
    from rapidfuzz.distance import Levenshtein as _RapidLevenshtein

    _RAPIDFUZZ_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when dep missing
    _RAPIDFUZZ_AVAILABLE = False


# Regex covering the common forms of a requirement line. PEP 508 is much
# bigger than this, but for typosquatting we only need the package name,
# and `pip` accepts the simpler grammar in practice.
_REQUIREMENT_RE = re.compile(
    r"""
    ^\s*
    (?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)         # PEP 503 candidate name
    (?:\s*\[[^\]]*\])?                           # optional extras: pkg[foo]
    \s*
    (?P<op>==|>=|<=|!=|~=|<|>)?                  # optional version operator
    \s*
    (?P<version>[A-Za-z0-9._+*-]*)?              # optional version
    """,
    re.VERBOSE,
)


@dataclass(frozen=True)
class Dependency:
    """A parsed dependency declaration.

    `version` is the *pinned* version when the operator is `==`, otherwise
    None. We do not attempt to resolve specifier sets here — the OSV query
    is best-effort.
    """

    name: str  # PEP 503 normalized
    version: str | None
    source_file: str
    line: int


class TyposquattingLayer(Layer):
    """Typosquatting + vulnerability database lookup."""

    id = "L4"
    name = "Typosquatting + OSV"
    weight = 0.75
    cost_estimate_ms = 50

    # Pulled out as class vars so tests can shrink the search space.
    _typo_distance_max: ClassVar[int] = 2
    _typo_min_length: ClassVar[int] = 4  # avoid noisy hits on very short names

    def __init__(
        self,
        *,
        top_packages: Iterable[str] | None = None,
        osv_enabled: bool = False,
        osv_endpoint: str = "https://api.osv.dev/v1/query",
        osv_timeout_s: float = 5.0,
    ) -> None:
        """Build the layer.

        Args:
            top_packages: Optional override for the typosquatting baseline.
                Useful in tests.
            osv_enabled: Whether to make network calls to OSV.dev. OFF by
                default so the standard scan stays hermetic.
            osv_endpoint: OSV.dev query endpoint. Configurable for tests.
            osv_timeout_s: HTTP timeout per request.
        """
        names = list(top_packages) if top_packages is not None else load_top_pypi_packages()
        self._top_set: set[str] = {_normalize(n) for n in names if n}
        self._top_list: list[str] = sorted(self._top_set)
        self._osv_enabled = osv_enabled
        self._osv_endpoint = osv_endpoint
        self._osv_timeout_s = osv_timeout_s

    # --- public scan -----------------------------------------------------

    def scan(self, context: NodeContext) -> LayerResult:
        start = time.perf_counter()
        findings: list[Finding] = []

        deps = list(self._collect_dependencies(context))

        # 1) Typosquatting check.
        if self._top_list:
            counter_typo = 0
            for dep in deps:
                if dep.name in self._top_set:
                    continue  # exact match against known good name
                if len(dep.name) < self._typo_min_length:
                    continue
                near = self._nearest(dep.name)
                if near is None:
                    continue
                target, distance = near
                if distance == 0 or distance > self._typo_distance_max:
                    continue
                counter_typo += 1
                findings.append(self._typosquat_finding(dep, target, distance, counter_typo))

        # 2) OSV.dev lookup (opt-in).
        if self._osv_enabled and deps:
            counter_cve = 0
            try:
                vulns_by_dep = self._query_osv(deps)
            except (
                urllib.error.URLError,
                urllib.error.HTTPError,
                TimeoutError,
                json.JSONDecodeError,
                OSError,
            ) as exc:
                findings.append(self._osv_unavailable_finding(str(exc)))
                vulns_by_dep = {}
            for dep_key, vulns in vulns_by_dep.items():
                for vuln in vulns:
                    counter_cve += 1
                    findings.append(self._cve_finding(dep_key, vuln, counter_cve))

        duration_ms = int((time.perf_counter() - start) * 1000)
        return LayerResult(layer_id=self.id, findings=findings, duration_ms=duration_ms)

    # --- dependency collection -------------------------------------------

    def _collect_dependencies(self, context: NodeContext) -> Iterable[Dependency]:
        """Yield Dependencies parsed from requirements.txt and pyproject.toml."""
        for path in context.text_files:
            try:
                rel = str(path.relative_to(context.root))
            except ValueError:
                rel = str(path)

            name = path.name.lower()
            if name == "requirements.txt" or name.endswith(".requirements.txt"):
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                yield from _parse_requirements(text, source_file=rel)
            elif name == "pyproject.toml":
                try:
                    raw = path.read_bytes()
                except OSError:
                    continue
                yield from _parse_pyproject(raw, source_file=rel)

    # --- typosquatting helpers ------------------------------------------

    def _nearest(self, name: str) -> tuple[str, int] | None:
        """Return (closest_top_package, distance) for `name`.

        We cap the search early: once we see a distance-1 hit we return it,
        since distance 1 dominates and is the strongest signal for typosquat.
        """
        best: tuple[str, int] | None = None
        for candidate in self._top_list:
            # Length filter — a Levenshtein distance of D requires lengths
            # within D of each other.
            if abs(len(candidate) - len(name)) > self._typo_distance_max:
                continue
            distance = _levenshtein(name, candidate, self._typo_distance_max)
            if distance is None:
                continue
            if best is None or distance < best[1]:
                best = (candidate, distance)
                if distance == 1:
                    return best
        return best

    def _typosquat_finding(
        self,
        dep: Dependency,
        target: str,
        distance: int,
        counter: int,
    ) -> Finding:
        severity = Severity.HIGH if distance == 1 else Severity.MEDIUM
        return Finding(
            id=f"L4-typo-{counter:04d}",
            layer=self.id,
            severity=severity,
            category="typosquatting",
            title=f"Possible typosquat: `{dep.name}` ≈ `{target}`",
            file=dep.source_file,
            line=dep.line,
            snippet=dep.name,
            explanation=(
                f"`{dep.name}` is within Levenshtein distance {distance} of the "
                f"popular package `{target}`. Confirm the spelling matches the "
                f"intended dependency. Attackers publish near-miss names to "
                f"PyPI hoping a typo lands them in a real install."
            ),
            cwe="CWE-1357",
        )

    # --- OSV helpers ----------------------------------------------------

    def _query_osv(
        self,
        deps: list[Dependency],
    ) -> dict[tuple[str, str | None], list[dict]]:
        """POST each dep to OSV.dev and return vulnerabilities keyed by dep."""
        results: dict[tuple[str, str | None], list[dict]] = {}
        for dep in deps:
            payload: dict[str, object] = {"package": {"name": dep.name, "ecosystem": "PyPI"}}
            if dep.version:
                payload["version"] = dep.version
            body = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(  # noqa: S310 - endpoint pinned via config
                self._osv_endpoint,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self._osv_timeout_s) as resp:  # noqa: S310
                data = json.loads(resp.read().decode("utf-8"))
            vulns = data.get("vulns") or []
            if vulns:
                results[(dep.name, dep.version)] = vulns
        return results

    def _cve_finding(
        self,
        dep_key: tuple[str, str | None],
        vuln: dict,
        counter: int,
    ) -> Finding:
        name, version = dep_key
        vuln_id = vuln.get("id", "OSV-?")
        summary = vuln.get("summary") or vuln.get("details") or vuln_id
        severity = _osv_severity(vuln)
        version_str = f" {version}" if version else ""
        return Finding(
            id=f"L4-osv-{counter:04d}",
            layer=self.id,
            severity=severity,
            category="known_vulnerability",
            title=f"{vuln_id}: vulnerability in `{name}`{version_str}",
            file=None,
            line=None,
            snippet=name + (f"=={version}" if version else ""),
            explanation=(
                f"OSV.dev reports {vuln_id} affecting `{name}`{version_str}. "
                f"Summary: {summary[:300]}"
            ),
            references=[f"https://osv.dev/vulnerability/{vuln_id}"] if vuln_id != "OSV-?" else [],
            cwe=None,
        )

    def _osv_unavailable_finding(self, reason: str) -> Finding:
        return Finding(
            id="L4-osv-info-0001",
            layer=self.id,
            severity=Severity.INFO,
            category="scanner_status",
            title="OSV.dev lookup skipped",
            file=None,
            line=None,
            snippet=None,
            explanation=(
                "Could not reach OSV.dev to verify dependencies against the "
                f"vulnerability database. Reason: {reason[:200]}. "
                "Re-run with network access to enable CVE checking."
            ),
            cwe=None,
        )


# --- module-level utilities ----------------------------------------------


_VERSION_RE = re.compile(r"^[A-Za-z0-9._+-]+$")


def _normalize(name: str) -> str:
    """PEP 503 normalization (lowercase, _ . -> -)."""
    out = name.strip().lower().replace("_", "-").replace(".", "-")
    while "--" in out:
        out = out.replace("--", "-")
    return out


def _parse_requirements(text: str, *, source_file: str) -> Iterable[Dependency]:
    """Best-effort requirements.txt parser. Tolerant of malformed lines."""
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        # Skip pip directives like `-r foo.txt`, `--index-url ...`, `-e ...`.
        if line.startswith("-"):
            continue
        # Skip direct URLs / VCS specs — we cannot meaningfully typosquat-check them.
        if "://" in line or line.startswith(("git+", "hg+", "svn+", "bzr+")):
            continue
        # Strip environment markers (`pkg; python_version>='3.10'`).
        line = line.split(";", 1)[0].strip()
        match = _REQUIREMENT_RE.match(line)
        if not match:
            continue
        name = _normalize(match.group("name") or "")
        if not name:
            continue
        op = match.group("op")
        version_raw = match.group("version") or ""
        version: str | None = None
        if op == "==" and _VERSION_RE.match(version_raw):
            version = version_raw
        yield Dependency(name=name, version=version, source_file=source_file, line=lineno)


def _parse_pyproject(raw: bytes, *, source_file: str) -> Iterable[Dependency]:
    """Best-effort pyproject.toml dependency extractor.

    Reads `project.dependencies` and `project.optional-dependencies.*`. We
    don't try to honor PEP 621 markers exhaustively — the goal is to surface
    the *names* for typosquat comparison, not to resolve them.
    """
    try:
        data = tomllib.loads(raw.decode("utf-8", errors="ignore"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        return

    project = data.get("project", {})
    deps: list[str] = list(project.get("dependencies") or [])
    optional = project.get("optional-dependencies") or {}
    if isinstance(optional, dict):
        for extras in optional.values():
            if isinstance(extras, list):
                deps.extend(extras)

    for entry in deps:
        if not isinstance(entry, str):
            continue
        # PEP 508 entry minus markers / environment qualifiers.
        spec = entry.split(";", 1)[0].strip()
        match = _REQUIREMENT_RE.match(spec)
        if not match:
            continue
        name = _normalize(match.group("name") or "")
        if not name:
            continue
        op = match.group("op")
        version_raw = match.group("version") or ""
        version: str | None = None
        if op == "==" and _VERSION_RE.match(version_raw):
            version = version_raw
        # pyproject.toml does not have stable line numbers without a real
        # parser; using 0 keeps tests deterministic.
        yield Dependency(name=name, version=version, source_file=source_file, line=0)


def _levenshtein(a: str, b: str, max_distance: int) -> int | None:
    """Levenshtein distance, capped at `max_distance`.

    Uses `rapidfuzz` when available (10-50x faster on real inputs) and a
    pure-Python implementation otherwise. Returns None if the distance is
    known to exceed `max_distance`.
    """
    if a == b:
        return 0
    if _RAPIDFUZZ_AVAILABLE:
        distance = _RapidLevenshtein.distance(a, b, score_cutoff=max_distance)  # pyright: ignore[reportPossiblyUnboundVariable]
        # rapidfuzz returns max_distance + 1 (or sometimes a sentinel) when
        # the cutoff is exceeded. Normalize to None for clarity.
        if distance > max_distance:
            return None
        return distance
    return _pure_python_levenshtein(a, b, max_distance)


def _pure_python_levenshtein(a: str, b: str, max_distance: int) -> int | None:
    """Bounded Levenshtein. Returns None if the true distance > max_distance."""
    if abs(len(a) - len(b)) > max_distance:
        return None
    if len(a) > len(b):
        a, b = b, a
    previous = list(range(len(a) + 1))
    for j, cb in enumerate(b, start=1):
        current = [j]
        row_min = j
        for i, ca in enumerate(a, start=1):
            cost = 0 if ca == cb else 1
            current.append(
                min(
                    previous[i] + 1,  # deletion
                    current[i - 1] + 1,  # insertion
                    previous[i - 1] + cost,  # substitution
                )
            )
            row_min = min(row_min, current[i])
        if row_min > max_distance:
            return None
        previous = current
    distance = previous[-1]
    return distance if distance <= max_distance else None


_OSV_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _osv_severity(vuln: dict) -> Severity:
    """Best-effort mapping from OSV severity payload to our Severity enum.

    OSV vulns may have a top-level `severity` array (CVSS scores) or a
    `database_specific.severity` string. We try the simpler string form first.
    """
    db_sev = vuln.get("database_specific", {}) or {}
    label = db_sev.get("severity")
    if isinstance(label, str):
        mapped = _OSV_SEVERITY_MAP.get(label.upper())
        if mapped is not None:
            return mapped
    # Fall back to CVSS3 score range, if present.
    for sev in vuln.get("severity") or []:
        score = sev.get("score")
        if not score:
            continue
        # CVSS vectors don't carry numeric scores directly; just default to HIGH
        # when *any* CVSS data is present — better than silently downgrading.
        return Severity.HIGH
    return Severity.MEDIUM
