"""WL2 — Aho-Corasick over concatenated widget values.

Same automaton, same `patterns.json` categories as
`nodesafe.layers.layer_02_patterns`, applied to the widget value text
instead of source files. Catches:

- Discord webhook URLs literally in widget values
- exec / eval keywords embedded in ExecutePython widgets
- base64 decoder names mentioned in widget code
- references to wallet paths, browser credential paths, etc.

Returns one Finding per (pattern, node) pair to keep the report readable
when a workflow embeds many copies of the same string.
"""

from __future__ import annotations

from nodesafe.data.signatures import load_pattern_categories
from nodesafe.report import Finding, Severity
from nodesafe.workflow.models import Workflow

try:
    import ahocorasick

    _AHOCORASICK_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when dep missing
    _AHOCORASICK_AVAILABLE = False


_SEVERITY_MAP: dict[str, Severity] = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def pattern_findings(workflow: Workflow) -> list[Finding]:
    """Return Findings for every pattern hit inside widget values."""
    if not _AHOCORASICK_AVAILABLE:
        return []

    categories = load_pattern_categories()
    if not categories:
        return []

    # Build pattern → (category, severity, cwe) map and Aho-Corasick automaton.
    meta: dict[str, tuple[str, Severity, str | None]] = {}
    for cat in categories:
        sev = _SEVERITY_MAP.get(cat.severity, Severity.MEDIUM)
        for pat in cat.patterns:
            if pat:
                meta.setdefault(pat, (cat.name, sev, cat.cwe))

    automaton = ahocorasick.Automaton()  # pyright: ignore[reportPossiblyUnboundVariable]
    for pat in meta:
        automaton.add_word(pat, pat)
    if len(automaton) == 0:
        return []
    automaton.make_automaton()

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()  # dedup per (node_id, pattern)
    counter = 0
    for node_id, node_type, _idx, value in workflow.iter_string_widgets():
        for _, pattern in automaton.iter(value):
            key = (node_id, pattern)
            if key in seen:
                continue
            seen.add(key)
            category, severity, cwe = meta[pattern]
            counter += 1
            findings.append(
                Finding(
                    id=f"WL2-pat-{counter:04d}",
                    layer="WL2",
                    severity=severity,
                    category=category,
                    title=f"{category}: pattern `{_short(pattern)}` in widget of {node_type}",
                    file=workflow.source,
                    line=None,
                    snippet=_short(value, 200),
                    explanation=(
                        f"Node #{node_id} ({node_type}) has a widget value that "
                        f"contains the literal pattern `{pattern}`, part of the "
                        f"`{category}` category. Widget values are loaded and "
                        "often executed or sent over the network when the workflow "
                        "runs; this pattern in a widget is the same risk as the "
                        "pattern in source code."
                    ),
                    cwe=cwe,
                )
            )
    return findings


def _short(s: str, max_len: int = 60) -> str:
    return s if len(s) <= max_len else s[: max_len - 3] + "..."
