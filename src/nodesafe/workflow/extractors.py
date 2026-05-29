"""Helpers that pull interesting strings out of a parsed Workflow.

These don't make security judgements on their own; they just produce
the raw substrate that the analyzers (WL1, WL2, ...) operate over.
"""

from __future__ import annotations

import re

from nodesafe.workflow.models import Workflow

_URL_RE = re.compile(
    r"https?://[^\s\"'<>()\[\]{}]+",
    re.IGNORECASE,
)


def concatenated_widget_text(workflow: Workflow) -> str:
    """Return every string widget value concatenated with newlines.

    Useful for layers that want a single buffer to pattern-scan (Aho-Corasick).
    """
    parts: list[str] = []
    for _node_id, _node_type, _idx, value in workflow.iter_string_widgets():
        parts.append(value)
    return "\n".join(parts)


def extract_urls(workflow: Workflow) -> list[tuple[str, str, str]]:
    """Yield (node_id, node_type, url) tuples for every URL in the workflow."""
    out: list[tuple[str, str, str]] = []
    for node_id, node_type, _idx, value in workflow.iter_string_widgets():
        for match in _URL_RE.finditer(value):
            # Trim trailing punctuation that often slips into matches.
            url = match.group(0).rstrip(".,;:!?")
            out.append((node_id, node_type, url))
    return out
