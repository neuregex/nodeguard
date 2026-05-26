"""Layer 2 — Aho-Corasick multi-pattern matching.

This layer detects suspicious patterns by running a single-pass scan over
each text file in the target. The patterns are curated literals (function
names, URLs, paths, registry keys, etc.) catalogued by category. Aho-Corasick
matches all patterns simultaneously in O(n + m + z) — one pass over the
content regardless of how many patterns are in the automaton.

This is intentionally pattern-based, not regex-based: it's faster and more
predictable for the large literal sets nodeguard uses. AST-aware checks live
in Layer 3.

Why categorize the patterns rather than treat them flat:
- Each category gets a meaningful severity (`critical` exfiltration vs
  `low` info gathering).
- Findings carry the category in their output, which makes the report
  human-readable: "exfiltration_channel: Discord webhook detected" beats
  "matched pattern #137".
- Communities contribute patterns by category — easier to review PRs.

Falls back gracefully if `pyahocorasick` is not installed (the layer is
still importable; it simply produces no findings and logs a hint).
"""

from __future__ import annotations

import time
from collections.abc import Iterable

from nodeguard.data.signatures import PatternCategory, load_pattern_categories
from nodeguard.layers.base import Layer, LayerResult, NodeContext
from nodeguard.report import Finding, Severity

try:
    import ahocorasick  # type: ignore[import-not-found]

    _AHOCORASICK_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when dep missing
    _AHOCORASICK_AVAILABLE = False


# Maximum bytes read per file. Anything bigger is sliced — protects against
# pathological inputs without losing coverage on real custom_nodes.
_MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MiB

_SEVERITY_MAP: dict[str, Severity] = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


class PatternLayer(Layer):
    """Aho-Corasick over curated suspicious patterns."""

    id = "L2"
    name = "Pattern matching (Aho-Corasick)"
    weight = 0.8
    cost_estimate_ms = 20

    def __init__(self, categories: Iterable[PatternCategory] | None = None) -> None:
        """Construct the layer.

        Args:
            categories: Optional pre-loaded category list. Defaults to the
                bundled pattern set.
        """
        cats = list(categories) if categories is not None else load_pattern_categories()
        self._categories = cats
        # Map each pattern -> (category_name, severity, cwe). One pattern can
        # appear in multiple categories in principle; we keep the first seen.
        self._pattern_meta: dict[str, tuple[str, Severity, str | None]] = {}
        for cat in cats:
            sev = _SEVERITY_MAP.get(cat.severity, Severity.MEDIUM)
            for pat in cat.patterns:
                # Skip empty patterns just in case the data file gets edited weird
                if not pat:
                    continue
                self._pattern_meta.setdefault(pat, (cat.name, sev, cat.cwe))

        self._automaton = self._build_automaton(self._pattern_meta.keys())

    @staticmethod
    def _build_automaton(patterns: Iterable[str]):
        """Build an Aho-Corasick automaton from the supplied patterns.

        Returns None if `pyahocorasick` is not installed, which makes the
        layer a no-op rather than failing imports.
        """
        if not _AHOCORASICK_AVAILABLE:
            return None
        automaton = ahocorasick.Automaton()  # pyright: ignore[reportPossiblyUnboundVariable]
        for pat in patterns:
            automaton.add_word(pat, pat)
        if len(automaton) > 0:
            automaton.make_automaton()
        return automaton

    def scan(self, context: NodeContext) -> LayerResult:
        start = time.perf_counter()
        findings: list[Finding] = []

        if self._automaton is None or len(self._automaton) == 0:
            return LayerResult(layer_id=self.id, findings=[], duration_ms=0)

        counter = 0
        for path in context.text_files:
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if len(content) > _MAX_FILE_BYTES:
                content = content[:_MAX_FILE_BYTES]

            # Track which (pattern, line) tuples we've already reported per
            # file to avoid spamming findings for repeated occurrences.
            seen_here: set[tuple[str, int]] = set()

            for end_idx, pattern in self._automaton.iter(content):
                start_idx = end_idx - len(pattern) + 1
                line_no = content.count("\n", 0, start_idx) + 1
                key = (pattern, line_no)
                if key in seen_here:
                    continue
                seen_here.add(key)

                category, severity, cwe = self._pattern_meta[pattern]
                counter += 1
                snippet = _extract_line(content, start_idx)
                findings.append(
                    Finding(
                        id=f"L2-pat-{counter:04d}",
                        layer=self.id,
                        severity=severity,
                        category=category,
                        title=f"{category}: pattern `{_short(pattern)}` matched",
                        file=str(path.relative_to(context.root)),
                        line=line_no,
                        snippet=snippet,
                        explanation=(
                            f"The literal pattern `{pattern}` was found, which belongs "
                            f"to the `{category}` category. Patterns in this category "
                            f"are commonly used in {category.replace('_', ' ')} attacks. "
                            f"Review the context — some patterns are benign in specific "
                            f"node types, but the combination of multiple findings is "
                            f"typically a strong signal."
                        ),
                        cwe=cwe,
                    )
                )

        duration_ms = int((time.perf_counter() - start) * 1000)
        return LayerResult(layer_id=self.id, findings=findings, duration_ms=duration_ms)


def _extract_line(content: str, offset: int, max_len: int = 200) -> str:
    """Extract the full line containing the byte offset, truncated to max_len."""
    line_start = content.rfind("\n", 0, offset) + 1
    line_end = content.find("\n", offset)
    if line_end == -1:
        line_end = len(content)
    line = content[line_start:line_end].strip()
    if len(line) > max_len:
        line = line[: max_len - 3] + "..."
    return line


def _short(pattern: str, max_len: int = 60) -> str:
    return pattern if len(pattern) <= max_len else pattern[: max_len - 3]
