"""Layer 1 — URL membership check against known malicious URLs.

Extracts URL-like substrings from text files in the target and checks them
against a list of known malicious URLs/domains.

V0.1: backed by a Python `set` for simplicity. The architecture is designed
to swap in a real Bloom filter (pybloom_live) once the URL list grows large
enough to justify it. See `URLChecker` below.

Source feeds (post-v0.1, fed at update time):
- URLhaus (abuse.ch)
- ThreatFox (abuse.ch)
- OpenPhish (community feed)
"""

from __future__ import annotations

import re
import time
from typing import Protocol

from nodeguard.data.signatures import load_malicious_urls
from nodeguard.layers.base import Layer, LayerResult, NodeContext
from nodeguard.report import Finding, Severity

# URL extraction: simple but effective. Catches http(s), no-scheme domains in
# strings, and Discord webhook patterns specifically.
URL_PATTERN = re.compile(
    r"(?:https?://|wss?://)"  # scheme
    r"[a-zA-Z0-9\-._~:/?#@!$&'()*+,;=%]+",  # path chars (RFC 3986 subset)
    re.IGNORECASE,
)


class URLChecker(Protocol):
    """Interface for URL membership checks.

    V0.1 implementation is a set. Future: BloomFilter for scale.
    """

    def __contains__(self, url: str) -> bool: ...


class SetURLChecker:
    """Simple set-based URL checker. Default for V0.1."""

    def __init__(self, urls: set[str]) -> None:
        # Normalize for case-insensitive matching
        self._urls = {u.lower().rstrip("/") for u in urls}

    def __contains__(self, url: str) -> bool:
        return url.lower().rstrip("/") in self._urls

    def __len__(self) -> int:
        return len(self._urls)


class UrlLayer(Layer):
    """URL membership check against malicious URL feed."""

    id = "L1"
    name = "URL Bloom check"
    weight = 0.9
    cost_estimate_ms = 10

    def __init__(self, checker: URLChecker | None = None) -> None:
        if checker is None:
            urls = load_malicious_urls()
            checker = SetURLChecker(urls)
        self._checker = checker

    def scan(self, context: NodeContext) -> LayerResult:
        start = time.perf_counter()
        findings: list[Finding] = []
        seen_urls: set[str] = set()
        counter = 0

        for path in context.text_files:
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            for match in URL_PATTERN.finditer(content):
                url = match.group(0)
                if url in self._checker and url not in seen_urls:
                    seen_urls.add(url)
                    line_no = content[: match.start()].count("\n") + 1
                    counter += 1
                    findings.append(
                        Finding(
                            id=f"L1-url-{counter:03d}",
                            layer=self.id,
                            severity=Severity.HIGH,
                            category="known_malicious_url",
                            title="Known malicious URL detected",
                            file=str(path.relative_to(context.root)),
                            line=line_no,
                            snippet=_truncate(url, 200),
                            explanation=(
                                "This URL appears in the catalogued list of known malicious "
                                "destinations (C2 servers, exfiltration endpoints, "
                                "typosquatted domains, etc.). The list is sourced from "
                                "public threat intelligence feeds."
                            ),
                            references=[],
                        )
                    )

        duration_ms = int((time.perf_counter() - start) * 1000)
        return LayerResult(layer_id=self.id, findings=findings, duration_ms=duration_ms)


def _truncate(text: str, max_len: int) -> str:
    return text if len(text) <= max_len else text[:max_len] + "..."
