"""WL1 — URL membership check on every URL found in widget values.

Reuses the same malicious URL list as `nodesafe.layers.layer_01_bloom_url`.
Each URL in a widget value is checked exactly the way Layer 1 checks URLs
found in source code: against the bundled `malicious_urls.txt`.
"""

from __future__ import annotations

from nodesafe.data.signatures import load_malicious_urls
from nodesafe.report import Finding, Severity
from nodesafe.workflow.extractors import extract_urls
from nodesafe.workflow.models import Workflow


def url_findings(workflow: Workflow) -> list[Finding]:
    """Return Findings for any widget-value URL in the malicious URL list."""
    urls = load_malicious_urls()
    if not urls:
        return []

    findings: list[Finding] = []
    seen: set[str] = set()
    counter = 0
    for node_id, node_type, url in extract_urls(workflow):
        if url not in urls:
            continue
        key = f"{node_id}|{url}"
        if key in seen:
            continue
        seen.add(key)
        counter += 1
        findings.append(
            Finding(
                id=f"WL1-url-{counter:04d}",
                layer="WL1",
                severity=Severity.CRITICAL,
                category="malicious_url_in_widget",
                title=f"Malicious URL embedded in widget: {_short(url)}",
                file=workflow.source,
                line=None,
                snippet=url,
                explanation=(
                    f"Node #{node_id} ({node_type}) has a widget value pointing to "
                    f"a URL that appears in the known malicious URL list. "
                    "Loading this workflow can trigger requests to it (HTTP nodes, "
                    "model downloaders, custom_node webhooks). Treat as malicious."
                ),
                cwe="CWE-829",
            )
        )
    return findings


def _short(url: str, max_len: int = 80) -> str:
    return url if len(url) <= max_len else url[: max_len - 3] + "..."
