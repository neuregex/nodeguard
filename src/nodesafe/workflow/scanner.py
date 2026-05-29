"""WorkflowScanner — runs the workflow analyzers and emits a Report.

Mirrors the structure of `nodesafe.scanner.Scanner` for code, but its
input is a single workflow file (JSON or PNG with embedded metadata)
rather than a directory tree of Python source.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path

from nodesafe.report import Finding, Report, make_report
from nodesafe.workflow.analyzers import pattern_findings, url_findings
from nodesafe.workflow.parser import parse_workflow


class WorkflowScanner:
    """Top-level workflow scanner. Composes the WL* analyzers."""

    def scan(self, target: Path | str) -> Report:
        """Parse and scan a workflow file. Returns the aggregated Report."""
        path = Path(target).resolve()
        started_at = datetime.now(timezone.utc)
        start = time.perf_counter()

        workflow = parse_workflow(path)

        all_findings: list[Finding] = []
        layers_run: list[str] = []

        all_findings.extend(url_findings(workflow))
        layers_run.append("WL1")

        all_findings.extend(pattern_findings(workflow))
        layers_run.append("WL2")

        duration_ms = int((time.perf_counter() - start) * 1000)

        return make_report(
            target=str(path),
            layers_run=layers_run,
            findings=all_findings,
            started_at=started_at,
            duration_ms=duration_ms,
        )
