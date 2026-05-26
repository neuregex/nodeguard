"""Data models for scan reports.

These models define the wire format of nodesafe reports. JSON serialization
is the canonical format; other renderers (Markdown, SARIF) transform from these.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity level for an individual finding."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VerdictLabel(str, Enum):
    """Top-level verdict for a scanned target."""

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    ERROR = "error"


class Confidence(str, Enum):
    """Confidence in the verdict."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Finding(BaseModel):
    """A single detection result from a layer."""

    id: str = Field(description="Stable identifier, e.g., 'L0-hash-001'")
    layer: str = Field(description="Layer that produced this finding, e.g., 'L0'")
    severity: Severity
    category: str = Field(description="Logical category, e.g., 'known_malware', 'exfiltration'")
    title: str
    file: str | None = None
    line: int | None = None
    snippet: str | None = None
    explanation: str
    cwe: str | None = None
    references: list[str] = Field(default_factory=list)


class Verdict(BaseModel):
    """Aggregated verdict combining all findings."""

    label: VerdictLabel
    score: float = Field(ge=0.0, le=1.0, description="Score 0.0-1.0; higher = more malicious")
    confidence: Confidence


class ScanMetadata(BaseModel):
    """Metadata about the scan run itself."""

    target: str
    started_at: datetime
    duration_ms: int
    layers_run: list[str]


class ScannerInfo(BaseModel):
    """Identification of the scanner that produced the report."""

    name: str = "nodesafe"
    version: str


class Report(BaseModel):
    """Top-level scan report. Serializes to the canonical JSON format."""

    schema_version: Literal["1.0"] = "1.0"
    scanner: ScannerInfo
    scan: ScanMetadata
    verdict: Verdict
    findings: list[Finding] = Field(default_factory=list)
    recommendation: Literal["install", "review", "do_not_install"]

    def to_json(self, *, indent: int = 2) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.model_dump(mode="json"), indent=indent, default=str)

    def to_markdown(self) -> str:
        """Render as human-readable Markdown."""
        emoji = {
            VerdictLabel.CLEAN: "🟢",
            VerdictLabel.SUSPICIOUS: "🟡",
            VerdictLabel.MALICIOUS: "🔴",
            VerdictLabel.ERROR: "⚠️",
        }[self.verdict.label]

        lines = [
            f"# nodesafe scan report — {self.scan.target}",
            "",
            f"**Verdict:** {emoji} `{self.verdict.label.value}` "
            f"(score `{self.verdict.score:.2f}`, confidence `{self.verdict.confidence.value}`)",
            f"**Recommendation:** `{self.recommendation}`",
            f"**Scanner:** {self.scanner.name} v{self.scanner.version}",
            f"**Duration:** {self.scan.duration_ms}ms",
            f"**Layers run:** {', '.join(self.scan.layers_run)}",
            "",
        ]

        if not self.findings:
            lines.extend(["## Findings", "", "No findings. The target appears clean.", ""])
        else:
            lines.extend(["## Findings", ""])
            for f in self.findings:
                lines.extend(
                    [
                        f"### [{f.severity.value.upper()}] {f.title}",
                        "",
                        f"- **ID:** `{f.id}`",
                        f"- **Layer:** {f.layer}",
                        f"- **Category:** {f.category}",
                    ]
                )
                if f.file:
                    loc = f"{f.file}" + (f":{f.line}" if f.line else "")
                    lines.append(f"- **Location:** `{loc}`")
                if f.snippet:
                    lines.extend(["", "```", f.snippet, "```", ""])
                lines.extend(["", f"{f.explanation}", ""])
                if f.references:
                    lines.append("**References:**")
                    for ref in f.references:
                        lines.append(f"- {ref}")
                    lines.append("")
                if f.cwe:
                    lines.append(f"**CWE:** {f.cwe}")
                    lines.append("")

        return "\n".join(lines)


def make_report(
    target: str,
    layers_run: list[str],
    findings: list[Finding],
    started_at: datetime | None = None,
    duration_ms: int = 0,
    scanner_version: str = "0.4.0",
) -> Report:
    """Aggregate findings into a final Report with computed verdict."""
    started_at = started_at or datetime.now(timezone.utc)

    verdict = _compute_verdict(findings)
    recommendation = _recommendation_for(verdict.label)

    return Report(
        scanner=ScannerInfo(version=scanner_version),
        scan=ScanMetadata(
            target=target,
            started_at=started_at,
            duration_ms=duration_ms,
            layers_run=layers_run,
        ),
        verdict=verdict,
        findings=findings,
        recommendation=recommendation,
    )


def _compute_verdict(findings: list[Finding]) -> Verdict:
    """Conservative verdict policy: any critical finding → malicious.

    See ARCHITECTURE.md section 5.12 for the full scoring composition.
    """
    if not findings:
        return Verdict(label=VerdictLabel.CLEAN, score=0.0, confidence=Confidence.HIGH)

    critical = any(f.severity == Severity.CRITICAL for f in findings)
    high = any(f.severity == Severity.HIGH for f in findings)
    medium = any(f.severity == Severity.MEDIUM for f in findings)

    if critical:
        return Verdict(label=VerdictLabel.MALICIOUS, score=0.98, confidence=Confidence.HIGH)
    if high:
        return Verdict(label=VerdictLabel.MALICIOUS, score=0.85, confidence=Confidence.HIGH)
    if medium:
        return Verdict(label=VerdictLabel.SUSPICIOUS, score=0.55, confidence=Confidence.MEDIUM)
    return Verdict(label=VerdictLabel.SUSPICIOUS, score=0.25, confidence=Confidence.LOW)


def _recommendation_for(label: VerdictLabel) -> Literal["install", "review", "do_not_install"]:
    # A match statement keeps pyright happy: each return is a Literal string,
    # so the inferred return type matches the annotation. A dict-literal lookup
    # would widen the values to `str` and break the Literal type contract.
    match label:
        case VerdictLabel.CLEAN:
            return "install"
        case VerdictLabel.MALICIOUS:
            return "do_not_install"
        case VerdictLabel.SUSPICIOUS | VerdictLabel.ERROR:
            return "review"
