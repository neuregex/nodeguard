"""Scanner — orchestrates the layer pipeline and aggregates results."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path

from nodesafe.config import Config
from nodesafe.layers import Layer, default_layers
from nodesafe.layers.base import NodeContext
from nodesafe.report import Finding, Report, make_report


class Scanner:
    """Top-level scanner. Composes layers and runs them against a target."""

    def __init__(
        self,
        config: Config | None = None,
        layers: list[Layer] | None = None,
    ) -> None:
        self.config = config or Config()
        self.layers = layers if layers is not None else self._default_layers_from_config()

    def _default_layers_from_config(self) -> list[Layer]:
        layer_ids = [s.strip() for s in self.config.scanner.default_layers.split(",") if s.strip()]
        return default_layers(layer_ids)

    def scan(self, target: Path | str) -> Report:
        """Scan the given target path and return a Report."""
        target_path = Path(target).resolve()
        if not target_path.exists():
            raise FileNotFoundError(f"Target does not exist: {target_path}")
        if not target_path.is_dir():
            # Allow single-file targets by wrapping their parent
            target_path = target_path.parent

        started_at = datetime.now(timezone.utc)
        start = time.perf_counter()

        context = NodeContext.from_directory(target_path)
        all_findings: list[Finding] = []
        layers_run: list[str] = []

        for layer in self.layers:
            result = layer.scan(context)
            layers_run.append(layer.id)
            all_findings.extend(result.findings)

            # Early-exit policy: a CRITICAL finding from a high-confidence
            # layer is enough to call malicious. No reason to spend more
            # compute on a node we already know is bad.
            if any(f.severity.value == "critical" for f in result.findings):
                break

        duration_ms = int((time.perf_counter() - start) * 1000)

        return make_report(
            target=str(target_path),
            layers_run=layers_run,
            findings=all_findings,
            started_at=started_at,
            duration_ms=duration_ms,
        )
