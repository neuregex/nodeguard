"""Layer 0 — SHA-256 hash matching against catalogued malware signatures.

This layer is the cheapest in the pipeline. It computes the SHA-256 of each
file in the target and looks it up in a static signature database. If a
match is found, the file is flagged with CRITICAL severity.

Limitations:
- Defeated by single-byte changes. Variants are caught by later layers
  (Layer 7 semantic similarity via CodeBERT).
- Effectiveness depends on the freshness of the signature database. The
  community PR workflow is the primary mechanism for keeping it current.
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path

from nodeguard.data.signatures import HashSignature, load_hash_signatures
from nodeguard.layers.base import Layer, LayerResult, NodeContext
from nodeguard.report import Finding, Severity


class HashLayer(Layer):
    """SHA-256 exact match against the malware signature database."""

    id = "L0"
    name = "Hash matching"
    weight = 1.0
    cost_estimate_ms = 5

    def __init__(self, signatures: list[HashSignature] | None = None) -> None:
        """Construct the layer.

        Args:
            signatures: Optional pre-loaded signatures. If None, loads from
                        the bundled signature database.
        """
        self._signatures = signatures if signatures is not None else load_hash_signatures()
        # Index by hash value for O(1) lookup
        self._by_hash: dict[str, HashSignature] = {s.value: s for s in self._signatures}

    def scan(self, context: NodeContext) -> LayerResult:
        start = time.perf_counter()
        findings: list[Finding] = []

        for idx, path in enumerate(context.files):
            digest = _sha256_of(path)
            if digest in self._by_hash:
                sig = self._by_hash[digest]
                findings.append(
                    Finding(
                        id=f"L0-hash-{idx:03d}",
                        layer=self.id,
                        severity=Severity.CRITICAL,
                        category="known_malware",
                        title=f"Exact hash match: {sig.id} ({sig.name})",
                        file=str(path.relative_to(context.root)),
                        line=None,
                        snippet=None,
                        explanation=(
                            f"File SHA-256 matches catalogued malware signature {sig.id}. "
                            f"This file is bit-for-bit identical to a known malicious sample. "
                            f"Categories: {', '.join(sig.category)}."
                        ),
                        references=sig.references,
                    )
                )

        duration_ms = int((time.perf_counter() - start) * 1000)
        return LayerResult(layer_id=self.id, findings=findings, duration_ms=duration_ms)


def _sha256_of(path: Path) -> str:
    """Compute the SHA-256 of a file in streaming fashion."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()
