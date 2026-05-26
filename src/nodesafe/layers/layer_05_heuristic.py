"""Layer 5 — Heuristic risk scoring.

Layers 0-4 produce *individual findings* tied to specific call sites, URLs,
hashes, patterns or dependencies. Layer 5 sits one level up: it looks at the
*aggregate structural shape* of the node and produces a single calibrated
score in [0, 1] together with a short list of contributing reasons.

The scorer is **hand-calibrated**, not learned. The architecture plan calls
for a Naive Bayes + XGBoost classifier here. We are deferring that until we
have enough labeled malicious / benign custom_nodes to train responsibly —
shipping a learned model trained on five synthetic fixtures would be worse
than honest heuristics. The feature extractor (`_features.py`) is the same
shape we would feed to a future classifier, so the swap from heuristic to
ML is local to `score_features` below.

Threshold policy:

- score >= 0.85 -> CRITICAL
- score >= 0.60 -> HIGH
- score >= 0.35 -> MEDIUM
- score <  0.35 -> no finding emitted

Below the MEDIUM threshold the layer is silent — we trust Layers 0-4 to
have surfaced anything actionable. Layer 5 only fires when the *combination*
of signals justifies flagging the node as a whole.
"""

from __future__ import annotations

import time

from nodesafe.layers._features import NodeFeatures, extract_features
from nodesafe.layers.base import Layer, LayerResult, NodeContext
from nodesafe.report import Finding, Severity


class HeuristicLayer(Layer):
    """Aggregate-score risk classifier (heuristic; ML model pending)."""

    id = "L5"
    name = "Heuristic risk scoring"
    weight = 0.6
    cost_estimate_ms = 30

    _MEDIUM_THRESHOLD = 0.35
    _HIGH_THRESHOLD = 0.60
    _CRITICAL_THRESHOLD = 0.85

    def scan(self, context: NodeContext) -> LayerResult:
        start = time.perf_counter()

        features = extract_features(context)
        score, reasons = score_features(features)

        findings: list[Finding] = []
        if score >= self._MEDIUM_THRESHOLD:
            findings.append(self._build_finding(score, reasons))

        duration_ms = int((time.perf_counter() - start) * 1000)
        return LayerResult(layer_id=self.id, findings=findings, duration_ms=duration_ms)

    def _build_finding(self, score: float, reasons: list[str]) -> Finding:
        if score >= self._CRITICAL_THRESHOLD:
            severity = Severity.CRITICAL
        elif score >= self._HIGH_THRESHOLD:
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM

        reason_block = (
            "\n".join(f"  - {r}" for r in reasons)
            if reasons
            else "  - (no specific signals listed)"
        )
        explanation = (
            f"Aggregate heuristic risk score for this node is {score:.2f} (out of 1.00). "
            f"Top contributing signals:\n{reason_block}\n\n"
            "Note: this score is from a hand-calibrated heuristic, not a trained ML "
            "classifier. A learned model is planned for v0.5 once enough labeled "
            "training data is collected. Treat the score as informative and review "
            "the Layer 0-4 findings (if any) for ground truth."
        )
        return Finding(
            id="L5-heuristic-0001",
            layer="L5",
            severity=severity,
            category="aggregate_risk",
            title=f"Aggregate heuristic risk score: {score:.2f}",
            file=None,
            line=None,
            snippet=None,
            explanation=explanation,
            cwe=None,
        )


# Weights for the heuristic scorer. Hand-tuned against the synthetic
# fixtures in tests/fixtures/. Each row is (predicate, contribution, label).
# A scorer iteration sums contributions and caps the result at 1.0.


def score_features(features: NodeFeatures) -> tuple[float, list[str]]:
    """Compute (score, reasons) for the given features.

    Returns:
        A pair `(score, reasons)` where `score` is in [0.0, 1.0] and
        `reasons` is an ordered list of the contributing signals (most
        significant first).
    """
    score = 0.0
    reasons: list[tuple[float, str]] = []

    # --- direct dangerous calls ------------------------------------------
    if features.exec_calls > 0:
        contribution = min(0.25, 0.10 + features.exec_calls * 0.05)
        score += contribution
        reasons.append((contribution, f"exec() called {features.exec_calls} time(s)"))
    if features.eval_calls > 0:
        contribution = min(0.20, 0.08 + features.eval_calls * 0.04)
        score += contribution
        reasons.append((contribution, f"eval() called {features.eval_calls} time(s)"))
    if features.compile_calls > 0:
        contribution = min(0.10, 0.05 + features.compile_calls * 0.02)
        score += contribution
        reasons.append((contribution, f"compile() called {features.compile_calls} time(s)"))
    if features.import_dunder_calls > 0:
        contribution = min(0.10, 0.04 + features.import_dunder_calls * 0.02)
        score += contribution
        reasons.append(
            (contribution, f"__import__() called {features.import_dunder_calls} time(s)")
        )

    # --- qualified dangerous calls ---------------------------------------
    if features.shell_calls > 0:
        contribution = min(0.20, 0.08 + features.shell_calls * 0.04)
        score += contribution
        reasons.append((contribution, f"shell/process execution calls: {features.shell_calls}"))
    if features.shell_true_count > 0:
        contribution = 0.25
        score += contribution
        reasons.append((contribution, f"subprocess with shell=True ({features.shell_true_count}x)"))
    if features.deserialization_calls > 0:
        contribution = min(0.20, 0.08 + features.deserialization_calls * 0.04)
        score += contribution
        reasons.append(
            (contribution, f"unsafe deserialization calls: {features.deserialization_calls}")
        )

    # --- combination signal: obfuscated loader pattern -------------------
    if features.exec_with_decoder_count > 0:
        contribution = 0.35
        score += contribution
        reasons.append(
            (
                contribution,
                f"exec/eval + decoder chain ({features.exec_with_decoder_count}x) — classic loader smell",
            )
        )

    # --- suspicious imports ----------------------------------------------
    if features.suspicious_import_count >= 3:
        contribution = 0.15
        score += contribution
        reasons.append(
            (contribution, f"many suspicious imports ({features.suspicious_import_count})")
        )
    elif features.suspicious_import_count >= 1:
        contribution = 0.07
        score += contribution
        reasons.append(
            (contribution, f"suspicious imports present ({features.suspicious_import_count})")
        )

    # --- dynamic dispatch ------------------------------------------------
    if features.dynamic_getattr_count >= 3:
        contribution = 0.10
        score += contribution
        reasons.append(
            (contribution, f"dynamic getattr() pattern ({features.dynamic_getattr_count}x)")
        )
    elif features.dynamic_getattr_count >= 1:
        contribution = 0.05
        score += contribution
        reasons.append(
            (contribution, f"dynamic getattr() present ({features.dynamic_getattr_count})")
        )

    # --- obfuscation signals ---------------------------------------------
    if features.long_base64_string_count > 0:
        contribution = min(0.25, features.long_base64_string_count * 0.08)
        score += contribution
        reasons.append(
            (contribution, f"long base64-looking strings ({features.long_base64_string_count})")
        )
    if features.long_hex_string_count > 0:
        contribution = min(0.20, features.long_hex_string_count * 0.06)
        score += contribution
        reasons.append(
            (contribution, f"long hex-looking strings ({features.long_hex_string_count})")
        )

    # --- network calls ---------------------------------------------------
    if features.network_calls >= 5:
        contribution = 0.10
        score += contribution
        reasons.append((contribution, f"many network calls ({features.network_calls})"))

    # --- manifest anomalies ----------------------------------------------
    if features.requirements_vcs_count > 0:
        contribution = 0.10
        score += contribution
        reasons.append(
            (contribution, f"VCS-installed dependencies ({features.requirements_vcs_count})")
        )
    if features.requirements_url_count > 0:
        contribution = 0.10
        score += contribution
        reasons.append(
            (contribution, f"URL-installed dependencies ({features.requirements_url_count})")
        )

    # --- density ---------------------------------------------------------
    if features.dangerous_call_density > 5.0:
        contribution = 0.15
        score += contribution
        reasons.append(
            (
                contribution,
                f"high dangerous-call density ({features.dangerous_call_density:.1f} per 100 LOC)",
            )
        )

    # Cap at 1.0.
    score = min(1.0, score)

    # Order reasons by contribution descending; keep the top 6.
    reasons.sort(key=lambda r: r[0], reverse=True)
    return score, [text for _, text in reasons[:6]]
