# Contributing to nodesafe

Thank you for your interest in contributing. nodesafe is an OSS project building public infrastructure for ML/diffusion ecosystem security. Every contribution — code, signatures, documentation, bug reports — moves the ecosystem forward.

## Quick Start for Contributors

```bash
# Clone
git clone https://github.com/neuregex/nodesafe.git
cd nodesafe

# Setup with uv (recommended) or pip
uv venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate
uv pip install -e ".[dev,full]"

# Run tests
pytest

# Lint and format
ruff check .
ruff format .

# Type check
pyright
```

## What We Especially Welcome

### 1. New Malware Signatures

If a malicious custom_node was reported publicly, add it to our signature DB so nodesafe catches it. See [`signatures/README.md`](signatures/README.md) for the format.

Workflow:
1. Fork the repo
2. Add an entry to `signatures/known_malware.jsonl`
3. Include `references` to public disclosure (Reddit thread, blog post, news article)
4. Open a PR with title `[signature] Add detection for <malware-name>`

### 2. False Positive Reports

If nodesafe flagged a legitimate node as malicious, tell us. Open an issue tagged `[false-positive]` with:
- The node (URL or path)
- Output of `nodesafe scan <path> --format json`
- Why the flagged findings are actually benign

### 3. Missed Detection Reports

If a malicious node passed through nodesafe undetected, tell us. Open an issue tagged `[missed-detection]` with the same info as above plus reasoning for why we should have caught it.

### 4. Code Contributions

**Layers in priority order (current M1-M2):**
- Improving Layer 0 (hash matching) — fuzzy hashes (ssdeep/tlsh) for variant detection
- Improving Layer 1 (Bloom URLs) — feed integrations (URLhaus, ThreatFox)
- Layer 2 (Aho-Corasick) — pattern curation, performance tuning
- Layer 3 (AST analysis) — visitor enrichments, semgrep rule integration
- Layer 4 (typosquatting) — OSV integration, Snyk DB opt-in

**Layers in M3+:**
- Layer 5-7 (ML pipeline) — see roadmap in `ARCHITECTURE.md`

### 5. Ecosystem Integrations

- **ComfyUI Manager** integration (M3 priority)
- **GitHub Action** improvements
- **pre-commit hook** improvements
- **Docker image** maintenance
- **CI/CD recipes** for common workflows

## Pull Request Process

1. **Open an issue first** for non-trivial changes to discuss approach. Saves your time and ours.
2. **Branch from `main`** with a descriptive name (`feat/layer-2-aho`, `fix/false-positive-controlnet`, `docs/threat-model`).
3. **Write tests** for new functionality. We require >85% coverage; ideally don't lower the bar.
4. **Run the full test suite** locally before pushing (`pytest`).
5. **Run linters** (`ruff check .` and `ruff format .`).
6. **Update CHANGELOG.md** under the `[Unreleased]` section.
7. **Open a PR** with a clear description of:
   - What changed
   - Why it changed
   - How to verify it works
8. **Respond to review comments** — we aim to respond within 48h.

## Code Style

- **Python 3.10+** features welcome (`match`, structural pattern matching, walrus, etc.).
- **Type hints required** on all public APIs. Strict pyright on `src/`, lenient on `tests/`.
- **Format with ruff** (`ruff format .`). Line length: 100.
- **Docstrings**: Google-style. Required on public functions and classes.
- **Imports**: handled by ruff isort. Don't manually order.
- **Naming**: `snake_case` for everything except classes (`PascalCase`) and constants (`UPPER_SNAKE`).

Example:

```python
def scan_file(
    path: pathlib.Path,
    layers: list[Layer],
    *,
    early_exit: bool = True,
) -> ScanResult:
    """Scan a single file through configured layers.

    Args:
        path: Absolute path to the file to scan.
        layers: List of Layer instances to run, in order.
        early_exit: If True, stop on the first high-confidence malicious finding.

    Returns:
        A ScanResult containing the aggregated verdict and findings.
    """
    ...
```

## Testing Guidelines

- **Unit tests** for every layer, in `tests/test_layer_<NN>_<name>.py`.
- **Fixtures** in `tests/fixtures/` — benign and synthetic-malicious. Real malware never goes into fixtures.
- **Synthetic malicious fixtures** should be:
  - Clearly marked with `# TEST FIXTURE — SYNTHETIC MALICIOUS PATTERN`
  - Non-functional (they exhibit patterns but don't actually do harm if executed)
  - Documented with what specific layer they're designed to trigger
- **Integration tests** marked with `@pytest.mark.integration` — slow tests, full pipeline.
- **Run `pytest --cov=nodesafe --cov-report=term-missing`** to check coverage.

## Documentation Contributions

Documentation lives in:
- `README.md` — overview, quick start
- `ARCHITECTURE.md` — full plan (also lives as `nodesafe-architecture-plan.md` in development)
- `docs/threat-model.md` — STRIDE threat model
- `docs/retrospective-analysis.md` — how nodesafe catches known incidents
- `signatures/README.md` — signature DB format
- Per-layer documentation in `src/nodesafe/layers/<layer>.py` docstrings

PRs for typos, clarifications, examples, translations all welcome.

## Code of Conduct

This project follows the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md). Be kind. Be patient. Disagree on technical merit, never on personhood.

## Recognition

All contributors are added to the contributors list on releases. Significant contributors get explicit mention in the README. We don't have a CLA — your PR is your contribution under Apache 2.0.

## Architectural Disagreements

If you disagree with a design decision in the plan or implementation:

1. **Read `ARCHITECTURE.md` first** to understand the reasoning behind current decisions.
2. **Open a discussion** (not an issue) tagged `architecture` with your alternative and trade-offs.
3. We genuinely consider proposals. The plan is alive, not gospel.

## What We Will NOT Accept

- **PRs that add telemetry** of any kind, even opt-in by default. Zero telemetry is policy.
- **PRs that monetize the project** (paywalls, freemium, "premium signatures"). nodesafe is OSS for community benefit.
- **PRs that introduce vendor lock-in** to any single LLM provider, cloud, or service.
- **Real malware in fixtures** — synthetic patterns only.
- **PRs without tests** for non-trivial functionality.

## Questions?

Open a [discussion](https://github.com/neuregex/nodesafe/discussions) or just ask in a draft PR. We don't bite.
