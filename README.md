# nodesafe

> Security scanner for ComfyUI custom nodes — and the emerging standard for node-based workflow plugin security.

[![PyPI](https://img.shields.io/pypi/v/nodesafe.svg)](https://pypi.org/project/nodesafe/)
[![Python](https://img.shields.io/pypi/pyversions/nodesafe.svg)](https://pypi.org/project/nodesafe/)
[![Downloads](https://img.shields.io/pypi/dm/nodesafe.svg)](https://pypi.org/project/nodesafe/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CI](https://github.com/neuregex/nodesafe/actions/workflows/ci.yml/badge.svg)](https://github.com/neuregex/nodesafe/actions/workflows/ci.yml)

`nodesafe` scans third-party plugins/nodes before you install them in node-based workflow tools, detecting malicious code with a cascading pipeline that combines static analysis, signature matching, machine learning, and optional semantic analysis with an LLM. Starting point: the ComfyUI ecosystem.

## Why this exists

In **June 2024**, ComfyUI_LLMVISION stole browser credentials and crypto wallets from hundreds of users. In **April 2026**, a botnet compromised 1,000+ ComfyUI instances by auto-installing malicious nodes via the Manager. The custom_nodes ecosystem is large, fast-moving, and largely unverified.

`nodesafe` scans before you install.

## Quick start

```bash
pip install nodesafe
nodesafe scan /path/to/custom_node
```

Or directly without installing:

```bash
uvx nodesafe scan /path/to/custom_node
```

## How it works

A 9-layer cascading pipeline. Each layer more expensive than the previous. Most clean nodes pass in <100ms; only ambiguous cases escalate.

| Layer | Technique | Cost |
|-------|-----------|------|
| 0 | Hash matching against malware database | μs |
| 1 | Bloom filter of malicious URLs | μs |
| 2 | Aho-Corasick over dangerous patterns | ms |
| 3 | AST analysis + obfuscation detectors (chr-chain, split-concat, Shannon entropy, suspicious identifiers, Unicode homoglyph, nested decoder chains, file-level minification) | ms |
| 4 | Typosquatting + OSV vulnerability check | ms |
| 5 | Aggregate heuristic risk score (hand-calibrated; ML model pending dataset) | tens of ms |
| 6 | Anomaly detection (Isolation Forest + Autoencoder) | tens of ms |
| 7 | Semantic similarity (CodeBERT embeddings + FAISS) | hundreds of ms |
| 8 | LLM review (optional, local-first via Ollama) | seconds |

**Current state (v0.5.1):** Layers 0-5 functional and shipping on PyPI. 87 tests passing across Python 3.10–3.12 × Linux/macOS/Windows. Layer 3 includes 7 obfuscation detectors that catch char-code keyword construction, split-concat, high-entropy literals, suspicious identifier shapes, Unicode homoglyph attacks, nested decoder chains, and minified files. CLI supports `--batch` for scanning a parent directory with many nodes at once. Layers 6-8 in the M3-M4 roadmap.

## Features

- ✓ **Pure static analysis** — never executes scanned code
- ✓ **Zero telemetry by default** — this policy is immutable
- ✓ **Works offline** (after the first signature update)
- ✓ **Multiple output formats**: JSON, Markdown (SARIF coming in v0.6 for GitHub Code Scanning integration)
- ✓ **GitHub Action ready** — see the example workflow
- ✓ **Pre-commit hook ready** — for CI/CD of custom_nodes repositories
- ✓ **Local-first LLM analysis** — Ollama by default, cloud opt-in with BYO key
- ✓ **OSS Apache 2.0** — no freemium, no hidden SaaS, no paid whitelisting

## Usage

### Scan a directory

```bash
nodesafe scan /path/to/custom_node
```

### JSON output

```bash
nodesafe scan /path/to/custom_node --format json
```

### Only cheap layers (fast, no aggregate score)

```bash
nodesafe scan /path/to/custom_node --layers 0,1,2,3
```

### Batch mode (scan a whole `custom_nodes/` folder at once)

```bash
nodesafe scan ComfyUI/custom_nodes --batch
```

Emits a per-node verdict plus an aggregate "worst verdict" line. Use
`--format json` to get an array of per-node summaries for tooling.

### Update signatures

```bash
nodesafe update
```

### Verify installation

```bash
nodesafe doctor
```

## Retrospective analysis

Would nodesafe have detected the historical incidents? We apply the pipeline mentally to each case:

| Incident | Detection layer | Time | Verdict |
|----------|-----------------|------|---------|
| LLMVISION (Jun 2024) | Layer 2-3 | ~30-50ms | malicious 0.98 |
| Pickai (Mar-Jun 2025) | Layer 2-3 + 5-7 | ~100ms | malicious 0.92 |
| Mining botnet (Apr 2026) | Layer 2-3 + Manager gate | <50ms | malicious 0.95 |

Full analysis in [`docs/retrospective-analysis.md`](docs/retrospective-analysis.md).

## Honest limitations

`nodesafe` is **static analysis**, not a sandbox. Its limits:

- **It does not prevent upstream supply chain attacks** (a legitimate provider being compromised). It detects the malware when it is distributed in nodes, not the original compromise.
- **It is not a replacement for the Manager** — it is complementary; ideally integrated.
- **It does not monitor runtime behavior** — that is the job of an IDS/EDR.
- **False positives happen** — the policy is conservative, but every flag shows exactly what triggered the alert so you can decide.

## Configuration

`~/.config/nodesafe/config.toml` (optional — sane defaults):

```toml
[scanner]
default_layers = "0,1,2,3,4,5,6"   # Layer 8 NOT included by default
fail_on = "suspicious"

[llm]
enabled = false                     # OFF by default. Conscious opt-in.
provider = "local"                  # local-first if enabled

[llm.local]
endpoint = "http://localhost:11434" # Ollama
model = "qwen2.5-coder:7b-instruct"

[telemetry]
enabled = false                     # ALWAYS false. Immutable policy.
```

## Roadmap

- **v0.5.x (shipped):** Layers 0-5 with obfuscation detectors + batch mode. Available now via `pip install nodesafe`.
- **v0.6 (next):** runtime-installation detector (catches nodes that pip-install or git-clone code at runtime, the April 2026 botnet vector) + SARIF output for GitHub Code Scanning.
- **v0.7 (M3):** Layer 6 anomaly detection (Isolation Forest + autoencoder over the feature extractor) once enough labeled samples have been collected to seed a baseline.
- **v0.9 (M3):** Layer 7 semantic similarity (CodeBERT embeddings + FAISS) for polymorphic variant matching.
- **v1.0:** Layer 8 LLM contextual review (local-first via Ollama, cloud opt-in) + first PR to ComfyUI-Manager so scans run before any install by default.
- **v1.5:** public threat report + consolidated community signature contributions.
- **v2+ (Year 2):** `.nodesafe` standard portable to other node-based ecosystems (LangFlow, n8n, Flowise).

Full plan in [`ARCHITECTURE.md`](ARCHITECTURE.md).

## Contributing

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

**Especially welcome:**
- Contributions of **new malware signatures** — see [`signatures/README.md`](signatures/README.md)
- **False positive reports** for legitimate nodes
- **Missed detection reports** — open an issue with the `[missed-detection]` tag
- **Semgrep rules** specific to ComfyUI / diffusion patterns

## Acknowledgments

Inspired by HuggingFace's `safetensors` push, [Snyk Labs' research](https://labs.snyk.io/resources/hacking-comfyui-through-custom-nodes/) on ComfyUI attack vectors, and the unfortunate work of [u/_roblaughter_](https://www.reddit.com/r/StableDiffusion/) who discovered LLMVISION at his own cost.

## License

Apache 2.0. See [LICENSE](LICENSE).

## Long-term vision

ComfyUI is the most urgent case, not the only one. The full category of node-based tools with executable plugins (LangFlow, Flowise, Node-RED, n8n, etc.) shares the same structural problem. In the long term, `.nodesafe` aspires to become a **portable manifest artifact** that any ecosystem can adopt — analogous to how `.safetensors` became the standard for ML model weights.

V2-V3 of the project formalizes the standard and works with maintainers of other ecosystems. Today, brutal focus on ComfyUI.
