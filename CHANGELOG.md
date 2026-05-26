# Changelog

All notable changes to nodeguard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] — 2026-05-25

First public release. Closes M1: a hermetic, offline-capable scanner with
five complementary detection layers covering known-bad hashes, malicious
URLs, suspicious literal patterns, structural AST risk, and typosquatting
against the popular PyPI baseline. Optional OSV.dev CVE lookup for
declared dependencies is wired in and opt-in.

### Added
- **Layer 4 (typosquatting + OSV):** parses `requirements.txt` and `pyproject.toml`
  from the scanned node, fuzzy-matches each dependency against a curated baseline
  of popular PyPI packages (`signatures/top_pypi_packages.txt`), and flags
  near-misses. Distance-1 hits are HIGH severity; distance-2 are MEDIUM. Optional
  opt-in path queries OSV.dev for known CVEs in the declared deps and reports
  each as a `known_vulnerability` finding. Network calls are OFF by default so
  scans stay hermetic and air-gap friendly. New `default_layers` is `"0,1,2,3,4"`.
- `rapidfuzz` is now a core dependency (was an optional extra) so Layer 4 works
  out of the box; a pure-Python fallback exists for environments where the wheel
  is unavailable.
- `signatures/top_pypi_packages.txt` curated list of high-value typosquatting
  targets (general + ML/AI + ComfyUI + crypto ecosystems). Bundled into the
  wheel via `force-include`.
- `load_top_pypi_packages()` loader with PEP 503 name normalization.
- `tests/fixtures/malicious/synthetic_typosquatting/` with a deliberately
  misspelled `requirements.txt` covering distance-1, distance-2, pip directives,
  VCS URLs, and a legitimate dep for false-positive control.
- `tests/test_layer_04_typosquatting.py` covering metadata, benign pass-through,
  distance-1/2 severity escalation, exact-match guard, pip-directive tolerance,
  pyproject.toml extras, malformed manifest handling, short-name skip,
  Levenshtein cap, environment-marker stripping, OSV opt-out by default, and
  OSV network-failure path emitting a single INFO finding.

- **Layer 3 (AST analysis):** stdlib-based `ast.NodeVisitor` that finds
  structural risk: direct `eval`/`exec`/`compile`/`__import__` calls, qualified
  calls to dangerous functions (`subprocess.*`, `os.system`, `pickle.loads`,
  `marshal.loads`, base64 decoders), `shell=True` in subprocess (escalates to
  CRITICAL), the `exec(b64decode(...))` obfuscated-loader chain (escalates to
  CRITICAL), suspicious imports (`pickle`, `marshal`, `ctypes`, `winreg`), and
  dynamic `getattr` with non-literal attribute names. Unparseable files are
  skipped silently.
- `tests/fixtures/malicious/synthetic_ast_loader/` and
  `tests/test_layer_03_ast.py` (8 tests).

- **Layer 2 (Aho-Corasick patterns):** multi-pattern matching over curated
  literals, categorized by intent. ~200 initial patterns shipped in
  `signatures/patterns.json`. Backed by `pyahocorasick`.
- `PatternCategory` dataclass and `load_pattern_categories()` loader.
- `tests/fixtures/malicious/synthetic_pattern_chain/` and
  `tests/test_layer_02_patterns.py` (6 tests).

### Changed
- `rapidfuzz` and `pyahocorasick` are core dependencies.
- Default `scanner.default_layers` is `"0,1,2,3,4"`.
- Wheel build uses `force-include` to bundle `signatures/*` inside the installed
  package.
- `data.signatures._signatures_dir()` resolution: env var -> wheel-bundled
  location -> repo-root walk-up.

### Initial scaffolding (pre-Layer-2 history)
- Layer 0: SHA-256 hash matching against signature DB.
- Layer 1: URL membership check against malicious URL list (Set-backed,
  BloomFilter planned).
- CLI with `scan`, `update`, `doctor` commands.
- Output formats: JSON, Markdown.
- Pydantic models for Report, Finding, Verdict.
- Initial signature DB with synthetic test entries.
- CI workflow (ruff + pyright + pytest).
- Documentation: README, SECURITY, CONTRIBUTING, threat model.

### Roadmap (planned)
- Layer 5 (ML classifier: Naive Bayes + XGBoost) - v0.5
- SARIF output for GitHub Code Scanning - v0.5
- Layer 6 (Isolation Forest + Autoencoder) - v0.7
- Layer 7 (CodeBERT + FAISS) - v0.9
- Layer 8 (LLM, local-first Ollama) - v1.0
- ComfyUI Manager integration PR - v1.0

## [0.1.0] — never released

Internal milestone. Layer 0 + Layer 1 functional. No public tag pushed;
superseded by v0.2.0 which includes Layers 2-4.
