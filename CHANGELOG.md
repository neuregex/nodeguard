# Changelog

All notable changes to nodesafe will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.1] - 2026-05-26

### Fixed
- **Windows redirect crash on `--format markdown`.** Rich's legacy
  Windows renderer encodes the buffer in cp1252 when stdout is not a
  TTY, which crashes on the verdict emoji (`UnicodeEncodeError: charmap
  codec can't encode character '\U0001f534'`). The CLI now detects
  non-TTY stdout and writes the markdown as UTF-8 bytes directly to
  `sys.stdout.buffer`, bypassing Rich entirely when piping or
  redirecting. Interactive terminal rendering is unchanged.

## [0.5.0] - 2026-05-26

### Added
- **Obfuscation detection in Layer 3.** A new module
  (`src/nodesafe/layers/_obfuscation.py`) extends the AST analysis with
  seven detectors that catch deliberately disguised code, regardless of
  what the payload would have done. Each emits its own category so the
  output stays inspectable.
  - `code_obfuscation_chr_chain` (CRITICAL): `chr(N) + chr(N) + ...`
    chains that reconstruct a dangerous keyword (`eval`, `exec`, `system`,
    `subprocess`, `pickle`, etc.).
  - `code_obfuscation_split_concat` (HIGH): the same idea built from
    string pieces, e.g. `"e" + "v" + "a" + "l"`.
  - `code_obfuscation_high_entropy` (MEDIUM): long string literals
    (>= 40 chars) whose Shannon entropy is at least 4.5 bits/char, the
    typical signature of a base64 / random-binary blob.
  - `code_obfuscation_suspicious_ident` (LOW): identifier-name
    heuristics (all-underscore names, underscore-prefixed consonant
    runs, confusable-character salads like `_o0o`, `_l1l`). Common
    short abbreviations (`cmd`, `tmp`, `ctx`, `idx`, etc.) are
    explicitly allowed.
  - `code_obfuscation_mixed_script` (CRITICAL): identifiers that mix
    Unicode scripts (e.g. Cyrillic `е` U+0435 inside an otherwise-Latin
    `eval`). Classic homoglyph attack vector.
  - `code_obfuscation_decoder_chain` (HIGH): nested calls of two or
    more known decoders in a single expression
    (`zlib.decompress(base64.b64decode(...))`).
  - `code_obfuscation_minified` (MEDIUM): file-level whitespace ratio
    below 5% on files larger than 400 chars. Typical Python source sits
    at 15-30%; deliberate minification of a sizeable file is suspicious.
- **`nodesafe scan --batch`**: scan a parent directory and treat each
  first-level subdirectory as a separate node. Emits a per-subdirectory
  verdict plus an aggregate "worst verdict" line. JSON output emits an
  array of per-node summaries. Designed for scanning a `custom_nodes/`
  tree with many plugins at once.
- `tests/fixtures/malicious/synthetic_obfuscation/` exercising every
  obfuscation detector in inert constructs.
- `tests/test_obfuscation.py` — 17 tests covering the pure detector
  functions and their integration into L3.
- 3 new CLI tests for `--batch` mode.

### Changed
- Layer 3 now emits both call-site findings (as before) and
  obfuscation findings. Category prefix `code_obfuscation_*` makes them
  filterable.

## [0.4.0] - 2026-05-25

### Added
- **Layer 5 (heuristic risk scoring):** new aggregate-score layer that combines
  structural signals — direct dangerous-call counts (eval/exec/compile/__import__),
  qualified-call counts (subprocess/os.system/pickle.loads/decoder calls),
  `shell=True` usage, `exec(b64decode(...))` chains, suspicious imports,
  dynamic `getattr` patterns, long base64/hex-looking embedded strings, network
  call density, manifest anomalies (VCS- and URL-installed deps), and overall
  dangerous-call density. Produces a single calibrated score in [0.0, 1.0]
  with the top contributing reasons attached. Thresholds: >=0.85 CRITICAL,
  >=0.60 HIGH, >=0.35 MEDIUM. Below 0.35 the layer is silent.
- `src/nodesafe/layers/_features.py`: reusable feature extractor with
  `NodeFeatures` dataclass + `extract_features(context)`. Designed as the
  same input shape we would feed a learned ML classifier later — heuristic
  ↔ ML swap is local to `score_features`.
- `tests/test_layer_05_heuristic.py`: 16 tests covering metadata, benign
  pass-through, multi-fixture detection, feature counting (eval/exec/shell=True),
  syntax-error tolerance, manifest scanning, score capping, property invariants.
- `default_layers` is now `"0,1,2,3,4,5"`.

### Honest framing
- Layer 5 is a hand-calibrated heuristic, **not** a trained ML model. The
  architecture plan called for Naive Bayes + XGBoost; that's still the target
  for v0.5 once we have enough labeled custom_node samples to train responsibly.
  Shipping a learned model on five synthetic fixtures would be worse than
  honest heuristics. The feature extractor is the same shape we would feed
  a future classifier, so the swap is one-line in `score_features`.

## [0.3.1] - 2026-05-25

First PyPI release under the `nodesafe` name. Sets up the automated
release pipeline via GitHub Actions OIDC + Trusted Publishing.
No code changes from v0.3.0; cuts a new tag so the freshly added
`release.yml` workflow has something to publish.

## [0.3.0] - 2026-05-25

Rebrand from `nodeguard` to `nodesafe`. The previous name conflicted
with an unrelated PyPI project published 10 days before our first
release. Functionally identical to v0.2.0 of `nodeguard`. Public API
import path changed: `from nodeguard import Scanner` becomes
`from nodesafe import Scanner`.

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
