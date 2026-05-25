# Threat Model

## Scope

`nodeguard` is a **static analysis** scanner for plugin/node packages distributed
through ecosystems like ComfyUI (custom_nodes), LangFlow, Flowise, Node-RED, and
similar node-based workflow tools. This document defines what nodeguard defends
against and what it explicitly does not.

## STRIDE analysis

| Category | Vector | Mitigation in nodeguard |
|----------|--------|-------------------------|
| **S**poofing | Attacker publishes node with name similar to popular one | Layer 4 (typosquatting check) |
| **T**ampering | Attacker modifies a legitimate node post-fame | Layer 0 (hash matching against known-good and known-bad), Layer 7 (semantic similarity vs known-clean version) |
| **R**epudiation | Author denies authoring malicious code | Out of scope (legal/social) |
| **I**nformation Disclosure | Node exfiltrates credentials, wallets, cookies | Layer 2 (sensitive paths), Layer 3 (network calls in inappropriate context), Layer 8 (intent analysis) |
| **D**enial of Service | Node consumes resources or persists mining | Layer 2 (process names), Layer 6 (anomaly in resource patterns) — limited by static-only analysis |
| **E**levation of Privilege | Node executes with user's full permissions | Out of scope (mitigated by OS sandbox, not by scanner) |

## What nodeguard defends against

1. **Known malware re-distribution**. Hash match on previously-catalogued samples.
2. **Code execution patterns** that are inappropriate for the declared purpose
   of a plugin (e.g., `exec(base64.b64decode(...))` in a "math node").
3. **Exfiltration channels**: known C2 URLs, Discord webhooks, paste sites,
   typical exfiltration sinks.
4. **Credential theft patterns**: reads from browser data paths, wallet files,
   keystore directories, SSH key locations.
5. **Persistence mechanisms**: cron entries, systemd units, registry writes,
   startup scripts.
6. **Typosquatting on dependencies**: requirements.txt entries close in
   edit-distance to popular legitimate packages.
7. **Variants of known malware** through semantic similarity (CodeBERT
   embeddings + FAISS, Layer 7) — even if exact hashes differ.
8. **Zero-day patterns** through anomaly detection (Isolation Forest +
   Autoencoder, Layer 6) — flags code that doesn't resemble the corpus of
   benign nodes.

## What nodeguard does NOT defend against

1. **Supply-chain compromise upstream of the plugin**. If a legitimate
   third-party package that the plugin depends on is itself compromised,
   nodeguard detects the malware *when it reaches the plugin's code*, not at
   the original compromise.
2. **Runtime behavior**. nodeguard is static-only. It never executes scanned
   code. Behavior that only manifests at runtime (timing-based, condition-
   gated, network-triggered) is invisible to static analysis.
3. **Sophisticated obfuscation specifically designed to evade nodeguard**.
   Adversarial evasion is an open problem. Capa 7 (semantic similarity) and
   Capa 8 (LLM intent analysis) are the primary defenses, but they are
   probabilistic and can be defeated by determined adversaries.
4. **Malicious models or weights**. nodeguard scans code, not model files.
   For model file safety, see [`comfyui_pt_security_scanner`](https://github.com/ComfyNodePRs/PR-comfyui_pt_security_scanner-5e7d0f33)
   for pickle-based safety and use `safetensors` format whenever possible.
5. **Vulnerabilities in nodeguard itself**. Report via
   [SECURITY.md](../SECURITY.md).
6. **Active attacks on a compromised system**. If an attacker is already
   on your machine (e.g., the April 2026 botnet that scans cloud IPs),
   nodeguard's preventive value depends on integration with the Manager
   (so auto-installs are gated by scanning). nodeguard alone does not stop
   an attacker who already has remote access.

## Adversarial scenarios considered

### Scenario 1: New malware uploaded under a new name

**Coverage:** Layers 2-3 (Aho-Corasick + AST) catch most behavioral patterns
without needing prior knowledge. Layer 6 (anomaly detection) flags code that
doesn't fit the corpus of benign nodes. Layer 8 (LLM intent) provides
semantic interpretation when other layers are ambiguous.

### Scenario 2: Existing benign node compromised by attacker who gained write access to the repo

**Coverage:** Layer 0 hash match against a previously-recorded known-good
hash detects the tampering (planned for v0.3). Layer 7 (semantic similarity)
flags significant semantic drift between versions. Time-based version pinning
in install workflows reduces blast radius.

### Scenario 3: Adversarial obfuscation specifically targeting nodeguard

**Coverage:** Layer 8 (LLM with chain-of-thought reasoning) is the strongest
defense — it can reason about intent even when surface patterns are masked.
Local-first policy means defenders can run unbounded analysis without per-
scan cloud cost concerns. Layer 6 (anomaly detection) catches statistical
outliers that obfuscation often produces.

### Scenario 4: Mass automated attack (e.g., April 2026 cryptomining botnet)

**Coverage:** Manager integration (M3 roadmap) is the structurally critical
defense. Without it, nodeguard protects only disciplined users. With it,
nodeguard becomes a gate on automated install flows.

## Assumptions

1. The host OS provides reasonable user-level isolation. nodeguard's role is
   pre-install verification, not runtime sandboxing.
2. The user's environment has not already been compromised. If it has, the
   scanner's verdicts cannot be trusted (an attacker may have tampered with
   nodeguard itself).
3. The signature database is current. Stale signatures = missed detections.
   `nodeguard update` should be run regularly. Future versions will support
   GPG-signed signature bundles.
4. The user makes informed decisions about Capa 8. Cloud LLM analysis sends
   plugin source code to the chosen provider. By policy this is opt-in with
   explicit warning.

## Out-of-scope by design

- **Runtime monitoring** (use an IDS/EDR for that)
- **Network firewall** (use OS-level or network-level controls)
- **Vulnerability scanning of the user's environment beyond plugin code**
- **Cryptographic signing of plugins** (a complementary problem; see the
  `.nodeguard` manifest design in V2+ for partial coverage)

## Reporting

Threat model concerns or scenarios we haven't considered: open a discussion
tagged `threat-model` or follow the private reporting flow in
[SECURITY.md](../SECURITY.md).
