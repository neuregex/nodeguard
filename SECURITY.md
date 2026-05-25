# Security Policy

## Reporting Vulnerabilities in nodeguard Itself

If you discover a security vulnerability in nodeguard (not in nodes it scans), please report it **privately**:

- **Preferred**: open a [GitHub Security Advisory](https://github.com/neuregex/nodeguard/security/advisories/new)
- **Or email**: `security@nodeguard.dev` (PGP key: see `KEYS.txt` in repo root once published)

Do NOT open public issues for vulnerabilities. We follow [coordinated disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure):

1. We acknowledge receipt within **72 hours**.
2. Initial assessment and severity rating within **7 days**.
3. Fix prepared and tested. Embargo period negotiated with reporter (typically 30-90 days).
4. CVE issued if applicable. Reporter credited in advisory unless they prefer anonymity.
5. Public disclosure after fix release.

## Reporting Malicious Nodes (false negatives)

If you found a malicious custom_node that nodeguard **missed**:

1. **Open a public issue** with tag `[missed-detection]` and details:
   - Repo URL of the malicious node
   - What it did (or attempts to do)
   - What nodeguard reported (verdict, score, findings)
   - Why it should have been flagged
2. Or open a **PR adding the hash** to `signatures/known_malware.jsonl` with a reference to the public disclosure of the incident.

We publish a **postmortem within 14 days** for significant misses, explaining:
- Why the miss happened (which layers failed to detect)
- What we changed (new signatures, rule updates, dataset additions)
- How users can verify their existing installations weren't affected

## Reporting False Positives

If nodeguard flagged a **legitimate node** as malicious:

1. Open an issue with tag `[false-positive]`
2. Include: the node, the findings reported, and why they're benign
3. We'll triage within 7 days and adjust rules/thresholds if confirmed

False positives are taken **as seriously as misses** — a scanner that cries wolf loses trust.

## Threat Model

The full STRIDE-based threat model lives in [`docs/threat-model.md`](docs/threat-model.md). It covers:

- What `nodeguard` defends against (code execution via plugins, data exfiltration, typosquatting, known malware patterns).
- What `nodeguard` does **not** defend against (supply chain compromise upstream, runtime behavior monitoring, network-level attacks, sandbox escapes).
- Adversarial scenarios we considered.

## Supported Versions

We support the latest minor version. Security fixes are backported to the previous minor for 90 days after a new minor is released.

| Version | Supported          |
| ------- | ------------------ |
| 0.x     | :white_check_mark: (current alpha) |

Once V1.0 ships, support policy will be updated.

## Cryptographic Trust

- **Signature DB updates** are served over HTTPS only.
- Once we stabilize the format (V1+), signature releases will be **signed with a GPG key** published in the repo. `nodeguard update --verify` will check the signature before applying.
- **API keys for cloud LLM providers** are BYO — nodeguard never has its own keys and never transmits user-provided keys anywhere except to the chosen provider.

## Privacy

- **Zero telemetry by default.** This is non-negotiable.
- **No phoning home** for any reason except explicit `nodeguard update` invocation (HTTPS to public endpoint, no identifying headers).
- **Capa 8 LLM analysis is opt-in.** When enabled with cloud provider, only the code of the node being scanned is transmitted — never environment data, never telemetry.

## Contact

For questions about this policy: open a [discussion](https://github.com/neuregex/nodeguard/discussions) tagged `security-policy`.
