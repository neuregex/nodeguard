# nodeguard signature database

This directory bundles the signature databases that ship with nodeguard.

## Files

- `known_malware.jsonl` — Hash-based signatures (JSON Lines).
- `malicious_urls.txt` — Known malicious URLs/domains (plain text, one per line).

## Hash signature format

Each line in `known_malware.jsonl` is a single JSON object:

```json
{
  "id": "MAL-2024-001",
  "name": "ComfyUI_LLMVISION",
  "type": "exact_hash",
  "value": "<sha256-hex>",
  "category": ["credential_stealer", "browser_exfil"],
  "severity": "critical",
  "first_seen": "2024-06-08",
  "references": [
    "https://hackread.com/comfyui-malicious-node-steal-crypto-browser-data/"
  ],
  "similar_to": null
}
```

Required fields: `id`, `name`, `type`, `value`.

Supported `type` values:
- `exact_hash` — SHA-256 of the file as hex (lowercase). Most common.
- `fuzzy_hash` — ssdeep or TLSH fuzzy hash. Catches variants. Coming in v0.2.

`id` convention: `<PREFIX>-<YEAR>-<NUMBER>[-<variant>]`. Prefixes:
- `MAL` — known malware
- `PAT` — behavioral pattern
- `URL` — URL/domain indicator (use `malicious_urls.txt` instead unless tied to specific malware family)

## Malicious URL format

Plain text. One URL per line. Comments allowed (`#` prefix). Blank lines ignored.

```
# C2 servers from LLMVISION campaign (June 2024)
https://example-c2.invalid/webhook

# Discord exfiltration channels (community-reported)
https://discord.com/api/webhooks/000000000000000000/redacted-example
```

## Contributing new signatures

1. Find a public disclosure of a malicious node (Reddit thread, blog post, advisory).
2. Compute SHA-256 of the malicious file(s):
   ```bash
   sha256sum suspicious_file.py
   ```
3. Open a PR adding entries to the appropriate file. Include `references` to the public disclosure.
4. Title the PR `[signature] Add detection for <malware-name>`.

We commit to merging well-formed signature PRs within 7 days.

## What does NOT go here

- Real malware payloads. Only hashes/URLs/patterns.
- Speculative or unverified signatures. We require a public reference for traceability.
- PII or victim data, even hashed.

## Update mechanism (future, post-v0.1)

- Signature updates published as GitHub Releases.
- `nodeguard update` downloads the latest signed bundle.
- Signatures verified against project GPG key before applying.
