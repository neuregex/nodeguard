<!-- Thanks for contributing to nodeguard! -->

## Summary

<!-- One-paragraph description of what this PR does and why. -->

## Type of change

- [ ] New signature(s) for known malware (see `signatures/README.md`)
- [ ] Bug fix
- [ ] New feature / layer
- [ ] Documentation
- [ ] Refactoring (no behavior change)
- [ ] Test improvements
- [ ] CI/build/release

## Verification

<!-- How can a reviewer verify your change works? -->

- [ ] `ruff check .` passes
- [ ] `ruff format --check .` passes
- [ ] `pytest` passes locally
- [ ] New tests added for new behavior (if applicable)
- [ ] CHANGELOG.md updated under `[Unreleased]`

## For signature contributions

- [ ] Includes a public reference (URL) in the `references` field
- [ ] Hash computed from the actual malicious file (SHA-256, lowercase hex)
- [ ] `id` follows the convention `<PREFIX>-<YEAR>-<NUMBER>`

## Related issues

<!-- Closes #123, related to #456 -->
