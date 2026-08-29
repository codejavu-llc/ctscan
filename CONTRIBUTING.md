# Contributing

Thank you for improving ctscan. Contributions should preserve its focus on fast, reliable, non-exploitative TLS reconnaissance.

## Development workflow

1. Use Go 1.26 or newer; allow the module's `toolchain` directive to select a patched release.
2. Create a focused branch and include tests for behavior changes.
3. Run `make check` and `make test-race` before opening a pull request.
4. Update the README, schema, and changelog when a public flag or JSON field changes.

Tests must use local fixtures. External endpoints such as badssl.com are reserved for opt-in interoperability checks and cannot be required by pull requests.

## Compatibility

- Existing flags `-l`, `-c`, `-t`, and `-o` are compatibility-sensitive.
- JSON fields may be added in schema 1.x but cannot be renamed or change meaning.
- Target failures should be returned as structured `Result.Error` values, not process-wide failures.
- stdout is for results; diagnostics belong on stderr.

## Security checks

New findings require deterministic evidence, remediation guidance, and an authoritative reference. Avoid ambiguous vulnerability claims and distinguish an unreachable check from a confirmed failure.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
