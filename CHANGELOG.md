# Changelog

All notable changes will be documented here. The project follows Semantic Versioning.

## Unreleased

No unreleased changes.

## 1.0.0 - 2026-08-29

### Added

- Schema-versioned text, JSONL, and unique-DNS output.
- Reusable `pkg/ctscan` scanning API with bounded concurrency and cancellation.
- Full certificate-chain, validation, TLS, fingerprint, and finding metadata.
- URL, port, IPv4/IPv6, CIDR, stdin, file, and argument input handling.
- SNI lists, custom DNS, all-IP scanning, HTTP/SOCKS5 proxies, and STARTTLS.
- Scope-safe certificate pivoting and CT history providers.
- TLS version/cipher audit profiles and snapshot diffing.
- Tests, race checks, CI, container builds, SBOMs, and signed release configuration.

### Changed

- The original root command now aliases the richer `scan` command.
- Timeouts accept either legacy bare seconds or duration strings such as `750ms`.

### Fixed

- Invalid concurrency no longer hangs or panics.
- Input scanner, file, output, and network errors are no longer discarded.
- Scans can be canceled cleanly without orphaning worker or progress goroutines.
