# ctscan

`ctscan` is a fast, pipeline-friendly TLS certificate reconnaissance and configuration-triage tool written in Go. It turns domains, IPs, URLs, ports, and CIDRs into structured TLS intelligence and can safely pivot through certificate names that remain inside an explicit scope.

It is designed for authorized bug-bounty reconnaissance, attack-surface inventory, certificate monitoring, and defensive TLS review. It does not exploit services or attempt authentication.

## Why ctscan

- Fast single-handshake reconnaissance with bounded concurrency, rate limiting, retries, deadlines, and cancellation.
- Full leaf and chain metadata: CN, every SAN type, issuer, validity, serial, key details, signatures, SCT presence, and SHA-256 fingerprints.
- TLS metadata: negotiated version, cipher, key-exchange group, ALPN, OCSP stapling, and client-certificate requests.
- Independent trust, hostname, validity, self-signed, and chain checks without discarding invalid certificates.
- Input from arguments, stdin, files, URLs, host:port pairs, IPv4/IPv6, CIDRs, port lists, and port ranges.
- SNI lists and all-IP DNS scanning for finding virtual hosts hidden behind a shared address.
- Scope-safe recursive certificate pivoting.
- Optional TLS version/cipher audit with `intermediate` and `modern` policy results.
- STARTTLS for SMTP, IMAP, POP3, FTP, LDAP, PostgreSQL, and MySQL.
- Certificate Transparency history through crt.sh or Cert Spotter.
- Stable JSONL, readable text, and unique-DNS output.
- Snapshot comparison for new assets, SAN changes, certificate rotation, and security regressions.
- A reusable Go package for integrations.

`ctscan` focuses on certificate-driven discovery and rapid TLS triage. Use [testssl.sh](https://github.com/testssl/testssl.sh) or [SSLyze](https://github.com/nabla-c0d3/sslyze) when you need exploit-specific checks such as Heartbleed or ROBOT.

## Installation

Download a signed archive from [GitHub Releases](https://github.com/codejavu-llc/ctscan/releases), or install from source with Go 1.26 or newer:

```bash
go install github.com/codejavu-llc/ctscan@latest
```

Build a local checkout:

```bash
git clone https://github.com/codejavu-llc/ctscan.git
cd ctscan
make build
./bin/ctscan version
```

Container images are published to `ghcr.io/codejavu-llc/ctscan`:

```bash
echo example.com | docker run --rm -i ghcr.io/codejavu-llc/ctscan:latest scan -j
```

## Quick start

The original command style remains supported:

```bash
ctscan -l targets.txt -c 100 -t 3 -o results.txt
echo example.com | ctscan
```

Scan mixed target forms and emit JSONL:

```bash
ctscan scan -j example.com example.com:8443 https://example.org 192.0.2.10
```

Extract unique certificate names for the usual reconnaissance pipeline:

```bash
cat ips.txt | ctscan scan --dns --scan-all-ips | dnsx -silent | httpx -silent
```

Probe multiple SNI identities against an address:

```bash
ctscan scan 192.0.2.10 --sni app.example.com --sni api.example.com -j
```

Discover certificate names and actively follow only names in the authorized scope:

```bash
ctscan scan 192.0.2.10 --pivot --scope example.com --pivot-depth 2 --dns
```

`--pivot` always requires `--scope`; names outside exact scope or its subdomains are never probed.

Audit TLS versions and cipher suites:

```bash
ctscan audit example.com --profile intermediate -j
```

Audit exits with status `3` when a high or critical policy finding is present, making it suitable for CI.

Discover historical names from Certificate Transparency, then test which are live:

```bash
ctscan ct example.com | ctscan scan --dns | dnsx -silent | httpx -silent
```

crt.sh is the default no-key provider. Cert Spotter is available with:

```bash
export CTSCAN_CERTSPOTTER_TOKEN='...'
ctscan ct --provider certspotter example.com
```

CT provider queries disclose the requested domain to that provider. Public-suffix-wide queries such as `com` or `co.uk` are rejected.

Scan STARTTLS services:

```bash
ctscan scan mail.example.com:25 --starttls smtp -j
ctscan scan db.example.com:5432 --starttls postgres -j
```

Compare two JSONL snapshots:

```bash
ctscan diff yesterday.jsonl today.jsonl
ctscan diff --format jsonl --fail-on-change yesterday.jsonl today.jsonl
```

## Inputs and output

Inputs from arguments, repeatable `-u`, repeatable `-l`, and piped stdin are merged and deduplicated. Explicit target ports override `-p`. CIDRs above 65,536 addresses require `--allow-large-range`.

Output formats:

- `--format text` is readable and includes target errors.
- `-j` or `--format jsonl` emits one schema-versioned object per target.
- `--dns` emits normalized, unique CN/SAN names and omits failures.
- `--include-failures=false` or `--success-only` suppresses failed targets in text and JSONL.
- `-o FILE` preserves the legacy behavior of writing to both stdout and the file.

Results go to stdout. Statistics and diagnostics go to stderr, so pipelines remain clean. The JSON schema is published at [`docs/result.schema.json`](docs/result.schema.json).

Target failure kinds are stable: `invalid_input`, `dns`, `connect_timeout`, `connect_refused`, `proxy`, `starttls`, `tls_handshake`, `no_certificate`, and `canceled`.

## Responsible use

Only scan systems you own or have explicit permission to test. Respect program scope, concurrency rules, and rate limits. Start conservatively:

```bash
ctscan scan -l scope.txt -c 50 --rate-limit 100 --timeout 5s
```

No third-party CT query, recursive pivot, revocation lookup, or exploit probe happens during a default scan.

## Go API

```go
cfg := ctscan.DefaultConfig()
scanner, err := ctscan.NewScanner(cfg)
if err != nil {
    return err
}
defer scanner.Close()

result := scanner.Scan(ctx, ctscan.Target{
    Input:      "example.com",
    Host:       "example.com",
    Port:       443,
    ServerName: "example.com",
})
```

`ScanStream` accepts a target channel and closes its result channel when input is exhausted or the context is canceled. Target-level failures are represented inside `Result`; scanner construction errors are reserved for invalid global configuration.

## Development

```bash
make check
make test-race
make benchmark
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution and test requirements. Security issues should follow [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
