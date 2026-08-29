# Security policy

## Supported versions

The latest released minor version receives security fixes. Pre-1.0 builds receive fixes on a best-effort basis.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose users, leak credentials, bypass scope controls, or compromise build/release integrity. Use GitHub's private security-advisory reporting for this repository and include:

- affected version and platform;
- reproduction steps or a minimal proof of concept;
- security impact and realistic threat model;
- any suggested mitigation.

Reports will be acknowledged within seven days. Please allow time for a coordinated fix and release before public disclosure.

ctscan performs network connections chosen by its operator. A remote server returning malformed TLS or application-protocol data is considered untrusted input and should never crash the process or escape configured timeouts.
