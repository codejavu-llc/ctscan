// Package ctscan provides concurrent TLS certificate reconnaissance.
package ctscan

import (
	"context"
	"crypto/x509"
	"net"
	"time"
)

const SchemaVersion = "1.0"

// Config controls network behavior for a Scanner.
type Config struct {
	Concurrency int
	Timeout     time.Duration
	Retries     int
	RateLimit   int
	ProxyURL    string
	MinVersion  uint16
	MaxVersion  uint16
	RootCAs     *x509.CertPool
}

// DefaultConfig returns conservative defaults suitable for reconnaissance.
func DefaultConfig() Config {
	return Config{
		Concurrency: 300,
		Timeout:     5 * time.Second,
		Retries:     1,
	}
}

// Target describes one network endpoint and its TLS identity.
type Target struct {
	Input      string `json:"input"`
	Host       string `json:"host"`
	Address    string `json:"address,omitempty"`
	Port       uint16 `json:"port"`
	ServerName string `json:"sni,omitempty"`
	StartTLS   string `json:"starttls,omitempty"`
}

// Result is the stable, schema-versioned representation of a scan attempt.
type Result struct {
	SchemaVersion string            `json:"schema_version"`
	Timestamp     time.Time         `json:"timestamp"`
	Input         string            `json:"input"`
	Host          string            `json:"host"`
	IP            string            `json:"ip,omitempty"`
	Port          uint16            `json:"port"`
	SNI           string            `json:"sni,omitempty"`
	StartTLS      string            `json:"starttls,omitempty"`
	Status        string            `json:"status"`
	DurationMS    int64             `json:"duration_ms"`
	TLS           *TLSInfo          `json:"tls,omitempty"`
	Certificate   *Certificate      `json:"certificate,omitempty"`
	Chain         []Certificate     `json:"chain,omitempty"`
	Validation    *Validation       `json:"validation,omitempty"`
	Audit         *AuditResult      `json:"audit,omitempty"`
	Findings      []Finding         `json:"findings,omitempty"`
	Error         *ScanError        `json:"error,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// TLSInfo contains properties negotiated in the successful handshake.
type TLSInfo struct {
	Version            string `json:"version"`
	Cipher             string `json:"cipher"`
	KeyExchange        string `json:"key_exchange,omitempty"`
	ALPN               string `json:"alpn,omitempty"`
	DidResume          bool   `json:"did_resume"`
	HandshakeComplete  bool   `json:"handshake_complete"`
	OCSPStapled        bool   `json:"ocsp_stapled"`
	ClientCertRequired bool   `json:"client_cert_required,omitempty"`
}

// DistinguishedName is a JSON-friendly certificate subject or issuer.
type DistinguishedName struct {
	CommonName         string   `json:"common_name,omitempty"`
	Organization       []string `json:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizational_unit,omitempty"`
	Country            []string `json:"country,omitempty"`
	Province           []string `json:"province,omitempty"`
	Locality           []string `json:"locality,omitempty"`
	String             string   `json:"string"`
}

// Certificate contains normalized X.509 data useful for reconnaissance.
type Certificate struct {
	Subject            DistinguishedName `json:"subject"`
	Issuer             DistinguishedName `json:"issuer"`
	DNSNames           []string          `json:"dns_names,omitempty"`
	IPAddresses        []string          `json:"ip_addresses,omitempty"`
	EmailAddresses     []string          `json:"email_addresses,omitempty"`
	URIs               []string          `json:"uris,omitempty"`
	SerialNumber       string            `json:"serial_number"`
	NotBefore          time.Time         `json:"not_before"`
	NotAfter           time.Time         `json:"not_after"`
	DaysRemaining      int               `json:"days_remaining"`
	FingerprintSHA256  string            `json:"fingerprint_sha256"`
	PublicKeyAlgorithm string            `json:"public_key_algorithm"`
	PublicKeyBits      int               `json:"public_key_bits,omitempty"`
	SignatureAlgorithm string            `json:"signature_algorithm"`
	IsCA               bool              `json:"is_ca"`
	HasSCT             bool              `json:"has_sct"`
}

// Validation records independent trust and identity checks. Scanning still
// succeeds when these checks fail so that callers retain the certificate.
type Validation struct {
	Trusted       bool   `json:"trusted"`
	HostnameMatch bool   `json:"hostname_match"`
	Expired       bool   `json:"expired"`
	NotYetValid   bool   `json:"not_yet_valid"`
	SelfSigned    bool   `json:"self_signed"`
	ChainComplete bool   `json:"chain_complete"`
	TrustError    string `json:"trust_error,omitempty"`
	HostnameError string `json:"hostname_error,omitempty"`
}

// Finding is an evidence-backed TLS configuration observation.
type Finding struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	Title       string   `json:"title"`
	Evidence    string   `json:"evidence"`
	Remediation string   `json:"remediation,omitempty"`
	References  []string `json:"references,omitempty"`
}

// AuditResult contains observations requiring additional handshakes.
type AuditResult struct {
	Profile           string   `json:"profile"`
	Compliance        string   `json:"compliance"`
	SupportedVersions []string `json:"supported_versions,omitempty"`
	SupportedCiphers  []string `json:"supported_ciphers,omitempty"`
}

// ScanError classifies a target-level failure without losing the cause.
type ScanError struct {
	Kind      string `json:"kind"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

// Scanner performs reusable, concurrency-safe TLS scans.
type Scanner struct {
	config Config
	dial   func(context.Context, string, string) (net.Conn, error)
	rate   <-chan time.Time
	stop   func()
}

// AuditConfig controls expensive enumeration behavior.
type AuditConfig struct {
	Profile           string
	CipherConcurrency int
}
