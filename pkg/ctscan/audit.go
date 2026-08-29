package ctscan

import (
	"context"
	"crypto/tls"
	"fmt"
	"slices"
	"strings"
	"sync"
)

var auditVersions = []struct {
	id   uint16
	name string
}{
	{tls.VersionTLS10, "TLS1.0"},
	{tls.VersionTLS11, "TLS1.1"},
	{tls.VersionTLS12, "TLS1.2"},
	{tls.VersionTLS13, "TLS1.3"},
}

// ScanAudit performs the normal reconnaissance handshake and then safely
// enumerates protocol versions and configurable cipher suites.
func (s *Scanner) ScanAudit(ctx context.Context, target Target, cfg AuditConfig) Result {
	if cfg.Profile == "" {
		cfg.Profile = "intermediate"
	}
	if cfg.CipherConcurrency < 1 {
		cfg.CipherConcurrency = 10
	}
	result := s.Scan(ctx, target)
	if result.Status != "success" {
		return result
	}

	audit := &AuditResult{Profile: cfg.Profile, Compliance: "pass"}
	negotiated := make(map[string]struct{})
	for _, candidate := range auditVersions {
		if err := s.waitRate(ctx); err != nil {
			break
		}
		probe, err := s.scanOnceWithTLS(ctx, target, candidate.id, candidate.id, nil)
		if err == nil && probe.Status == "success" {
			audit.SupportedVersions = append(audit.SupportedVersions, candidate.name)
			if probe.TLS != nil && probe.TLS.Cipher != "" {
				negotiated[probe.TLS.Cipher] = struct{}{}
			}
		}
	}

	type cipherProbe struct {
		id      uint16
		version uint16
	}
	var probes []cipherProbe
	for _, suite := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		for _, version := range suite.SupportedVersions {
			if version <= tls.VersionTLS12 {
				probes = append(probes, cipherProbe{id: suite.ID, version: version})
			}
		}
	}

	jobs := make(chan cipherProbe)
	accepted := make(chan string, cfg.CipherConcurrency)
	var workers sync.WaitGroup
	workers.Add(cfg.CipherConcurrency)
	for range cfg.CipherConcurrency {
		go func() {
			defer workers.Done()
			for probe := range jobs {
				if err := s.waitRate(ctx); err != nil {
					return
				}
				attempt, err := s.scanOnceWithTLS(ctx, target, probe.version, probe.version, []uint16{probe.id})
				if err == nil && attempt.Status == "success" && attempt.TLS != nil && attempt.TLS.Cipher == tls.CipherSuiteName(probe.id) {
					select {
					case accepted <- attempt.TLS.Cipher:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, probe := range probes {
			select {
			case jobs <- probe:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		workers.Wait()
		close(accepted)
	}()
	for cipher := range accepted {
		negotiated[cipher] = struct{}{}
	}
	for cipher := range negotiated {
		audit.SupportedCiphers = append(audit.SupportedCiphers, cipher)
	}
	slices.Sort(audit.SupportedVersions)
	slices.Sort(audit.SupportedCiphers)
	result.Audit = audit
	result.Findings = append(result.Findings, auditFindings(audit, cfg.Profile)...)
	audit.Compliance = complianceFor(result.Findings)
	return result
}

func auditFindings(audit *AuditResult, profile string) []Finding {
	const owaspTLS = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security"
	const tlsRef = "https://docs.tlsref.org/"
	findings := make([]Finding, 0)
	for _, version := range audit.SupportedVersions {
		switch version {
		case "TLS1.0", "TLS1.1":
			findings = append(findings, Finding{
				ID: "tls-deprecated-version", Severity: "high", Title: "Deprecated TLS version is supported",
				Evidence: version, Remediation: "Disable TLS 1.0 and TLS 1.1; require TLS 1.2 or TLS 1.3.", References: []string{owaspTLS, tlsRef},
			})
		case "TLS1.2":
			if profile == "modern" {
				findings = append(findings, Finding{
					ID: "tls-modern-profile-version", Severity: "medium", Title: "TLS 1.2 is outside the modern policy",
					Evidence: version, Remediation: "Require TLS 1.3 when compatibility requirements allow it.", References: []string{tlsRef},
				})
			}
		}
	}
	for _, cipher := range audit.SupportedCiphers {
		upper := strings.ToUpper(cipher)
		severity := ""
		reason := ""
		switch {
		case strings.Contains(upper, "NULL") || strings.Contains(upper, "ANON") || strings.Contains(upper, "EXPORT"):
			severity, reason = "critical", "unauthenticated or unencrypted cipher"
		case strings.Contains(upper, "RC4") || strings.Contains(upper, "3DES"):
			severity, reason = "high", "deprecated cipher"
		case strings.Contains(upper, "CBC") || (!strings.Contains(upper, "GCM") && !strings.Contains(upper, "CHACHA20") && !strings.HasPrefix(upper, "TLS_AES_")):
			severity, reason = "medium", "legacy non-AEAD cipher"
		}
		if severity != "" {
			findings = append(findings, Finding{
				ID: "tls-weak-cipher", Severity: severity, Title: "Weak TLS cipher is supported",
				Evidence: fmt.Sprintf("%s (%s)", cipher, reason), Remediation: "Restrict the service to TLSRef-recommended AEAD cipher suites.", References: []string{owaspTLS, tlsRef},
			})
		}
	}
	return findings
}

func complianceFor(findings []Finding) string {
	compliance := "pass"
	for _, finding := range findings {
		switch finding.Severity {
		case "critical", "high":
			return "fail"
		case "medium", "low":
			compliance = "warn"
		}
	}
	return compliance
}
