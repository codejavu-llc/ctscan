package snapshot

import (
	"testing"

	"github.com/codejavu-llc/ctscan/pkg/ctscan"
)

func TestDiffDetectsCertificateAndSecurityChanges(t *testing.T) {
	oldResult := ctscan.Result{Host: "example.com", IP: "192.0.2.1", Port: 443, SNI: "example.com", Certificate: &ctscan.Certificate{FingerprintSHA256: "old", DNSNames: []string{"example.com"}}, Audit: &ctscan.AuditResult{Compliance: "pass"}}
	newResult := oldResult
	newResult.Certificate = &ctscan.Certificate{FingerprintSHA256: "new", DNSNames: []string{"api.example.com", "example.com"}}
	newResult.Audit = &ctscan.AuditResult{Compliance: "fail"}
	changes := Diff(map[string]ctscan.Result{Identity(oldResult): oldResult}, map[string]ctscan.Result{Identity(newResult): newResult})
	kinds := make(map[string]bool)
	for _, change := range changes {
		kinds[change.Kind] = true
	}
	for _, kind := range []string{"certificate_changed", "san_added", "security_regression"} {
		if !kinds[kind] {
			t.Fatalf("missing %s in %#v", kind, changes)
		}
	}
}
