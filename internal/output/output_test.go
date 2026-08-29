package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/codejavu-llc/ctscan/pkg/ctscan"
)

func TestDNSOutputDeduplicatesAndNormalizes(t *testing.T) {
	var buffer bytes.Buffer
	writer, err := New(&buffer, Config{Format: "dns"})
	if err != nil {
		t.Fatal(err)
	}
	result := ctscan.Result{Status: "success", Certificate: &ctscan.Certificate{Subject: ctscan.DistinguishedName{CommonName: "API.Example.com"}, DNSNames: []string{"*.api.example.com", "www.example.com"}}}
	if err := writer.Write(result); err != nil {
		t.Fatal(err)
	}
	if err := writer.Write(result); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	got := strings.Fields(buffer.String())
	if len(got) != 2 || got[0] != "api.example.com" || got[1] != "www.example.com" {
		t.Fatalf("unexpected DNS output %q", buffer.String())
	}
}

func TestJSONFailureFiltering(t *testing.T) {
	var buffer bytes.Buffer
	writer, _ := New(&buffer, Config{Format: "jsonl", IncludeFailures: false})
	_ = writer.Write(ctscan.Result{Status: "failed", Error: &ctscan.ScanError{Kind: "dns"}})
	_ = writer.Flush()
	if buffer.Len() != 0 {
		t.Fatalf("unexpected output %q", buffer.String())
	}
}
