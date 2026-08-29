package input

import (
	"testing"

	"github.com/codejavu-llc/ctscan/pkg/ctscan"
)

func TestParsePorts(t *testing.T) {
	ports, err := ParsePorts("443,8443,9000-9002,443")
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{443, 8443, 9000, 9001, 9002}
	if len(ports) != len(want) {
		t.Fatalf("got %v, want %v", ports, want)
	}
	for index := range want {
		if ports[index] != want[index] {
			t.Fatalf("got %v, want %v", ports, want)
		}
	}
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		host string
		port uint16
		sni  string
	}{
		{"hostname", "Example.COM", "example.com", 443, "example.com"},
		{"hostname and port", "example.com:8443", "example.com", 8443, "example.com"},
		{"URL", "https://example.com:9443/path?q=1", "example.com", 9443, "example.com"},
		{"IPv4", "192.0.2.1", "192.0.2.1", 443, ""},
		{"IPv6", "[2001:db8::1]", "2001:db8::1", 443, ""},
		{"IDN", "bücher.example", "xn--bcher-kva.example", 443, "xn--bcher-kva.example"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			targets, err := ParseTarget(test.raw, Options{Ports: []uint16{443}})
			if err != nil {
				t.Fatal(err)
			}
			if len(targets) != 1 {
				t.Fatalf("got %d targets", len(targets))
			}
			got := targets[0]
			if got.Host != test.host || got.Port != test.port || got.ServerName != test.sni {
				t.Fatalf("got %#v", got)
			}
		})
	}
}

func TestParseTargetExpandsPortsAndSNI(t *testing.T) {
	targets, err := ParseTarget("192.0.2.2", Options{Ports: []uint16{443, 8443}, ServerNames: []string{"one.example", "two.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 4 {
		t.Fatalf("got %d targets, want 4", len(targets))
	}
}

func TestParseCIDRGuard(t *testing.T) {
	targets, err := ParseTarget("192.0.2.0/30", Options{Ports: []uint16{443}})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 4 {
		t.Fatalf("got %d targets, want 4", len(targets))
	}
	if _, err := ParseTarget("10.0.0.0/15", Options{Ports: []uint16{443}}); err == nil {
		t.Fatal("expected large CIDR error")
	}
}

func TestNormalizeAndScope(t *testing.T) {
	name, err := NormalizeDNSName("*.API.Example.COM.")
	if err != nil || name != "api.example.com" {
		t.Fatalf("got %q, %v", name, err)
	}
	if !InScope("a.b.example.com", []string{"example.com"}) {
		t.Fatal("expected subdomain to be in scope")
	}
	if InScope("notexample.com", []string{"example.com"}) {
		t.Fatal("suffix without label boundary must not be in scope")
	}
}

func TestTargetKeyFieldsCompile(t *testing.T) {
	_ = ctscan.Target{Input: "x", Host: "x", Port: 443}
}

func FuzzParseTarget(f *testing.F) {
	for _, seed := range []string{"example.com", "https://example.com:443/x", "127.0.0.1", "2001:db8::1", "10.0.0.0/30", "bad host"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		_, _ = ParseTarget(value, Options{Ports: []uint16{443}})
	})
}

func BenchmarkParseTarget(b *testing.B) {
	for range b.N {
		_, _ = ParseTarget("https://api.example.com:8443/path", Options{Ports: []uint16{443}})
	}
}
