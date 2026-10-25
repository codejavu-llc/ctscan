package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/codejavu-llc/ctscan/pkg/ctscan"
)

func TestVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"version"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "ctscan") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestNoTargetsIsUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"scan"}, strings.NewReader(""), &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "no targets") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}

func TestInvalidConcurrency(t *testing.T) {
	var stdout, stderr bytes.Buffer
	// Flags intentionally follow the positional target: interspersed options are
	// part of the public CLI contract.
	code := Run(context.Background(), []string{"scan", "127.0.0.1", "-c", "0"}, strings.NewReader(""), &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "concurrency") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}

func TestPivotRequiresSafeExplicitScope(t *testing.T) {
	for _, args := range [][]string{
		{"scan", "example.com", "--pivot"},
		{"scan", "example.com", "--pivot", "--scope", "com"},
	} {
		var stdout, stderr bytes.Buffer
		code := Run(context.Background(), args, strings.NewReader(""), &stdout, &stderr)
		if code != 2 || !strings.Contains(stderr.String(), "scope") {
			t.Fatalf("args=%v code=%d stderr=%q", args, code, stderr.String())
		}
	}
}

func TestOutputFileIsQuietWithProgress(t *testing.T) {
	server := httptest.NewUnstartedServer(nil)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	// A local non-TLS endpoint provides deterministic failed scan results.
	failed := httptest.NewServer(nil)
	defer failed.Close()

	for _, tc := range []struct {
		name    string
		command string
		flags   []string
		format  string
		silent  bool
	}{
		{name: "default", format: "text"},
		{name: "json", command: "scan", flags: []string{"-j"}, format: "jsonl"},
		{name: "ordered", command: "scan", flags: []string{"-j", "--ordered"}, format: "jsonl"},
		{name: "audit", command: "audit", flags: []string{"-j"}, format: "jsonl"},
		{name: "ordered audit", command: "audit", flags: []string{"-j", "--ordered"}, format: "jsonl"},
		{name: "dns", flags: []string{"--dns"}, format: "dns"},
		{name: "filtered failures", flags: []string{"-j", "--success-only"}, format: "jsonl"},
		{name: "silent", flags: []string{"--silent"}, format: "text", silent: true},
		{name: "stats disabled", flags: []string{"--stats=false"}, format: "text"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "results")
			var args []string
			if tc.command != "" {
				args = append(args, tc.command)
			}
			args = append(args, "-o", path, "-c", "2", "--retries", "0", "-t", "2s", server.URL, failed.URL, server.URL)
			args = append(args, tc.flags...)
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), args, strings.NewReader(""), &stdout, &stderr)
			if code != 0 && !(tc.command == "audit" && code == 3) {
				t.Fatalf("code=%d stderr=%q", code, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("results leaked to stdout: %q", stdout.String())
			}
			if tc.silent {
				if stderr.Len() != 0 {
					t.Fatalf("silent stderr=%q", stderr.String())
				}
			} else if !strings.HasPrefix(stderr.String(), "Objects left to scan: 2\n") || !strings.HasSuffix(stderr.String(), "Objects left to scan: 0\n") || strings.Contains(stderr.String(), "Scanned ") {
				t.Fatalf("unexpected progress: %q", stderr.String())
			}
			data, err := os.ReadFile(path)
			if err != nil || len(data) == 0 {
				t.Fatalf("missing file results: %q, %v", data, err)
			}
			if tc.format == "jsonl" {
				lines := strings.Split(strings.TrimSpace(string(data)), "\n")
				want := 2
				if tc.name == "filtered failures" {
					want = 1
				}
				if len(lines) != want {
					t.Fatalf("got %d results, want %d: %s", len(lines), want, data)
				}
				for _, line := range lines {
					var result ctscan.Result
					if err := json.Unmarshal([]byte(line), &result); err != nil || result.Status == "" {
						t.Fatalf("invalid result: %q, %v", line, err)
					}
				}
			}
		})
	}
}

func TestScanWithoutOutputFileStillUsesStdout(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{server.URL}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 || stdout.Len() == 0 || !strings.Contains(stderr.String(), "Scanned 1 targets") || strings.Contains(stderr.String(), "Objects left") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestOrderedProgressBeforeBufferedResults(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	release := make(chan struct{})
	defer close(release)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			<-release
		}
	}()
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scanner, err := ctscan.NewScanner(ctscan.Config{Concurrency: 2, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer scanner.Close()
	port := func(addr net.Addr) uint16 { return uint16(addr.(*net.TCPAddr).Port) }
	targets := []ctscan.Target{
		{Host: "127.0.0.1", Address: "127.0.0.1", Port: port(listener.Addr())},
		{Host: "127.0.0.1", Address: "127.0.0.1", Port: port(server.Listener.Addr())},
	}
	completed := make(chan struct{}, 2)
	emitted := make(chan struct{}, 2)
	done := make(chan error, 1)
	go func() {
		done <- runWave(ctx, scanner, targets, false, scanOptions{concurrency: 2, ordered: true}, func() {
			completed <- struct{}{}
		}, func(ctscan.Result) error {
			emitted <- struct{}{}
			return nil
		})
	}()
	defer func() {
		cancel()
		<-done
	}()
	select {
	case <-completed:
		if len(emitted) != 0 {
			t.Fatal("ordered results emitted while the first target is still scanning")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("progress waited for the entire ordered wave")
	}
}
