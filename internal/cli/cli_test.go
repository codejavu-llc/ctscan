package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
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
