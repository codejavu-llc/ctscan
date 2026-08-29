package snapshot

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/codejavu-llc/ctscan/pkg/ctscan"
)

type Change struct {
	SchemaVersion string `json:"schema_version"`
	Kind          string `json:"kind"`
	Severity      string `json:"severity"`
	Identity      string `json:"identity"`
	Detail        string `json:"detail"`
}

func Read(reader io.Reader) (map[string]ctscan.Result, error) {
	results := make(map[string]ctscan.Result)
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var result ctscan.Result
		if err := json.Unmarshal(scanner.Bytes(), &result); err != nil {
			return nil, fmt.Errorf("decode JSONL line %d: %w", line, err)
		}
		results[Identity(result)] = result
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

func Identity(result ctscan.Result) string {
	return fmt.Sprintf("%s|%s|%d|%s", result.Host, result.IP, result.Port, result.SNI)
}

func Diff(before, after map[string]ctscan.Result) []Change {
	var changes []Change
	for identity, current := range after {
		previous, exists := before[identity]
		if !exists {
			changes = append(changes, Change{"1.0", "asset_added", "info", identity, "endpoint appears in the new snapshot"})
			continue
		}
		oldFingerprint, newFingerprint := fingerprint(previous), fingerprint(current)
		if oldFingerprint != newFingerprint {
			changes = append(changes, Change{"1.0", "certificate_changed", "info", identity, fmt.Sprintf("%s -> %s", oldFingerprint, newFingerprint)})
		}
		for _, name := range difference(names(current), names(previous)) {
			changes = append(changes, Change{"1.0", "san_added", "info", identity, name})
		}
		for _, name := range difference(names(previous), names(current)) {
			changes = append(changes, Change{"1.0", "san_removed", "info", identity, name})
		}
		if complianceRank(compliance(current)) > complianceRank(compliance(previous)) {
			changes = append(changes, Change{"1.0", "security_regression", "high", identity, fmt.Sprintf("%s -> %s", compliance(previous), compliance(current))})
		}
	}
	for identity := range before {
		if _, exists := after[identity]; !exists {
			changes = append(changes, Change{"1.0", "asset_removed", "info", identity, "endpoint is absent from the new snapshot"})
		}
	}
	slices.SortFunc(changes, func(a, b Change) int {
		if compared := strings.Compare(a.Identity, b.Identity); compared != 0 {
			return compared
		}
		return strings.Compare(a.Kind, b.Kind)
	})
	return changes
}

func fingerprint(result ctscan.Result) string {
	if result.Certificate == nil {
		return ""
	}
	return result.Certificate.FingerprintSHA256
}

func names(result ctscan.Result) []string {
	if result.Certificate == nil {
		return nil
	}
	names := append([]string(nil), result.Certificate.DNSNames...)
	slices.Sort(names)
	return slices.Compact(names)
}

func difference(left, right []string) []string {
	rightSet := make(map[string]struct{}, len(right))
	for _, item := range right {
		rightSet[item] = struct{}{}
	}
	var result []string
	for _, item := range left {
		if _, ok := rightSet[item]; !ok {
			result = append(result, item)
		}
	}
	return result
}

func compliance(result ctscan.Result) string {
	if result.Audit != nil && result.Audit.Compliance != "" {
		return result.Audit.Compliance
	}
	for _, finding := range result.Findings {
		if finding.Severity == "critical" || finding.Severity == "high" {
			return "fail"
		}
	}
	if len(result.Findings) > 0 {
		return "warn"
	}
	return "pass"
}

func complianceRank(value string) int {
	switch value {
	case "fail":
		return 2
	case "warn":
		return 1
	default:
		return 0
	}
}
