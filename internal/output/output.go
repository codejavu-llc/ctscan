package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/codejavu-llc/ctscan/internal/input"
	"github.com/codejavu-llc/ctscan/pkg/ctscan"
)

type Config struct {
	Format          string
	IncludeFailures bool
}

type Writer struct {
	mu      sync.Mutex
	buffer  *bufio.Writer
	encoder *json.Encoder
	config  Config
	seenDNS map[string]struct{}
}

func New(destination io.Writer, cfg Config) (*Writer, error) {
	switch cfg.Format {
	case "", "text":
		cfg.Format = "text"
	case "json", "jsonl":
		cfg.Format = "jsonl"
	case "dns":
	default:
		return nil, fmt.Errorf("unsupported output format %q", cfg.Format)
	}
	buffer := bufio.NewWriter(destination)
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	return &Writer{buffer: buffer, encoder: encoder, config: cfg, seenDNS: make(map[string]struct{})}, nil
}

func (w *Writer) Write(result ctscan.Result) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if result.Status != "success" && !w.config.IncludeFailures {
		return nil
	}
	switch w.config.Format {
	case "jsonl":
		return w.encoder.Encode(result)
	case "dns":
		for _, name := range CertificateNames(result) {
			if _, ok := w.seenDNS[name]; ok {
				continue
			}
			w.seenDNS[name] = struct{}{}
			if _, err := fmt.Fprintln(w.buffer, name); err != nil {
				return err
			}
		}
		return nil
	default:
		_, err := fmt.Fprintln(w.buffer, formatText(result))
		return err
	}
}

func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buffer.Flush()
}

func CertificateNames(result ctscan.Result) []string {
	if result.Certificate == nil {
		return nil
	}
	seen := make(map[string]struct{})
	values := append([]string(nil), result.Certificate.DNSNames...)
	if result.Certificate.Subject.CommonName != "" {
		values = append(values, result.Certificate.Subject.CommonName)
	}
	var names []string
	for _, value := range values {
		name, err := input.NormalizeDNSName(value)
		if err != nil {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func formatText(result ctscan.Result) string {
	endpoint := result.Host
	if result.IP != "" && result.IP != result.Host {
		endpoint += "(" + result.IP + ")"
	}
	endpoint = netJoinDisplay(endpoint, result.Port)
	if result.Error != nil {
		return fmt.Sprintf("[%s] Error: %s (%s)", endpoint, strings.ToUpper(result.Error.Kind), result.Error.Message)
	}
	cn := ""
	sans := []string(nil)
	if result.Certificate != nil {
		cn = result.Certificate.Subject.CommonName
		sans = result.Certificate.DNSNames
	}
	version, cipher := "", ""
	if result.TLS != nil {
		version, cipher = result.TLS.Version, result.TLS.Cipher
	}
	line := fmt.Sprintf("[%s] CN: %s | SANs: [%s] | TLS: %s | Cipher: %s", endpoint, cn, strings.Join(sans, ", "), version, cipher)
	if result.SNI != "" && result.SNI != result.Host {
		line += " | SNI: " + result.SNI
	}
	if result.Audit != nil {
		line += fmt.Sprintf(" | Audit: %s (%s)", result.Audit.Compliance, result.Audit.Profile)
	}
	if len(result.Findings) > 0 {
		line += fmt.Sprintf(" | Findings: %d", len(result.Findings))
	}
	return line
}

func netJoinDisplay(host string, port uint16) string {
	if strings.Contains(host, ":") && !strings.Contains(host, ")") {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}
