// Package transparency provides passive certificate-transparency discovery.
package transparency

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/codejavu-llc/ctscan/internal/input"
)

type Record struct {
	SchemaVersion string    `json:"schema_version"`
	Provider      string    `json:"provider"`
	Domain        string    `json:"domain"`
	CertificateID string    `json:"certificate_id"`
	DNSNames      []string  `json:"dns_names"`
	Issuer        string    `json:"issuer,omitempty"`
	NotBefore     time.Time `json:"not_before,omitempty"`
	NotAfter      time.Time `json:"not_after,omitempty"`
}

type Provider interface {
	Name() string
	Search(context.Context, string, bool) ([]Record, error)
}

type ClientConfig struct {
	HTTPClient *http.Client
	Token      string
	UserAgent  string
	BaseURL    string
	Retries    int
}

func New(name string, cfg ClientConfig) (Provider, error) {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "ctscan"
	}
	switch strings.ToLower(name) {
	case "", "crtsh":
		return &crtSH{config: cfg}, nil
	case "certspotter":
		if cfg.Token == "" {
			return nil, fmt.Errorf("certspotter requires CTSCAN_CERTSPOTTER_TOKEN or --token")
		}
		return &certSpotter{config: cfg}, nil
	default:
		return nil, fmt.Errorf("unsupported CT provider %q", name)
	}
}

type crtSH struct{ config ClientConfig }

func (c *crtSH) Name() string { return "crtsh" }

func (c *crtSH) Search(ctx context.Context, domain string, includeSubdomains bool) ([]Record, error) {
	query := domain
	if includeSubdomains {
		query = "%." + domain
	}
	base := c.config.BaseURL
	if base == "" {
		base = "https://crt.sh/"
	}
	endpoint := strings.TrimRight(base, "/") + "/?output=json&q=" + url.QueryEscape(query)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", c.config.UserAgent)
	response, err := doRequest(ctx, c.config, request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned %s", response.Status)
	}
	var raw []struct {
		ID         int64  `json:"id"`
		NameValue  string `json:"name_value"`
		IssuerName string `json:"issuer_name"`
		NotBefore  string `json:"not_before"`
		NotAfter   string `json:"not_after"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<20))
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode crt.sh response: %w", err)
	}
	records := make([]Record, 0, len(raw))
	for _, item := range raw {
		record := Record{SchemaVersion: "1.0", Provider: c.Name(), Domain: domain, CertificateID: strconv.FormatInt(item.ID, 10), Issuer: item.IssuerName}
		record.DNSNames = normalizedNames(strings.Fields(item.NameValue), domain)
		record.NotBefore = parseTime(item.NotBefore)
		record.NotAfter = parseTime(item.NotAfter)
		if len(record.DNSNames) > 0 {
			records = append(records, record)
		}
	}
	return records, nil
}

type certSpotter struct{ config ClientConfig }

func (c *certSpotter) Name() string { return "certspotter" }

func (c *certSpotter) Search(ctx context.Context, domain string, includeSubdomains bool) ([]Record, error) {
	base := c.config.BaseURL
	if base == "" {
		base = "https://api.certspotter.com/v1/issuances"
	}
	query := url.Values{}
	query.Set("domain", domain)
	query.Set("include_subdomains", strconv.FormatBool(includeSubdomains))
	query.Add("expand", "dns_names")
	query.Add("expand", "issuer")
	endpoint := base + "?" + query.Encode()
	var records []Record
	for endpoint != "" {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Authorization", "Bearer "+c.config.Token)
		request.Header.Set("User-Agent", c.config.UserAgent)
		response, err := doRequest(ctx, c.config, request)
		if err != nil {
			return nil, err
		}
		if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			return nil, fmt.Errorf("certspotter returned %s", response.Status)
		}
		var raw []struct {
			ID        string   `json:"id"`
			DNSNames  []string `json:"dns_names"`
			NotBefore string   `json:"not_before"`
			NotAfter  string   `json:"not_after"`
			Issuer    struct {
				Name string `json:"name"`
			} `json:"issuer"`
		}
		decodeErr := json.NewDecoder(io.LimitReader(response.Body, 16<<20)).Decode(&raw)
		_ = response.Body.Close()
		if decodeErr != nil {
			return nil, fmt.Errorf("decode certspotter response: %w", decodeErr)
		}
		for _, item := range raw {
			names := normalizedNames(item.DNSNames, domain)
			if len(names) == 0 {
				continue
			}
			records = append(records, Record{
				SchemaVersion: "1.0", Provider: c.Name(), Domain: domain, CertificateID: item.ID,
				DNSNames: names, Issuer: item.Issuer.Name, NotBefore: parseTime(item.NotBefore), NotAfter: parseTime(item.NotAfter),
			})
		}
		next := parseNextLink(response.Header.Get("Link"))
		if next != "" {
			if parsedNext, err := url.Parse(next); err == nil && !parsedNext.IsAbs() {
				if parsedBase, err := url.Parse(endpoint); err == nil {
					next = parsedBase.ResolveReference(parsedNext).String()
				}
			}
		}
		endpoint = next
	}
	return records, nil
}

func normalizedNames(values []string, domain string) []string {
	seen := make(map[string]struct{})
	var names []string
	for _, value := range values {
		name, err := input.NormalizeDNSName(value)
		if err != nil || !input.InScope(name, []string{domain}) {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return names
}

func parseTime(value string) time.Time {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}

func parseNextLink(value string) string {
	for _, item := range strings.Split(value, ",") {
		if strings.Contains(item, `rel="next"`) {
			start := strings.IndexByte(item, '<')
			end := strings.IndexByte(item, '>')
			if start >= 0 && end > start {
				return item[start+1 : end]
			}
		}
	}
	return ""
}

func doRequest(ctx context.Context, cfg ClientConfig, request *http.Request) (*http.Response, error) {
	retries := cfg.Retries
	if retries == 0 {
		retries = 2
	}
	if retries < 0 {
		retries = 0
	}
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		response, err := cfg.HTTPClient.Do(request.Clone(ctx))
		if err == nil && response.StatusCode != http.StatusTooManyRequests && response.StatusCode < 500 {
			return response, nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("provider returned %s", response.Status)
			_ = response.Body.Close()
		}
		if attempt == retries {
			break
		}
		delay := time.Duration(1<<attempt) * 250 * time.Millisecond
		if response != nil {
			if seconds, err := strconv.Atoi(response.Header.Get("Retry-After")); err == nil && seconds > 0 {
				delay = time.Duration(seconds) * time.Second
			}
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, lastErr
}
