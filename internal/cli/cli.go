package cli

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/codejavu-llc/ctscan/internal/input"
	"github.com/codejavu-llc/ctscan/internal/output"
	"github.com/codejavu-llc/ctscan/internal/snapshot"
	"github.com/codejavu-llc/ctscan/internal/transparency"
	"github.com/codejavu-llc/ctscan/pkg/ctscan"
	flag "github.com/spf13/pflag"
	"golang.org/x/net/publicsuffix"
)

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

const usageText = `ctscan — certificate-driven reconnaissance and TLS triage

Usage:
  ctscan [scan flags] [targets...]     Fast TLS reconnaissance (default)
  ctscan scan [flags] [targets...]    Fast TLS reconnaissance
  ctscan audit [flags] [targets...]   Enumerate TLS versions and ciphers
  ctscan ct [flags] [domains...]      Discover names from CT history
  ctscan diff [flags] OLD NEW         Compare JSONL scan snapshots
  ctscan version                      Print build information
  ctscan completion SHELL             Generate bash, zsh, or fish completion

Use "ctscan COMMAND -h" for command-specific options.`

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }
func (values *stringList) Type() string   { return "value" }
func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

type scanOptions struct {
	targets         stringList
	lists           stringList
	ports           string
	concurrency     int
	timeout         string
	retries         int
	rateLimit       int
	outputFile      string
	format          string
	jsonOutput      bool
	dnsOutput       bool
	silent          bool
	stats           bool
	successOnly     bool
	includeFailures bool
	ordered         bool
	scanAllIPs      bool
	resolver        string
	serverNames     stringList
	sniList         string
	proxy           string
	startTLS        string
	minVersion      string
	maxVersion      string
	caFile          string
	allowLargeRange bool
	pivot           bool
	scopes          stringList
	pivotDepth      int
	maxDiscovery    int
	profile         string
	cipherWorkers   int
}

type runStats struct {
	processed int
	succeeded int
	failed    int
	findings  int
	auditFail bool
	started   time.Time
}

func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return runScan(ctx, nil, stdin, stdout, stderr, false)
	}
	switch args[0] {
	case "scan":
		return runScan(ctx, args[1:], stdin, stdout, stderr, false)
	case "audit":
		return runScan(ctx, args[1:], stdin, stdout, stderr, true)
	case "ct":
		return runCT(ctx, args[1:], stdin, stdout, stderr)
	case "diff":
		return runDiff(args[1:], stdout, stderr)
	case "version", "--version":
		fmt.Fprintf(stdout, "ctscan %s (%s, %s, %s/%s)\n", Version, Commit, Date, runtime.GOOS, runtime.GOARCH)
		return 0
	case "completion":
		return runCompletion(args[1:], stdout, stderr)
	case "help":
		fmt.Fprintln(stdout, usageText)
		return 0
	default:
		return runScan(ctx, args, stdin, stdout, stderr, false)
	}
}

func runScan(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, audit bool) int {
	command := "scan"
	if audit {
		command = "audit"
	}
	fs := flag.NewFlagSet("ctscan "+command, flag.ContinueOnError)
	fs.SetOutput(stderr)
	opts := scanOptions{ports: "443", concurrency: 300, timeout: "5s", retries: 1, format: "text", stats: true, includeFailures: true, pivotDepth: 1, maxDiscovery: 10_000, profile: "intermediate", cipherWorkers: 10}
	if audit {
		opts.concurrency = 20
	}
	fs.VarP(&opts.targets, "target", "u", "target to scan (repeatable or comma-separated)")
	fs.VarP(&opts.lists, "list", "l", "input list file (repeatable)")
	fs.StringVarP(&opts.ports, "port", "p", opts.ports, "ports or ranges, for example 443,8443,9443-9445")
	fs.IntVarP(&opts.concurrency, "concurrency", "c", opts.concurrency, "number of concurrent targets")
	fs.StringVarP(&opts.timeout, "timeout", "t", opts.timeout, "per-attempt timeout (bare numbers mean seconds)")
	fs.IntVar(&opts.retries, "retries", opts.retries, "retries for transient failures")
	fs.IntVar(&opts.rateLimit, "rate-limit", 0, "maximum connection attempts per second (0 is unlimited)")
	fs.StringVarP(&opts.outputFile, "output", "o", "", "also write results to this file")
	fs.StringVar(&opts.format, "format", opts.format, "output format: text, jsonl, or dns")
	fs.BoolVarP(&opts.jsonOutput, "json", "j", false, "emit JSONL")
	fs.BoolVar(&opts.dnsOutput, "dns", false, "emit unique certificate names")
	fs.BoolVar(&opts.silent, "silent", false, "suppress status messages")
	fs.BoolVar(&opts.stats, "stats", opts.stats, "print final scan statistics")
	fs.BoolVar(&opts.successOnly, "success-only", false, "omit failed targets")
	fs.BoolVar(&opts.includeFailures, "include-failures", opts.includeFailures, "include structured target failures")
	fs.BoolVar(&opts.ordered, "ordered", false, "preserve target order (buffers a scan wave)")
	fs.BoolVar(&opts.scanAllIPs, "scan-all-ips", false, "scan every resolved address")
	fs.StringVar(&opts.resolver, "resolver", "", "custom DNS resolver host[:port]")
	fs.Var(&opts.serverNames, "sni", "override TLS SNI (repeatable)")
	fs.StringVar(&opts.sniList, "sni-list", "", "file containing SNI names")
	fs.StringVar(&opts.proxy, "proxy", "", "HTTP(S) CONNECT or SOCKS5 proxy URL")
	fs.StringVar(&opts.startTLS, "starttls", "", "smtp, imap, pop3, ftp, ldap, postgres, or mysql")
	fs.StringVar(&opts.minVersion, "min-version", "", "minimum TLS version: tls10, tls11, tls12, tls13")
	fs.StringVar(&opts.maxVersion, "max-version", "", "maximum TLS version")
	fs.StringVar(&opts.caFile, "ca-file", "", "additional PEM CA bundle")
	fs.BoolVar(&opts.allowLargeRange, "allow-large-range", false, "allow CIDRs larger than 65536 addresses")
	fs.BoolVar(&opts.pivot, "pivot", false, "scan in-scope names discovered in certificates")
	fs.Var(&opts.scopes, "scope", "DNS suffix allowed for --pivot (repeatable)")
	fs.IntVar(&opts.pivotDepth, "pivot-depth", opts.pivotDepth, "maximum certificate-pivot depth")
	fs.IntVar(&opts.maxDiscovery, "max-discovery", opts.maxDiscovery, "maximum names added by pivoting")
	if audit {
		fs.StringVar(&opts.profile, "profile", opts.profile, "audit profile: intermediate or modern")
		fs.IntVar(&opts.cipherWorkers, "cipher-concurrency", opts.cipherWorkers, "cipher probes per target")
	}
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: ctscan %s [flags] [targets...]\n\n", command)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if opts.jsonOutput {
		opts.format = "jsonl"
	}
	if opts.dnsOutput {
		opts.format = "dns"
	}
	if opts.pivot && len(opts.scopes) == 0 {
		fmt.Fprintln(stderr, "error: --pivot requires at least one explicit --scope")
		return 2
	}
	if opts.pivot {
		for index, scope := range opts.scopes {
			normalized, scopeErr := input.NormalizeDNSName(scope)
			if scopeErr != nil {
				fmt.Fprintf(stderr, "error: invalid --scope %q: %v\n", scope, scopeErr)
				return 2
			}
			suffix, icann := publicsuffix.PublicSuffix(normalized)
			if icann && suffix == normalized {
				fmt.Fprintf(stderr, "error: --scope %q is a public suffix, not an authorized registrable domain\n", scope)
				return 2
			}
			opts.scopes[index] = normalized
		}
	}
	if opts.pivotDepth < 1 || opts.maxDiscovery < 1 {
		fmt.Fprintln(stderr, "error: pivot depth and discovery limit must be positive")
		return 2
	}
	if opts.concurrency < 1 || opts.concurrency > 100_000 {
		fmt.Fprintln(stderr, "error: concurrency must be between 1 and 100000")
		return 2
	}
	if audit && opts.profile != "intermediate" && opts.profile != "modern" {
		fmt.Fprintln(stderr, "error: --profile must be intermediate or modern")
		return 2
	}
	ports, err := input.ParsePorts(opts.ports)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	timeout, err := parseDuration(opts.timeout)
	if err != nil {
		fmt.Fprintln(stderr, "error: invalid timeout:", err)
		return 2
	}
	minVersion, err := parseTLSVersion(opts.minVersion)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	maxVersion, err := parseTLSVersion(opts.maxVersion)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	roots, err := loadRoots(opts.caFile)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	if opts.sniList != "" {
		if err := input.ReadFile(opts.sniList, func(value string) error {
			if strings.TrimSpace(value) != "" {
				opts.serverNames = append(opts.serverNames, strings.TrimSpace(value))
			}
			return nil
		}); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
	}

	rawTargets, err := collectRawTargets(fs.Args(), opts.targets, opts.lists, stdin)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	if len(rawTargets) == 0 {
		fmt.Fprintln(stderr, "error: no targets supplied through arguments, -u, -l, or stdin")
		return 2
	}
	resolver, err := input.Resolver(opts.resolver)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	remoteDNS := strings.HasPrefix(strings.ToLower(opts.proxy), "socks5h://")
	parsed, failures, err := prepareTargets(ctx, rawTargets, input.Options{Ports: ports, AllowLargeRange: opts.allowLargeRange, StartTLS: opts.startTLS, ServerNames: opts.serverNames}, resolver, opts.scanAllIPs, remoteDNS)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}

	config := ctscan.Config{Concurrency: opts.concurrency, Timeout: timeout, Retries: opts.retries, RateLimit: opts.rateLimit, ProxyURL: opts.proxy, MinVersion: minVersion, MaxVersion: maxVersion, RootCAs: roots}
	scanner, err := ctscan.NewScanner(config)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	defer scanner.Close()

	destination := stdout
	var outputHandle *os.File
	if opts.outputFile != "" {
		outputHandle, err = os.Create(opts.outputFile)
		if err != nil {
			fmt.Fprintln(stderr, "error: create output:", err)
			return 1
		}
		defer outputHandle.Close()
		// Persist first so a downstream broken pipe cannot leave -o incomplete.
		destination = io.MultiWriter(outputHandle, stdout)
	}
	includeFailures := opts.includeFailures && !opts.successOnly && opts.format != "dns"
	resultWriter, err := output.New(destination, output.Config{Format: opts.format, IncludeFailures: includeFailures})
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	stats := runStats{started: time.Now()}
	for _, failure := range failures {
		stats.processed++
		stats.failed++
		if err := resultWriter.Write(failure); err != nil {
			fmt.Fprintln(stderr, "error: write output:", err)
			return 1
		}
	}
	seen := make(map[string]struct{}, len(parsed))
	for _, target := range parsed {
		seen[targetKey(target)] = struct{}{}
	}
	wave := parsed
	discovered := 0
	for depth := 0; len(wave) > 0; depth++ {
		var nextNames []string
		err = runWave(ctx, scanner, wave, audit, opts, func(result ctscan.Result) error {
			stats.processed++
			if result.Status == "success" {
				stats.succeeded++
			} else {
				stats.failed++
			}
			stats.findings += len(result.Findings)
			if result.Audit != nil && result.Audit.Compliance == "fail" {
				stats.auditFail = true
			}
			if opts.pivot && depth < opts.pivotDepth {
				for _, name := range output.CertificateNames(result) {
					if input.InScope(name, opts.scopes) {
						nextNames = append(nextNames, name)
					}
				}
			}
			return resultWriter.Write(result)
		})
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		if !opts.pivot || depth >= opts.pivotDepth {
			break
		}
		slices.Sort(nextNames)
		nextNames = slices.Compact(nextNames)
		var next []ctscan.Target
		for _, name := range nextNames {
			if discovered >= opts.maxDiscovery {
				break
			}
			candidates, pivotFailures, prepErr := prepareTargets(ctx, []string{name}, input.Options{Ports: ports, StartTLS: opts.startTLS}, resolver, opts.scanAllIPs, remoteDNS)
			if prepErr != nil {
				continue
			}
			for _, failure := range pivotFailures {
				stats.processed++
				stats.failed++
				if writeErr := resultWriter.Write(failure); writeErr != nil {
					fmt.Fprintln(stderr, "error: write pivot failure:", writeErr)
					return 1
				}
			}
			addedName := false
			for _, candidate := range candidates {
				key := targetKey(candidate)
				if _, exists := seen[key]; exists {
					continue
				}
				seen[key] = struct{}{}
				next = append(next, candidate)
				addedName = true
			}
			if addedName {
				discovered++
			}
		}
		wave = next
	}
	if err := resultWriter.Flush(); err != nil {
		fmt.Fprintln(stderr, "error: flush output:", err)
		return 1
	}
	if opts.stats && !opts.silent {
		elapsed := time.Since(stats.started)
		rate := 0.0
		if elapsed > 0 {
			rate = float64(stats.processed) / elapsed.Seconds()
		}
		fmt.Fprintf(stderr, "Scanned %d targets in %s (%.2f/sec): %d succeeded, %d failed, %d findings\n", stats.processed, elapsed.Round(time.Millisecond), rate, stats.succeeded, stats.failed, stats.findings)
	}
	if ctx.Err() != nil {
		return 130
	}
	if audit && stats.auditFail {
		return 3
	}
	return 0
}

func runWave(ctx context.Context, scanner *ctscan.Scanner, targets []ctscan.Target, audit bool, opts scanOptions, emit func(ctscan.Result) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if opts.ordered {
		results := make([]ctscan.Result, len(targets))
		jobs := make(chan int)
		var workers sync.WaitGroup
		workers.Add(opts.concurrency)
		for range opts.concurrency {
			go func() {
				defer workers.Done()
				for index := range jobs {
					if audit {
						results[index] = scanner.ScanAudit(ctx, targets[index], ctscan.AuditConfig{Profile: opts.profile, CipherConcurrency: opts.cipherWorkers})
					} else {
						results[index] = scanner.Scan(ctx, targets[index])
					}
				}
			}()
		}
		for index := range targets {
			select {
			case jobs <- index:
			case <-ctx.Done():
				close(jobs)
				workers.Wait()
				return ctx.Err()
			}
		}
		close(jobs)
		workers.Wait()
		for _, result := range results {
			if err := emit(result); err != nil {
				return err
			}
		}
		return nil
	}

	if !audit {
		channel := make(chan ctscan.Target, opts.concurrency)
		go func() {
			defer close(channel)
			for _, target := range targets {
				select {
				case channel <- target:
				case <-ctx.Done():
					return
				}
			}
		}()
		for result := range scanner.ScanStream(ctx, channel) {
			if err := emit(result); err != nil {
				return err
			}
		}
		return nil
	}

	jobs := make(chan ctscan.Target)
	results := make(chan ctscan.Result, opts.concurrency)
	var workers sync.WaitGroup
	workers.Add(opts.concurrency)
	for range opts.concurrency {
		go func() {
			defer workers.Done()
			for target := range jobs {
				result := scanner.ScanAudit(ctx, target, ctscan.AuditConfig{Profile: opts.profile, CipherConcurrency: opts.cipherWorkers})
				select {
				case results <- result:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, target := range targets {
			select {
			case jobs <- target:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		workers.Wait()
		close(results)
	}()
	for result := range results {
		if err := emit(result); err != nil {
			return err
		}
	}
	return nil
}

func collectRawTargets(args []string, direct, listFiles []string, stdin io.Reader) ([]string, error) {
	var values []string
	emit := func(value string) error {
		value = strings.TrimSpace(value)
		if value != "" {
			values = append(values, value)
		}
		return nil
	}
	for _, value := range append(append([]string(nil), direct...), args...) {
		for _, item := range strings.Split(value, ",") {
			_ = emit(item)
		}
	}
	for _, path := range listFiles {
		if err := input.ReadFile(path, emit); err != nil {
			return nil, err
		}
	}
	if shouldReadStdin(stdin) {
		if err := input.ReadLines(stdin, emit); err != nil {
			return nil, err
		}
	}
	return values, nil
}

func shouldReadStdin(reader io.Reader) bool {
	file, ok := reader.(*os.File)
	if !ok {
		return true
	}
	stat, err := file.Stat()
	return err == nil && stat.Mode()&os.ModeCharDevice == 0
}

func prepareTargets(ctx context.Context, raw []string, opts input.Options, resolver *net.Resolver, allIPs, remoteDNS bool) ([]ctscan.Target, []ctscan.Result, error) {
	seen := make(map[string]struct{})
	var targets []ctscan.Target
	var failures []ctscan.Result
	for _, value := range raw {
		parsed, err := input.ParseTarget(value, opts)
		if err != nil {
			return nil, nil, err
		}
		for _, target := range parsed {
			if remoteDNS && net.ParseIP(target.Host) == nil {
				key := targetKey(target)
				if _, exists := seen[key]; !exists {
					seen[key] = struct{}{}
					targets = append(targets, target)
				}
				continue
			}
			resolved, err := input.Resolve(ctx, resolver, target, allIPs)
			if err != nil {
				failures = append(failures, ctscan.Result{SchemaVersion: ctscan.SchemaVersion, Timestamp: time.Now().UTC(), Input: target.Input, Host: target.Host, Port: target.Port, SNI: target.ServerName, Status: "failed", Error: &ctscan.ScanError{Kind: "dns", Message: err.Error(), Retryable: true}})
				continue
			}
			for _, candidate := range resolved {
				key := targetKey(candidate)
				if _, exists := seen[key]; exists {
					continue
				}
				seen[key] = struct{}{}
				targets = append(targets, candidate)
			}
		}
	}
	return targets, failures, nil
}

func targetKey(target ctscan.Target) string {
	return fmt.Sprintf("%s|%s|%d|%s|%s", target.Host, target.Address, target.Port, target.ServerName, target.StartTLS)
}

func parseDuration(value string) (time.Duration, error) {
	if seconds, err := strconv.Atoi(value); err == nil {
		return time.Duration(seconds) * time.Second, nil
	}
	return time.ParseDuration(value)
}

func parseTLSVersion(value string) (uint16, error) {
	switch strings.ToLower(strings.ReplaceAll(value, ".", "")) {
	case "":
		return 0, nil
	case "tls10", "tls1":
		return tls.VersionTLS10, nil
	case "tls11":
		return tls.VersionTLS11, nil
	case "tls12":
		return tls.VersionTLS12, nil
	case "tls13":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("invalid TLS version %q", value)
	}
}

func loadRoots(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("CA file %q contained no certificates", path)
	}
	return roots, nil
}

func runCT(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ctscan ct", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var domains, lists stringList
	providerName := "crtsh"
	format := "dns"
	token := ""
	includeSubdomains := true
	timeout := 30 * time.Second
	fs.VarP(&domains, "domain", "d", "domain to query (repeatable)")
	fs.VarP(&lists, "list", "l", "domain list file (repeatable)")
	fs.StringVar(&providerName, "provider", providerName, "CT provider: crtsh or certspotter")
	fs.StringVar(&format, "format", format, "output format: dns, text, or jsonl")
	fs.StringVar(&token, "token", os.Getenv("CTSCAN_CERTSPOTTER_TOKEN"), "Cert Spotter API token")
	fs.BoolVar(&includeSubdomains, "include-subdomains", includeSubdomains, "include subdomains")
	fs.DurationVar(&timeout, "timeout", timeout, "provider request timeout")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	raw, err := collectRawTargets(fs.Args(), domains, lists, stdin)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	if len(raw) == 0 {
		fmt.Fprintln(stderr, "error: no domains supplied")
		return 2
	}
	provider, err := transparency.New(providerName, transparency.ClientConfig{Token: token, UserAgent: "ctscan/" + Version, HTTPClient: &http.Client{Timeout: timeout}})
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	buffer := bufio.NewWriter(stdout)
	defer buffer.Flush()
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	seenNames := make(map[string]struct{})
	seenRecords := make(map[string]struct{})
	for _, value := range raw {
		domain, err := input.NormalizeDNSName(value)
		if err != nil {
			fmt.Fprintf(stderr, "warning: skip invalid domain %q: %v\n", value, err)
			continue
		}
		if suffix, icann := publicsuffix.PublicSuffix(domain); icann && suffix == domain {
			fmt.Fprintf(stderr, "error: refusing CT query for public suffix %q\n", domain)
			return 2
		}
		records, err := provider.Search(ctx, domain, includeSubdomains)
		if err != nil {
			fmt.Fprintf(stderr, "error: %s: %v\n", domain, err)
			return 1
		}
		for _, record := range records {
			key := record.Provider + "|" + record.CertificateID
			if _, exists := seenRecords[key]; exists {
				continue
			}
			seenRecords[key] = struct{}{}
			switch format {
			case "json", "jsonl":
				if err := encoder.Encode(record); err != nil {
					return 1
				}
			case "text":
				fmt.Fprintf(buffer, "[%s:%s] %s | %s → %s\n", record.Provider, record.CertificateID, strings.Join(record.DNSNames, ", "), record.NotBefore.Format(time.RFC3339), record.NotAfter.Format(time.RFC3339))
			case "dns":
				for _, name := range record.DNSNames {
					if _, exists := seenNames[name]; exists {
						continue
					}
					seenNames[name] = struct{}{}
					fmt.Fprintln(buffer, name)
				}
			default:
				fmt.Fprintln(stderr, "error: unsupported CT output format", format)
				return 2
			}
		}
	}
	if err := buffer.Flush(); err != nil {
		return 1
	}
	return 0
}

func runDiff(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ctscan diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := "text"
	failOnChange := false
	fs.StringVar(&format, "format", format, "output format: text or jsonl")
	fs.BoolVar(&failOnChange, "fail-on-change", false, "exit 3 when any change is found")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if fs.NArg() != 2 {
		fmt.Fprintln(stderr, "error: diff requires OLD.jsonl and NEW.jsonl")
		return 2
	}
	beforeFile, err := os.Open(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	defer beforeFile.Close()
	afterFile, err := os.Open(fs.Arg(1))
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	defer afterFile.Close()
	before, err := snapshot.Read(beforeFile)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	after, err := snapshot.Read(afterFile)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	changes := snapshot.Diff(before, after)
	encoder := json.NewEncoder(stdout)
	for _, change := range changes {
		if format == "json" || format == "jsonl" {
			if err := encoder.Encode(change); err != nil {
				return 1
			}
		} else if format == "text" {
			fmt.Fprintf(stdout, "[%s] %s %s: %s\n", strings.ToUpper(change.Severity), change.Identity, change.Kind, change.Detail)
		} else {
			fmt.Fprintln(stderr, "error: unsupported diff output format", format)
			return 2
		}
	}
	if failOnChange && len(changes) > 0 {
		return 3
	}
	return 0
}

func runCompletion(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "error: completion requires bash, zsh, or fish")
		return 2
	}
	commands := "scan audit ct diff version completion"
	switch args[0] {
	case "bash":
		fmt.Fprintf(stdout, "complete -W %q ctscan\n", commands)
	case "zsh":
		fmt.Fprintf(stdout, "#compdef ctscan\n_arguments '1:command:(%s)'\n", commands)
	case "fish":
		for _, command := range strings.Fields(commands) {
			fmt.Fprintf(stdout, "complete -c ctscan -f -a %s\n", command)
		}
	default:
		fmt.Fprintln(stderr, "error: completion requires bash, zsh, or fish")
		return 2
	}
	return 0
}
