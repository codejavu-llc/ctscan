package input

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/codejavu-llc/ctscan/pkg/ctscan"
	"golang.org/x/net/idna"
)

const defaultCIDRLimit = 65_536

type Options struct {
	Ports           []uint16
	AllowLargeRange bool
	StartTLS        string
	ServerNames     []string
}

// ParsePorts parses comma-separated individual ports and inclusive ranges.
func ParsePorts(value string) ([]uint16, error) {
	if strings.TrimSpace(value) == "" {
		return []uint16{443}, nil
	}
	seen := make(map[uint16]struct{})
	var ports []uint16
	add := func(number int) error {
		if number < 1 || number > 65535 {
			return fmt.Errorf("port %d is outside 1-65535", number)
		}
		port := uint16(number)
		if _, ok := seen[port]; !ok {
			seen[port] = struct{}{}
			ports = append(ports, port)
		}
		return nil
	}
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if before, after, ok := strings.Cut(item, "-"); ok {
			start, err := strconv.Atoi(before)
			if err != nil {
				return nil, fmt.Errorf("invalid port range %q", item)
			}
			end, err := strconv.Atoi(after)
			if err != nil || end < start {
				return nil, fmt.Errorf("invalid port range %q", item)
			}
			if end-start > 10_000 {
				return nil, fmt.Errorf("port range %q exceeds 10001 ports", item)
			}
			for port := start; port <= end; port++ {
				if err := add(port); err != nil {
					return nil, err
				}
			}
			continue
		}
		number, err := strconv.Atoi(item)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q", item)
		}
		if err := add(number); err != nil {
			return nil, err
		}
	}
	if len(ports) == 0 {
		return nil, errorsNew("no ports were provided")
	}
	return ports, nil
}

// ParseTarget expands a raw target into endpoint/port/SNI combinations.
func ParseTarget(raw string, opts Options) ([]ctscan.Target, error) {
	original := strings.TrimSpace(raw)
	if original == "" || strings.HasPrefix(original, "#") {
		return nil, nil
	}
	if before, _, ok := strings.Cut(original, " #"); ok {
		original = strings.TrimSpace(before)
	}
	if original == "" {
		return nil, nil
	}
	if len(opts.Ports) == 0 {
		opts.Ports = []uint16{443}
	}

	host, explicitPort, err := splitTarget(original)
	if err != nil {
		return nil, err
	}
	if _, network, err := net.ParseCIDR(host); err == nil {
		if explicitPort != 0 {
			return nil, fmt.Errorf("CIDR target %q cannot contain an inline port", original)
		}
		return expandCIDR(original, network, opts)
	}
	normalized, err := normalizeHost(host)
	if err != nil {
		return nil, fmt.Errorf("invalid target %q: %w", original, err)
	}
	ports := opts.Ports
	if explicitPort != 0 {
		ports = []uint16{explicitPort}
	}
	serverNames := opts.ServerNames
	if len(serverNames) == 0 {
		if net.ParseIP(normalized) == nil {
			serverNames = []string{normalized}
		} else {
			serverNames = []string{""}
		}
	}
	var targets []ctscan.Target
	for _, port := range ports {
		for _, serverName := range serverNames {
			normalizedSNI := ""
			if serverName != "" {
				normalizedSNI, err = NormalizeDNSName(serverName)
				if err != nil {
					return nil, fmt.Errorf("invalid SNI %q: %w", serverName, err)
				}
			}
			targets = append(targets, ctscan.Target{Input: raw, Host: normalized, Port: port, ServerName: normalizedSNI, StartTLS: opts.StartTLS})
		}
	}
	return targets, nil
}

func splitTarget(raw string) (string, uint16, error) {
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Hostname() == "" {
			return "", 0, fmt.Errorf("invalid URL")
		}
		port := uint16(0)
		if parsed.Port() != "" {
			number, err := strconv.Atoi(parsed.Port())
			if err != nil || number < 1 || number > 65535 {
				return "", 0, fmt.Errorf("invalid URL port")
			}
			port = uint16(number)
		}
		return parsed.Hostname(), port, nil
	}
	if net.ParseIP(strings.Trim(raw, "[]")) != nil {
		return strings.Trim(raw, "[]"), 0, nil
	}
	if host, portValue, err := net.SplitHostPort(raw); err == nil {
		number, err := strconv.Atoi(portValue)
		if err != nil || number < 1 || number > 65535 {
			return "", 0, fmt.Errorf("invalid port %q", portValue)
		}
		return host, uint16(number), nil
	}
	if strings.Count(raw, ":") == 1 {
		host, portValue, _ := strings.Cut(raw, ":")
		if number, err := strconv.Atoi(portValue); err == nil {
			if number < 1 || number > 65535 {
				return "", 0, fmt.Errorf("invalid port %q", portValue)
			}
			return host, uint16(number), nil
		}
	}
	return raw, 0, nil
}

func normalizeHost(host string) (string, error) {
	host = strings.TrimSpace(strings.TrimSuffix(host, "."))
	if host == "" || strings.ContainsAny(host, " \t\r\n/\\") {
		return "", errorsNew("host is empty or contains invalid characters")
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return ip.String(), nil
	}
	return NormalizeDNSName(host)
}

// NormalizeDNSName returns a lowercase ASCII hostname and removes a wildcard
// prefix so the result can be resolved and scanned.
func NormalizeDNSName(name string) (string, error) {
	name = strings.TrimSpace(strings.TrimSuffix(strings.ToLower(name), "."))
	name = strings.TrimPrefix(name, "*.")
	if name == "" || strings.ContainsAny(name, " \t\r\n/\\") {
		return "", errorsNew("DNS name is empty or contains invalid characters")
	}
	ascii, err := idna.Lookup.ToASCII(name)
	if err != nil {
		return "", err
	}
	if len(ascii) > 253 {
		return "", errorsNew("DNS name exceeds 253 bytes")
	}
	for _, label := range strings.Split(ascii, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("invalid DNS label %q", label)
		}
	}
	return ascii, nil
}

func expandCIDR(original string, network *net.IPNet, opts Options) ([]ctscan.Target, error) {
	var addresses []string
	for ip := append(net.IP(nil), network.IP...); network.Contains(ip); incrementIP(ip) {
		if !opts.AllowLargeRange && len(addresses) >= defaultCIDRLimit {
			return nil, fmt.Errorf("CIDR %q exceeds %d addresses; use --allow-large-range", original, defaultCIDRLimit)
		}
		addresses = append(addresses, ip.String())
	}
	var targets []ctscan.Target
	for _, address := range addresses {
		for _, port := range opts.Ports {
			serverNames := opts.ServerNames
			if len(serverNames) == 0 {
				serverNames = []string{""}
			}
			for _, serverName := range serverNames {
				normalizedSNI := ""
				if serverName != "" {
					var err error
					normalizedSNI, err = NormalizeDNSName(serverName)
					if err != nil {
						return nil, err
					}
				}
				targets = append(targets, ctscan.Target{Input: original, Host: address, Address: address, Port: port, ServerName: normalizedSNI, StartTLS: opts.StartTLS})
			}
		}
	}
	return targets, nil
}

func incrementIP(ip net.IP) {
	for index := len(ip) - 1; index >= 0; index-- {
		ip[index]++
		if ip[index] != 0 {
			break
		}
	}
}

// ReadLines consumes newline- and comma-delimited targets with a raised token
// limit so unusually large generated records fail explicitly rather than vanish.
func ReadLines(reader io.Reader, emit func(string) error) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		for _, item := range strings.Split(line, ",") {
			if err := emit(item); err != nil {
				return err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read targets: %w", err)
	}
	return nil
}

func ReadFile(path string, emit func(string) error) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open target list %q: %w", path, err)
	}
	defer file.Close()
	return ReadLines(file, emit)
}

// Resolve resolves a parsed target, optionally returning every address.
func Resolve(ctx context.Context, resolver *net.Resolver, target ctscan.Target, all bool) ([]ctscan.Target, error) {
	if target.Address != "" || net.ParseIP(target.Host) != nil {
		if target.Address == "" {
			target.Address = target.Host
		}
		return []ctscan.Target{target}, nil
	}
	addresses, err := resolver.LookupIPAddr(ctx, target.Host)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("DNS returned no addresses for %s", target.Host)
	}
	if !all {
		addresses = addresses[:1]
	}
	resolved := make([]ctscan.Target, 0, len(addresses))
	for _, address := range addresses {
		copyTarget := target
		copyTarget.Address = address.IP.String()
		resolved = append(resolved, copyTarget)
	}
	return resolved, nil
}

// Resolver creates a DNS resolver using the supplied host:port, or the system
// resolver when address is empty.
func Resolver(address string) (*net.Resolver, error) {
	if address == "" {
		return net.DefaultResolver, nil
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		address = net.JoinHostPort(address, "53")
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dialer := net.Dialer{}
			protocol := "udp"
			if strings.HasPrefix(network, "tcp") {
				protocol = "tcp"
			}
			return dialer.DialContext(ctx, protocol, address)
		},
	}, nil
}

// InScope checks a hostname against exact or subdomain suffix scopes.
func InScope(name string, scopes []string) bool {
	normalized, err := NormalizeDNSName(name)
	if err != nil {
		return false
	}
	for _, scope := range scopes {
		normalizedScope, err := NormalizeDNSName(scope)
		if err == nil && (normalized == normalizedScope || strings.HasSuffix(normalized, "."+normalizedScope)) {
			return true
		}
	}
	return false
}

func errorsNew(message string) error { return fmt.Errorf("%s", message) }
