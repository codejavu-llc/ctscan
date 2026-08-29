package ctscan

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	xproxy "golang.org/x/net/proxy"
)

const (
	defaultPort = 443
	maxRetries  = 10
)

var (
	errNoCertificate = errors.New("server did not present a certificate")
	sctOID           = []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)

// NewScanner validates cfg and constructs a concurrency-safe scanner.
func NewScanner(cfg Config) (*Scanner, error) {
	if cfg.Concurrency == 0 {
		cfg.Concurrency = DefaultConfig().Concurrency
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultConfig().Timeout
	}
	if cfg.Concurrency < 1 || cfg.Concurrency > 100_000 {
		return nil, fmt.Errorf("concurrency must be between 1 and 100000")
	}
	if cfg.Timeout < time.Millisecond {
		return nil, fmt.Errorf("timeout must be at least 1ms")
	}
	if cfg.Retries < 0 || cfg.Retries > maxRetries {
		return nil, fmt.Errorf("retries must be between 0 and %d", maxRetries)
	}
	if cfg.RateLimit < 0 {
		return nil, fmt.Errorf("rate limit cannot be negative")
	}
	if cfg.MinVersion != 0 && cfg.MaxVersion != 0 && cfg.MinVersion > cfg.MaxVersion {
		return nil, fmt.Errorf("minimum TLS version cannot exceed maximum TLS version")
	}

	dial, err := makeDialer(cfg)
	if err != nil {
		return nil, err
	}

	s := &Scanner{config: cfg, dial: dial, stop: func() {}}
	if cfg.RateLimit > 0 {
		period := time.Second / time.Duration(cfg.RateLimit)
		if period < time.Microsecond {
			period = time.Microsecond
		}
		ticker := time.NewTicker(period)
		s.rate = ticker.C
		s.stop = ticker.Stop
	}
	return s, nil
}

// Close releases the scanner's rate limiter. It is safe to call more than once.
func (s *Scanner) Close() { s.stop() }

func makeDialer(cfg Config) (func(context.Context, string, string) (net.Conn, error), error) {
	base := &net.Dialer{Timeout: cfg.Timeout, KeepAlive: -1}
	if cfg.ProxyURL == "" {
		return base.DialContext, nil
	}

	proxyURL, err := url.Parse(cfg.ProxyURL)
	if err != nil {
		return nil, fmt.Errorf("parse proxy URL: %w", err)
	}
	switch strings.ToLower(proxyURL.Scheme) {
	case "socks5", "socks5h":
		d, err := xproxy.FromURL(proxyURL, base)
		if err != nil {
			return nil, fmt.Errorf("configure SOCKS5 proxy: %w", err)
		}
		if cd, ok := d.(xproxy.ContextDialer); ok {
			return cd.DialContext, nil
		}
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			type response struct {
				conn net.Conn
				err  error
			}
			ch := make(chan response, 1)
			go func() {
				conn, dialErr := d.Dial(network, address)
				ch <- response{conn: conn, err: dialErr}
			}()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case result := <-ch:
				return result.conn, result.err
			}
		}, nil
	case "http", "https":
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialHTTPProxy(ctx, base, proxyURL, address)
		}, nil
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", proxyURL.Scheme)
	}
}

func dialHTTPProxy(ctx context.Context, base *net.Dialer, proxyURL *url.URL, address string) (net.Conn, error) {
	proxyAddress := proxyURL.Host
	if _, _, err := net.SplitHostPort(proxyAddress); err != nil {
		port := "80"
		if proxyURL.Scheme == "https" {
			port = "443"
		}
		proxyAddress = net.JoinHostPort(proxyAddress, port)
	}
	conn, err := base.DialContext(ctx, "tcp", proxyAddress)
	if err != nil {
		return nil, err
	}
	if proxyURL.Scheme == "https" {
		host, _, _ := net.SplitHostPort(proxyAddress)
		tlsConn := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("TLS handshake with proxy: %w", err)
		}
		conn = tlsConn
	}

	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: address}, Host: address, Header: make(http.Header)}
	if proxyURL.User != nil {
		password, _ := proxyURL.User.Password()
		credentials := base64.StdEncoding.EncodeToString([]byte(proxyURL.User.Username() + ":" + password))
		req.Header.Set("Proxy-Authorization", "Basic "+credentials)
	}
	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("proxy CONNECT returned %s", resp.Status)
	}
	return conn, nil
}

// Scan performs one TLS handshake and returns all data available from it.
func (s *Scanner) Scan(ctx context.Context, target Target) Result {
	started := time.Now()
	result := baseResult(target, started)
	if target.Port == 0 {
		target.Port = defaultPort
		result.Port = defaultPort
	}
	if target.Host == "" && target.Address == "" {
		result.Error = &ScanError{Kind: "invalid_input", Message: "target host is empty"}
		return finishResult(result, started)
	}

	var lastErr error
	for attempt := 0; attempt <= s.config.Retries; attempt++ {
		if err := s.waitRate(ctx); err != nil {
			lastErr = err
			break
		}
		if attempt > 0 {
			delay := time.Duration(1<<min(attempt-1, 5)) * 100 * time.Millisecond
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				lastErr = ctx.Err()
				break
			case <-timer.C:
			}
			if ctx.Err() != nil {
				break
			}
		}

		attemptResult, err := s.scanOnce(ctx, target)
		if err == nil {
			attemptResult.Timestamp = result.Timestamp
			return finishResult(attemptResult, started)
		}
		lastErr = err
		if !isRetryable(err) {
			break
		}
	}

	result.Error = classifyError(lastErr)
	return finishResult(result, started)
}

func (s *Scanner) waitRate(ctx context.Context) error {
	if s.rate == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.rate:
		return nil
	}
}

func (s *Scanner) scanOnce(ctx context.Context, target Target) (Result, error) {
	return s.scanOnceWithTLS(ctx, target, s.config.MinVersion, s.config.MaxVersion, nil)
}

func (s *Scanner) scanOnceWithTLS(ctx context.Context, target Target, minVersion, maxVersion uint16, cipherSuites []uint16) (Result, error) {
	result := baseResult(target, time.Now())
	connectHost := target.Address
	if connectHost == "" {
		connectHost = target.Host
	}
	address := net.JoinHostPort(connectHost, fmt.Sprintf("%d", target.Port))
	dialCtx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()
	conn, err := s.dial(dialCtx, "tcp", address)
	if err != nil {
		return result, fmt.Errorf("dial %s: %w", address, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(s.config.Timeout))
	if remote, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		result.IP = remote.IP.String()
	}

	if target.StartTLS != "" {
		if err := negotiateStartTLS(conn, target.StartTLS); err != nil {
			return result, fmt.Errorf("starttls %s: %w", target.StartTLS, err)
		}
	}

	serverName := target.ServerName
	if serverName == "" && net.ParseIP(target.Host) == nil {
		serverName = target.Host
	}
	result.SNI = serverName
	clientCertRequested := false
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // Validation is performed independently below.
		ServerName:         serverName,
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
		CipherSuites:       cipherSuites,
		RootCAs:            s.config.RootCAs,
		NextProtos:         []string{"h2", "http/1.1"},
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			clientCertRequested = true
			return &tls.Certificate{}, nil
		},
	}
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		return result, fmt.Errorf("TLS handshake: %w", err)
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return result, errNoCertificate
	}

	result.Status = "success"
	keyExchange := ""
	if state.CurveID != 0 {
		keyExchange = state.CurveID.String()
	}
	result.TLS = &TLSInfo{
		Version:            tlsVersionName(state.Version),
		Cipher:             tls.CipherSuiteName(state.CipherSuite),
		KeyExchange:        keyExchange,
		ALPN:               state.NegotiatedProtocol,
		DidResume:          state.DidResume,
		HandshakeComplete:  state.HandshakeComplete,
		OCSPStapled:        len(state.OCSPResponse) > 0,
		ClientCertRequired: clientCertRequested,
	}
	result.Certificate = certificateInfo(state.PeerCertificates[0], time.Now())
	result.Chain = make([]Certificate, 0, len(state.PeerCertificates))
	for _, cert := range state.PeerCertificates {
		result.Chain = append(result.Chain, *certificateInfo(cert, time.Now()))
	}
	expectedName := serverName
	if expectedName == "" {
		expectedName = target.Host
	}
	result.Validation = validateCertificate(state.PeerCertificates, expectedName, s.config.RootCAs, time.Now())
	result.Findings = certificateFindings(result.Certificate, result.Validation)
	return result, nil
}

// ScanStream scans targets with bounded worker concurrency. The returned
// channel closes when input is exhausted or ctx is canceled; cancellation may
// leave queued targets unprocessed.
func (s *Scanner) ScanStream(ctx context.Context, targets <-chan Target) <-chan Result {
	results := make(chan Result, s.config.Concurrency)
	var workers sync.WaitGroup
	workers.Add(s.config.Concurrency)
	for range s.config.Concurrency {
		go func() {
			defer workers.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case target, ok := <-targets:
					if !ok {
						return
					}
					result := s.Scan(ctx, target)
					select {
					case results <- result:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}
	go func() {
		workers.Wait()
		close(results)
	}()
	return results
}

func baseResult(target Target, timestamp time.Time) Result {
	return Result{
		SchemaVersion: SchemaVersion,
		Timestamp:     timestamp.UTC(),
		Input:         target.Input,
		Host:          target.Host,
		Port:          target.Port,
		SNI:           target.ServerName,
		StartTLS:      target.StartTLS,
		Status:        "failed",
	}
}

func finishResult(result Result, started time.Time) Result {
	result.DurationMS = time.Since(started).Milliseconds()
	return result
}

func certificateInfo(cert *x509.Certificate, now time.Time) *Certificate {
	info := &Certificate{
		Subject:            distinguishedName(cert.Subject.String(), cert.Subject.CommonName, cert.Subject.Organization, cert.Subject.OrganizationalUnit, cert.Subject.Country, cert.Subject.Province, cert.Subject.Locality),
		Issuer:             distinguishedName(cert.Issuer.String(), cert.Issuer.CommonName, cert.Issuer.Organization, cert.Issuer.OrganizationalUnit, cert.Issuer.Country, cert.Issuer.Province, cert.Issuer.Locality),
		DNSNames:           cloneStrings(cert.DNSNames),
		EmailAddresses:     cloneStrings(cert.EmailAddresses),
		SerialNumber:       strings.ToUpper(cert.SerialNumber.Text(16)),
		NotBefore:          cert.NotBefore.UTC(),
		NotAfter:           cert.NotAfter.UTC(),
		DaysRemaining:      int(time.Until(cert.NotAfter).Hours() / 24),
		FingerprintSHA256:  sha256Hex(cert.Raw),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		IsCA:               cert.IsCA,
	}
	info.DaysRemaining = int(cert.NotAfter.Sub(now).Hours() / 24)
	for _, ip := range cert.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}
	for _, uri := range cert.URIs {
		info.URIs = append(info.URIs, uri.String())
	}
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(sctOID) {
			info.HasSCT = true
			break
		}
	}
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		info.PublicKeyBits = key.N.BitLen()
	case *ecdsa.PublicKey:
		info.PublicKeyBits = key.Curve.Params().BitSize
	case ed25519.PublicKey:
		info.PublicKeyBits = len(key) * 8
	}
	return info
}

func distinguishedName(raw, cn string, org, ou, country, province, locality []string) DistinguishedName {
	return DistinguishedName{
		CommonName: cn, Organization: cloneStrings(org), OrganizationalUnit: cloneStrings(ou),
		Country: cloneStrings(country), Province: cloneStrings(province), Locality: cloneStrings(locality), String: raw,
	}
}

func validateCertificate(chain []*x509.Certificate, expectedName string, roots *x509.CertPool, now time.Time) *Validation {
	leaf := chain[0]
	validation := &Validation{
		Expired:     now.After(leaf.NotAfter),
		NotYetValid: now.Before(leaf.NotBefore),
		SelfSigned:  leaf.CheckSignatureFrom(leaf) == nil && leaf.RawSubject != nil && string(leaf.RawSubject) == string(leaf.RawIssuer),
	}
	if expectedName != "" {
		if err := leaf.VerifyHostname(expectedName); err != nil {
			validation.HostnameError = err.Error()
		} else {
			validation.HostnameMatch = true
		}
	}
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	_, err := leaf.Verify(x509.VerifyOptions{DNSName: expectedName, Roots: roots, Intermediates: intermediates, CurrentTime: now})
	if err != nil {
		validation.TrustError = err.Error()
	} else {
		validation.Trusted = true
		validation.ChainComplete = true
	}
	return validation
}

func certificateFindings(cert *Certificate, validation *Validation) []Finding {
	if cert == nil || validation == nil {
		return nil
	}
	findings := make([]Finding, 0, 6)
	references := []string{
		"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security",
		"https://datatracker.ietf.org/doc/html/rfc5280",
	}
	add := func(id, severity, title, evidence, remediation string) {
		findings = append(findings, Finding{ID: id, Severity: severity, Title: title, Evidence: evidence, Remediation: remediation, References: references})
	}
	if validation.Expired {
		add("cert-expired", "high", "Certificate is expired", cert.NotAfter.Format(time.RFC3339), "Replace the certificate and deploy the complete chain.")
	} else if validation.NotYetValid {
		add("cert-not-yet-valid", "high", "Certificate is not yet valid", cert.NotBefore.Format(time.RFC3339), "Deploy a certificate whose validity period includes the current time.")
	} else if cert.DaysRemaining < 7 {
		add("cert-expiry-critical", "high", "Certificate expires within 7 days", fmt.Sprintf("%d days remaining", cert.DaysRemaining), "Renew and deploy the certificate immediately.")
	} else if cert.DaysRemaining < 30 {
		add("cert-expiry-soon", "medium", "Certificate expires within 30 days", fmt.Sprintf("%d days remaining", cert.DaysRemaining), "Schedule certificate renewal.")
	}
	if !validation.HostnameMatch {
		add("cert-hostname-mismatch", "high", "Certificate does not match the requested identity", validation.HostnameError, "Deploy a certificate containing the requested DNS name or IP SAN.")
	}
	if validation.SelfSigned {
		add("cert-self-signed", "medium", "Certificate is self-signed", cert.Subject.String, "Use a certificate issued by an appropriate trusted CA where public trust is required.")
	} else if !validation.Trusted {
		add("cert-untrusted", "medium", "Certificate chain is not trusted", validation.TrustError, "Deploy a complete chain anchored in an appropriate trust store.")
	}
	if cert.PublicKeyAlgorithm == "RSA" && cert.PublicKeyBits > 0 && cert.PublicKeyBits < 2048 {
		add("cert-weak-rsa-key", "high", "Certificate uses a weak RSA key", fmt.Sprintf("%d bits", cert.PublicKeyBits), "Replace it with at least a 2048-bit RSA key or a suitable modern elliptic-curve key.")
	}
	signature := strings.ToUpper(cert.SignatureAlgorithm)
	if strings.Contains(signature, "MD5") || strings.Contains(signature, "SHA1") {
		add("cert-weak-signature", "high", "Certificate uses a deprecated signature algorithm", cert.SignatureAlgorithm, "Reissue the certificate using SHA-256 or stronger.")
	}
	return findings
}

func sha256Hex(data []byte) string {
	// x509 fingerprints are intentionally rendered without separators for easy joins.
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return append([]string(nil), values...)
}

func classifyError(err error) *ScanError {
	if err == nil {
		return &ScanError{Kind: "internal", Message: "unknown scan failure"}
	}
	kind := "tls_handshake"
	retryable := isRetryable(err)
	var dnsErr *net.DNSError
	var opErr *net.OpError
	switch {
	case errors.Is(err, context.Canceled):
		kind = "canceled"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &opErr) && opErr.Timeout():
		kind = "connect_timeout"
	case errors.As(err, &dnsErr):
		kind = "dns"
	case errors.Is(err, errNoCertificate):
		kind = "no_certificate"
	case strings.Contains(strings.ToLower(err.Error()), "connection refused"):
		kind = "connect_refused"
	case strings.Contains(strings.ToLower(err.Error()), "proxy"):
		kind = "proxy"
	case strings.Contains(strings.ToLower(err.Error()), "starttls"):
		kind = "starttls"
	}
	return &ScanError{Kind: kind, Message: err.Error(), Retryable: retryable}
}

func isRetryable(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "connection reset") || strings.Contains(message, "unexpected eof") || strings.Contains(message, "temporarily unavailable")
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

func negotiateStartTLS(conn net.Conn, protocol string) error {
	reader := bufio.NewReader(conn)
	write := func(value string) error {
		_, err := io.WriteString(conn, value)
		return err
	}
	readLine := func() (string, error) {
		line, err := reader.ReadString('\n')
		return strings.TrimSpace(line), err
	}
	readSMTPReply := func() (string, error) {
		var last string
		for range 100 {
			line, err := readLine()
			if err != nil {
				return line, err
			}
			last = line
			if len(line) < 4 || line[3] != '-' {
				return last, nil
			}
		}
		return last, errors.New("SMTP response exceeded 100 lines")
	}

	switch strings.ToLower(protocol) {
	case "smtp":
		line, err := readSMTPReply()
		if err != nil || !strings.HasPrefix(line, "220") {
			return fmt.Errorf("unexpected SMTP greeting %q: %w", line, err)
		}
		if err := write("EHLO ctscan\r\n"); err != nil {
			return err
		}
		if line, err = readSMTPReply(); err != nil || !strings.HasPrefix(line, "250") {
			return fmt.Errorf("SMTP EHLO failed %q: %w", line, err)
		}
		if err := write("STARTTLS\r\n"); err != nil {
			return err
		}
		if line, err = readSMTPReply(); err != nil || !strings.HasPrefix(line, "220") {
			return fmt.Errorf("SMTP STARTTLS rejected %q: %w", line, err)
		}
	case "imap":
		line, err := readLine()
		if err != nil || !strings.HasPrefix(strings.ToUpper(line), "* OK") {
			return fmt.Errorf("unexpected IMAP greeting %q: %w", line, err)
		}
		if err := write("a001 STARTTLS\r\n"); err != nil {
			return err
		}
		line, err = readLine()
		if err != nil || !strings.HasPrefix(strings.ToUpper(line), "A001 OK") {
			return fmt.Errorf("IMAP STARTTLS rejected %q: %w", line, err)
		}
	case "pop3":
		line, err := readLine()
		if err != nil || !strings.HasPrefix(strings.ToUpper(line), "+OK") {
			return fmt.Errorf("unexpected POP3 greeting %q: %w", line, err)
		}
		if err := write("STLS\r\n"); err != nil {
			return err
		}
		line, err = readLine()
		if err != nil || !strings.HasPrefix(strings.ToUpper(line), "+OK") {
			return fmt.Errorf("POP3 STLS rejected %q: %w", line, err)
		}
	case "ftp":
		line, err := readSMTPReply()
		if err != nil || !strings.HasPrefix(line, "220") {
			return fmt.Errorf("unexpected FTP greeting %q: %w", line, err)
		}
		if err := write("AUTH TLS\r\n"); err != nil {
			return err
		}
		line, err = readSMTPReply()
		if err != nil || (!strings.HasPrefix(line, "234") && !strings.HasPrefix(line, "334")) {
			return fmt.Errorf("FTP AUTH TLS rejected %q: %w", line, err)
		}
	case "postgres", "postgresql":
		request := make([]byte, 8)
		binary.BigEndian.PutUint32(request[0:4], 8)
		binary.BigEndian.PutUint32(request[4:8], 80877103)
		if _, err := conn.Write(request); err != nil {
			return err
		}
		answer := []byte{0}
		if _, err := io.ReadFull(reader, answer); err != nil {
			return err
		}
		if answer[0] != 'S' {
			return fmt.Errorf("PostgreSQL server returned %q instead of S", answer[0])
		}
	case "ldap":
		request := []byte{0x30, 0x1d, 0x02, 0x01, 0x01, 0x77, 0x18, 0x80, 0x16}
		request = append(request, []byte("1.3.6.1.4.1.1466.20037")...)
		if _, err := conn.Write(request); err != nil {
			return err
		}
		response := make([]byte, 4096)
		n, err := reader.Read(response)
		if err != nil {
			return err
		}
		if !containsBytes(response[:n], []byte{0x0a, 0x01, 0x00}) {
			return errors.New("LDAP StartTLS response was not successful")
		}
	case "mysql":
		if err := negotiateMySQL(conn, reader); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported protocol %q", protocol)
	}
	return nil
}

func negotiateMySQL(conn net.Conn, reader *bufio.Reader) error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return err
	}
	length := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if length < 18 || length > 1<<20 {
		return fmt.Errorf("invalid MySQL greeting length %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return err
	}
	if payload[0] == 0xff {
		return errors.New("MySQL server returned an error greeting")
	}
	zero := indexByte(payload[1:], 0)
	if zero < 0 {
		return errors.New("invalid MySQL server version")
	}
	capOffset := 1 + zero + 1 + 4 + 8 + 1
	if capOffset+2 > len(payload) {
		return errors.New("truncated MySQL greeting")
	}
	capabilities := uint32(binary.LittleEndian.Uint16(payload[capOffset : capOffset+2]))
	if capOffset+7 < len(payload) {
		capabilities |= uint32(binary.LittleEndian.Uint16(payload[capOffset+5:capOffset+7])) << 16
	}
	const (
		clientLongPassword     = 0x00000001
		clientLongFlag         = 0x00000004
		clientProtocol41       = 0x00000200
		clientSSL              = 0x00000800
		clientTransactions     = 0x00002000
		clientSecureConnection = 0x00008000
	)
	if capabilities&clientSSL == 0 {
		return errors.New("MySQL server does not advertise TLS")
	}
	requested := uint32(clientLongPassword | clientLongFlag | clientProtocol41 | clientSSL | clientTransactions | clientSecureConnection)
	sslRequest := make([]byte, 4+32)
	sslRequest[0] = 32
	sslRequest[3] = 1
	binary.LittleEndian.PutUint32(sslRequest[4:8], requested)
	binary.LittleEndian.PutUint32(sslRequest[8:12], 16*1024*1024)
	sslRequest[12] = 0x21
	_, err := conn.Write(sslRequest)
	return err
}

func containsBytes(data, pattern []byte) bool {
	if len(pattern) == 0 {
		return true
	}
	for i := 0; i+len(pattern) <= len(data); i++ {
		matched := true
		for j := range pattern {
			if data[i+j] != pattern[j] {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func indexByte(data []byte, value byte) int {
	for i, candidate := range data {
		if candidate == value {
			return i
		}
	}
	return -1
}
