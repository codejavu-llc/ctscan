package ctscan

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewScannerValidation(t *testing.T) {
	tests := []Config{
		{Concurrency: -1, Timeout: time.Second},
		{Concurrency: 1, Timeout: -1},
		{Concurrency: 1, Timeout: time.Second, Retries: -1},
		{Concurrency: 1, Timeout: time.Second, RateLimit: -1},
	}
	for _, config := range tests {
		if _, err := NewScanner(config); err == nil {
			t.Fatalf("expected error for %#v", config)
		}
	}
}

func TestScanLocalTLS(t *testing.T) {
	certificate, parsed := testCertificate(t, "localhost")
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err == nil {
			if tlsConn, ok := conn.(*tls.Conn); ok {
				_ = tlsConn.Handshake()
			}
			_ = conn.Close()
		}
	}()

	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	scanner, err := NewScanner(Config{Concurrency: 2, Timeout: 2 * time.Second, RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	defer scanner.Close()
	result := scanner.Scan(context.Background(), Target{Input: "localhost", Host: "localhost", Address: "127.0.0.1", Port: port, ServerName: "localhost"})
	<-done
	if result.Status != "success" || result.Error != nil {
		t.Fatalf("unexpected result: %#v", result)
	}
	if result.Certificate == nil || result.Certificate.Subject.CommonName != "localhost" {
		t.Fatalf("missing certificate: %#v", result.Certificate)
	}
	if result.TLS == nil || result.TLS.Version == "" || result.TLS.Cipher == "" {
		t.Fatalf("missing TLS metadata: %#v", result.TLS)
	}
	if result.Validation == nil || !result.Validation.Trusted || !result.Validation.HostnameMatch {
		t.Fatalf("unexpected validation: %#v", result.Validation)
	}
}

func TestSMTPStartTLSNegotiation(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(server)
		if _, err := io.WriteString(server, "220 mail.example ESMTP\r\n"); err != nil {
			done <- err
			return
		}
		line, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "EHLO") {
			done <- err
			return
		}
		_, _ = io.WriteString(server, "250-mail.example\r\n250 STARTTLS\r\n")
		line, err = reader.ReadString('\n')
		if err != nil || strings.TrimSpace(line) != "STARTTLS" {
			done <- err
			return
		}
		_, err = io.WriteString(server, "220 Ready to start TLS\r\n")
		done <- err
	}()
	if err := negotiateStartTLS(client, "smtp"); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestAuditEnumeratesModernVersions(t *testing.T) {
	certificate, parsed := testCertificate(t, "localhost")
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	var connections sync.WaitGroup
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer connections.Done()
				defer conn.Close()
				if tlsConn, ok := conn.(*tls.Conn); ok {
					_ = tlsConn.Handshake()
				}
			}()
		}
	}()
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	scanner, err := NewScanner(Config{Concurrency: 1, Timeout: 500 * time.Millisecond, RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	target := Target{Input: "localhost", Host: "localhost", Address: "127.0.0.1", Port: uint16(listener.Addr().(*net.TCPAddr).Port), ServerName: "localhost"}
	result := scanner.ScanAudit(context.Background(), target, AuditConfig{Profile: "intermediate", CipherConcurrency: 4})
	scanner.Close()
	_ = listener.Close()
	<-serverDone
	connections.Wait()
	if result.Status != "success" || result.Audit == nil {
		t.Fatalf("unexpected audit result %#v", result)
	}
	joined := strings.Join(result.Audit.SupportedVersions, ",")
	if !strings.Contains(joined, "TLS1.2") || !strings.Contains(joined, "TLS1.3") {
		t.Fatalf("unexpected versions %v", result.Audit.SupportedVersions)
	}
	if strings.Contains(joined, "TLS1.0") || strings.Contains(joined, "TLS1.1") {
		t.Fatalf("deprecated versions reported: %v", result.Audit.SupportedVersions)
	}
}

func TestHTTPProxyConnectAuthentication(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		request, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			serverDone <- err
			return
		}
		if request.Method != http.MethodConnect || request.Host != "example.com:443" {
			serverDone <- errors.New("unexpected CONNECT request")
			return
		}
		if request.Header.Get("Proxy-Authorization") != "Basic dXNlcjpwYXNz" {
			serverDone <- errors.New("missing proxy authorization")
			return
		}
		_, err = io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
		serverDone <- err
	}()
	proxyURL, _ := url.Parse("http://user:pass@" + listener.Addr().String())
	conn, err := dialHTTPProxy(context.Background(), &net.Dialer{Timeout: time.Second}, proxyURL, "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func testCertificate(t *testing.T, hostname string) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, parsed
}
