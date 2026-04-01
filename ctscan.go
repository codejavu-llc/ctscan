package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Result struct {
	Target string
	CN     string
	SANs   []string
	Error  string
}

func worker(
	wg *sync.WaitGroup,
	jobs <-chan string,
	results chan<- Result,
	tlsConfig *tls.Config,
	timeout time.Duration,
	remaining *int64,
) {
	defer wg.Done()

	dialer := &net.Dialer{Timeout: timeout}

	for target := range jobs {
		address := net.JoinHostPort(target, "443")

		conf := tlsConfig.Clone()
		// Enable SNI if the target is not a raw IP
		if net.ParseIP(target) == nil {
			conf.ServerName = target
		}

		conn, err := tls.DialWithDialer(dialer, "tcp", address, conf)
		if err != nil {
			results <- Result{Target: target, Error: "DIAL_ERROR"}
			atomic.AddInt64(remaining, -1)
			continue
		}

		state := conn.ConnectionState()
		conn.Close()

		if len(state.PeerCertificates) == 0 {
			results <- Result{Target: target, Error: "NO_CERT"}
		} else {
			cert := state.PeerCertificates[0]
			var sans []string
			sans = append(sans, cert.DNSNames...)
			for _, ip := range cert.IPAddresses {
				sans = append(sans, ip.String())
			}

			results <- Result{
				Target: target,
				CN:     cert.Subject.CommonName,
				SANs:   sans,
			}
		}

		atomic.AddInt64(remaining, -1)
	}
}

func main() {
	listFile := flag.String("l", "", "Input list file (optional if using stdin)")
	concurrency := flag.Int("c", 100, "Concurrency level")
	timeoutSec := flag.Int("t", 3, "Timeout in seconds")
	outputFile := flag.String("o", "", "Output file (optional)")
	flag.Parse()

	var targets []string

	// Handle Stdin (cat hosts | ctscan)
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				targets = append(targets, line)
			}
		}
	}

	// Handle File Input if provided (overrides or appends to stdin)
	if *listFile != "" {
		file, err := os.Open(*listFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
			os.Exit(1)
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				targets = append(targets, line)
			}
		}
		file.Close()
	}

	if len(targets) == 0 {
		fmt.Println("No input targets found via stdin or -l")
		return
	}

	total := int64(len(targets))
	remaining := total

	// Prepare Output
	var writer *bufio.Writer
	if *outputFile != "" {
		out, err := os.Create(*outputFile)
		if err != nil {
			panic(err)
		}
		defer out.Close()
		writer = bufio.NewWriter(out)
		defer writer.Flush()
	}

	jobs := make(chan string, 1000)
	results := make(chan Result, 1000)
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	timeout := time.Duration(*timeoutSec) * time.Second

	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go worker(&wg, jobs, results, tlsConfig, timeout, &remaining)
	}

	go func() {
		for _, t := range targets {
			jobs <- t
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	// Progress indicator (Stderr to not pollute stdout)
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
			left := atomic.LoadInt64(&remaining)
			fmt.Fprintf(os.Stderr, "\rProgress: %d/%d targets remaining...", left, total)
			if left <= 0 {
				fmt.Fprintf(os.Stderr, "\rScanning complete.                    \n")
				return
			}
		}
	}()

	count := 0
	for res := range results {
		outputLine := ""
		if res.Error != "" {
			outputLine = fmt.Sprintf("[%s] Error: %s\n", res.Target, res.Error)
		} else {
			outputLine = fmt.Sprintf("[%s] CN: %s | SANs: [%s]\n", res.Target, res.CN, strings.Join(res.SANs, ", "))
		}

		// Print to stdout by default
		fmt.Print(outputLine)

		// Also write to file if -o is specified
		if writer != nil {
			writer.WriteString(outputLine)
		}
		count++
	}

	elapsed := time.Since(start)
	fmt.Fprintf(os.Stderr, "Scanned %d targets in %s (%.2f/sec)\n", count, elapsed, float64(count)/elapsed.Seconds())
}
