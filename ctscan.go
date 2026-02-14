package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type Result struct {
	IP string
	CN string
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

	for ip := range jobs {
		address := net.JoinHostPort(ip, "443")

		conn, err := tls.DialWithDialer(dialer, "tcp", address, tlsConfig)
		if err != nil {
			results <- Result{IP: ip, CN: "ERROR"}
			atomic.AddInt64(remaining, -1)
			continue
		}

		state := conn.ConnectionState()
		conn.Close()

		if len(state.PeerCertificates) == 0 {
			results <- Result{IP: ip, CN: "NO_CERT"}
		} else {
			results <- Result{
				IP: ip,
				CN: state.PeerCertificates[0].Subject.CommonName,
			}
		}

		atomic.AddInt64(remaining, -1)
	}
}

func main() {
	// CLI flags
	listFile := flag.String("l", "", "IP list file")
	concurrency := flag.Int("c", 100, "Concurrency level")
	timeoutSec := flag.Int("t", 3, "Timeout in seconds")
	outputFile := flag.String("o", "output.txt", "Output file")
	flag.Parse()

	if *listFile == "" {
		fmt.Println("Usage: ./ctscan -l ips.txt -c 100 -t 3 -o output.txt")
		os.Exit(1)
	}

	// Read IPs
	file, err := os.Open(*listFile)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	var ips []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ips = append(ips, scanner.Text())
	}

	total := int64(len(ips))
	remaining := total

	// Output file
	out, err := os.Create(*outputFile)
	if err != nil {
		panic(err)
	}
	defer out.Close()
	writer := bufio.NewWriter(out)
	defer writer.Flush()

	jobs := make(chan string, 1000)
	results := make(chan Result, 1000)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	timeout := time.Duration(*timeoutSec) * time.Second

	var wg sync.WaitGroup
	start := time.Now()

	// Workers
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go worker(&wg, jobs, results, tlsConfig, timeout, &remaining)
	}

	// Feed jobs
	go func() {
		for _, ip := range ips {
			jobs <- ip
		}
		close(jobs)
	}()

	// Close results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Progress ticker
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			left := atomic.LoadInt64(&remaining)
			fmt.Printf("\rIPs left: %d", left)
			if left <= 0 {
				fmt.Print("\rIPs left: 0\n")
				return
			}
		}
	}()

	// Collect results
	count := 0
	for res := range results {
		fmt.Fprintf(writer, "%s -> %s\n", res.IP, res.CN)
		count++
	}

	elapsed := time.Since(start)
	fmt.Printf(
		"Done. Scanned %d IPs in %s (%.2f IPs/sec)\n",
		count,
		elapsed,
		float64(count)/elapsed.Seconds(),
	)
}
