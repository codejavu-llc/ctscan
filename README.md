# ctscan

⚡ **ctscan** is a fast, concurrent TLS scanner written in Go that extracts the **Common Name (CN)** from TLS certificates on port **443**.

It is designed for **large-scale internet scanning** and can comfortably handle **hundreds of IPs per second** on a typical VPS.

---

## Features

- 🔐 Extract TLS **Common Name (CN)**
- 🚀 High-performance concurrent scanning
- 📂 File-based IP input
- ⏱ Configurable timeout
- 🧵 Adjustable concurrency
- 📈 Live progress (IPs left to scan)
- 📝 Output to file
- 💻 Single static binary

---

## Build

```bash
go build -o ctscan ctscan.go
```
## Usage

```bash
./ctscan -l ips.txt -c 100 -t 3 -o output.txt
