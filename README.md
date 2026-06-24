# ctscan

⚡ **ctscan** is a fast, concurrent TLS scanner written in Go that extracts the **Common Name (CN)** from TLS certificates on port **443**.

It is designed for **large-scale internet scanning** and can comfortably handle **hundreds of Hosts/IPs per second** on a typical VPS.

---

## Features

- 🔐 Extract TLS **Common Name (CN)**
- 🚀 High-performance concurrent scanning
- 📂 File-based IP input
- ⏱ Configurable timeout
- 🧵 Adjustable concurrency
- 📈 Live progress (Hosts/IPs left to scan)
- 📝 Output to file
- 💻 Single static binary

---

## Install

```bash
git clone https://github.com/codejavu-llc/ctscan.git
cd ctscan
go mod init && go mod tidy
go build -o ctscan ctscan.go
sudo cp ctscan /usr/local/bin # if you want to run the script from any 
```
## Usage

```bash
ctscan -l hostsorips.txt -c 100 -t 3 -o output.txt
echo google.com | ctscan
