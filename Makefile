BINARY := bin/ctscan
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X github.com/codejavu-llc/ctscan/internal/cli.Version=$(VERSION) -X github.com/codejavu-llc/ctscan/internal/cli.Commit=$(COMMIT) -X github.com/codejavu-llc/ctscan/internal/cli.Date=$(DATE)

.PHONY: build test test-race check benchmark clean

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) .

test:
	go test ./...

test-race:
	go test -race ./...

check:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test ./...

benchmark:
	go test -run '^$$' -bench . -benchmem ./...

clean:
	go clean
