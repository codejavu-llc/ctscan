package cli

import (
	"fmt"
	"io"
	"sync"
	"time"
)

// scanProgress counts completed targets, independently of output filtering and
// ordering. Pivot scans start a new count for each newly discovered wave.
type scanProgress struct {
	mu        sync.Mutex
	writer    io.Writer
	remaining int
	lastPrint time.Time
}

func newScanProgress(writer io.Writer, total int) *scanProgress {
	p := &scanProgress{writer: writer, remaining: total}
	p.print()
	return p
}

func (p *scanProgress) complete() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.remaining--
	// Keep large scans quiet while always reporting the end of each wave.
	if p.remaining == 0 || time.Since(p.lastPrint) >= time.Second {
		p.print()
	}
}

func (p *scanProgress) print() {
	fmt.Fprintf(p.writer, "Objects left to scan: %d\n", p.remaining)
	p.lastPrint = time.Now()
}
