// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

// Live-progress tuning. The bar width is fixed so the line length is stable
// (important for clean in-place redraws). TTY redraws are frequent enough that
// the elapsed/ETA fields advance smoothly even while a rate-limited scan sits
// between results; the non-TTY cadence is slow so piped/CI logs stay readable.
const (
	progressBarWidth     = 24
	progressTTYInterval  = 150 * time.Millisecond
	progressPipeInterval = 2 * time.Second
)

// progressReporter renders a live progress indicator for long-running enum
// scans. On a TTY it redraws a single line in place (carriage return + clear
// to end of line); off a TTY it emits a throttled newline line so piped/CI
// logs stay readable. It is suppressed entirely (every method a no-op) when
// disabled — used for --quiet and --json, which own stderr/stdout framing.
//
// The render cadence is decoupled from Update: a background goroutine redraws
// on a timer, so the elapsed/ETA fields keep advancing between results. Update
// only stores a cheap snapshot, so it is safe to call from the enumerator's
// serialized onResult callback on the hot path.
//
// All exported methods are safe for concurrent use.
type progressReporter struct {
	w        io.Writer
	total    int
	enabled  bool
	isTTY    bool
	useColor bool
	interval time.Duration

	// now is the clock; overridable by tests for deterministic elapsed/ETA.
	now func() time.Time

	mu        sync.Mutex
	start     time.Time
	processed int
	metrics   string
	onScreen  bool // a TTY bar line is currently drawn (needs clearing)
	stopped   bool // Stop has run; guards close(done) against a double call

	done chan struct{}
	wg   sync.WaitGroup
}

// newProgressReporter builds a reporter writing to w (typically os.Stderr).
// enabled is the caller's gate (false under --quiet/--json). TTY detection is
// best-effort: when w is not a terminal (piped, redirected, or not an *os.File)
// the reporter falls back to throttled newline lines.
func newProgressReporter(w io.Writer, total int, enabled, useColor bool) *progressReporter {
	isTTY := enabled && writerIsTerminal(w)
	interval := progressPipeInterval
	if isTTY {
		interval = progressTTYInterval
	}
	return &progressReporter{
		w:        w,
		total:    total,
		enabled:  enabled,
		isTTY:    isTTY,
		useColor: useColor,
		interval: interval,
		now:      time.Now,
		done:     make(chan struct{}),
	}
}

// writerIsTerminal reports whether w refers to a terminal. It recognizes any
// writer exposing an Fd() (notably *os.File) so tests using a bytes.Buffer are
// treated as non-TTY.
func writerIsTerminal(w io.Writer) bool {
	f, ok := w.(interface{ Fd() uintptr })
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

// Start records the start time and launches the background redraw goroutine.
// It is a no-op when disabled. Call Stop exactly once when the work finishes.
func (p *progressReporter) Start() {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	p.start = p.now()
	p.mu.Unlock()

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		t := time.NewTicker(p.interval)
		defer t.Stop()
		for {
			select {
			case <-p.done:
				return
			case <-t.C:
				p.flush(false)
			}
		}
	}()
}

// Update records the latest processed count and metrics tail (e.g. "8 found").
// It does not render — the background goroutine does — so it is cheap enough
// for the per-result hot path. No-op when disabled.
//
// metrics MUST be composed only of counts and fixed strings; it MUST NOT carry
// untrusted server-/target-controlled data (e.g. a GitHub login), because the
// reporter writes it to the terminal verbatim alongside raw ANSI control
// sequences (\r\033[K).
func (p *progressReporter) Update(processed int, metrics string) {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	p.processed = processed
	p.metrics = metrics
	p.mu.Unlock()
}

// Clear erases the current in-place bar line so the caller can print a result
// row to the (shared) terminal without corrupting it; the bar redraws on the
// next tick. No-op when disabled or off-TTY (where lines never redraw in place).
//
// Callers print the result row to stdout after Clear returns and the lock is
// released, so the background ticker may redraw the bar in that small window.
// This is a cosmetic interleave that self-heals on the next tick, not a data
// race (the bar and the result row are separate streams).
func (p *progressReporter) Clear() {
	if !p.enabled || !p.isTTY {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.onScreen {
		_, _ = fmt.Fprint(p.w, "\r\033[K")
		p.onScreen = false
	}
}

// Stop halts the background goroutine and renders a final line terminated with
// a newline so subsequent output starts cleanly. No-op when disabled. Idempotent:
// a second call is a safe no-op so a future double-call/backstop can't panic on
// close(done).
func (p *progressReporter) Stop() {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return
	}
	p.stopped = true
	p.mu.Unlock()
	close(p.done)
	p.wg.Wait()
	p.flush(true)
}

// flush renders the current snapshot. On a TTY non-final renders redraw the
// line in place (\r + clear) with no trailing newline; the final render adds a
// newline. Off-TTY every render is a full newline line.
func (p *progressReporter) flush(final bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	elapsed := time.Duration(0)
	if !p.start.IsZero() {
		elapsed = p.now().Sub(p.start)
	}
	line := dim(p.useColor, progressLine(p.processed, p.total, elapsed, p.metrics))

	if p.isTTY {
		_, _ = fmt.Fprint(p.w, "\r\033[K"+line)
		p.onScreen = true
		if final {
			_, _ = fmt.Fprint(p.w, "\n")
			p.onScreen = false
		}
		return
	}
	_, _ = fmt.Fprint(p.w, line+"\n")
}

// progressLine builds the human-readable progress content (no color, no
// carriage return). Pure and deterministic given its inputs, so it is unit
// tested directly. Layout:
//
//	[*] [=====>    ] 42% · 4200/10000 · 38/s · elapsed 1m50s · ETA 2m32s · 8 found
//
// When total is 0 (unknown size) the bar, percentage, and ETA are omitted.
func progressLine(processed, total int, elapsed time.Duration, metrics string) string {
	var b strings.Builder
	b.WriteString(SymbolInfo)

	if total > 0 {
		frac := float64(processed) / float64(total)
		if frac > 1 {
			frac = 1
		}
		filled := int(frac * progressBarWidth)
		b.WriteString(" [")
		for i := 0; i < progressBarWidth; i++ {
			switch {
			case i < filled:
				b.WriteByte('=')
			case i == filled:
				b.WriteByte('>')
			default:
				b.WriteByte(' ')
			}
		}
		b.WriteString("]")
		fmt.Fprintf(&b, " %d%%", int(frac*100))
		fmt.Fprintf(&b, " · %d/%d", processed, total)
	} else {
		fmt.Fprintf(&b, " %d", processed)
	}

	fmt.Fprintf(&b, " · %s", progressRate(processed, elapsed))
	fmt.Fprintf(&b, " · elapsed %s", formatDuration(elapsed))

	if total > 0 {
		fmt.Fprintf(&b, " · ETA %s", progressETA(processed, total, elapsed))
	}

	if metrics != "" {
		fmt.Fprintf(&b, " · %s", metrics)
	}
	return b.String()
}

// progressRate formats throughput as items/second. Below 10/s it keeps one
// decimal so a slow, rate-limited scan still shows movement.
func progressRate(processed int, elapsed time.Duration) string {
	secs := elapsed.Seconds()
	if processed <= 0 || secs <= 0 {
		return "--/s"
	}
	rate := float64(processed) / secs
	if rate >= 10 {
		return fmt.Sprintf("%.0f/s", rate)
	}
	return fmt.Sprintf("%.1f/s", rate)
}

// progressETA estimates time remaining from the average rate so far. Returns
// "--" before any progress (no rate to extrapolate from) or once complete.
func progressETA(processed, total int, elapsed time.Duration) string {
	secs := elapsed.Seconds()
	if processed <= 0 || secs <= 0 || processed >= total {
		return "--"
	}
	rate := float64(processed) / secs
	remaining := float64(total-processed) / rate
	return formatDuration(time.Duration(remaining * float64(time.Second)))
}

// formatDuration renders a coarse, human-friendly duration: "45s", "2m32s",
// "1h03m" (seconds dropped past an hour). Sub-second renders as "0s".
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return "0s"
	}
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	switch {
	case h > 0:
		return fmt.Sprintf("%dh%02dm", h, m)
	case m > 0:
		return fmt.Sprintf("%dm%02ds", m, s)
	default:
		return fmt.Sprintf("%ds", s)
	}
}
