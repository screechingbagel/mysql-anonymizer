// Package progress wraps an io.Reader and periodically prints throughput to stderr.
package progress

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/docker/go-units"
)

// Reader is an io.Reader that counts bytes read. A background goroutine
// prints throughput statistics to w (typically os.Stderr) at the given interval.
type Reader struct {
	r        io.Reader
	total    atomic.Int64
	humanize bool
}

// New wraps r and starts the background reporting goroutine.
// If rhythm is zero, no reporting is performed.
// If humanize is true, sizes are printed in human-readable form (e.g. "12 MiB").
// The goroutine stops when the returned stop function is called.
func New(r io.Reader, w io.Writer, rhythm time.Duration, humanize bool) (*Reader, func()) {
	pr := &Reader{r: r, humanize: humanize}

	stop := func() {} // no-op default
	if rhythm > 0 {
		ticker := time.NewTicker(rhythm)
		done := make(chan struct{})
		var last int64

		go func() {
			for {
				select {
				case <-ticker.C:
					now := pr.total.Load()
					delta := now - last
					last = now
					pr.print(w, now, delta, rhythm)
				case <-done:
					ticker.Stop()
					return
				}
			}
		}()

		stop = func() {
			close(done)
		}
	}

	return pr, stop
}

// Read implements io.Reader, counting bytes as they pass through.
func (pr *Reader) Read(p []byte) (int, error) {
	n, err := pr.r.Read(p)
	if n > 0 {
		pr.total.Add(int64(n))
	}
	return n, err
}

// Total returns the total number of bytes read so far.
func (pr *Reader) Total() int64 {
	return pr.total.Load()
}

func (pr *Reader) print(w io.Writer, totalBytes, deltaBytes int64, rhythm time.Duration) {
	rate := float64(deltaBytes) / rhythm.Seconds()
	if pr.humanize {
		_, _ = fmt.Fprintf(w, "progress: %s read, %s/s\n",
			units.BytesSize(float64(totalBytes)),
			units.BytesSize(rate),
		)
	} else {
		_, _ = fmt.Fprintf(w, "progress: %d bytes read, %.0f bytes/s\n", totalBytes, rate)
	}
}
