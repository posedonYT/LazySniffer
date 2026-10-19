// Package engine runs work over all frames of a capture: display filtering,
// searching and statistics passes, spread across CPU cores.
package engine

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/poseydon/lazysniffer/internal/dfilter"
	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/store"
)

// Matcher decides whether a dissected frame is kept.
type Matcher func(pi *dissect.PacketInfo) bool

// WantFor builds a field-want vector for a filter.
func WantFor(f *dfilter.Filter, extra ...*dissect.FieldDef) []bool {
	want := make([]bool, dissect.NumFields())
	if f != nil {
		f.Want(want)
	}
	for _, e := range extra {
		want[e.ID] = true
	}
	return want
}

// Filter returns the frame numbers in [from, to] (1-based, inclusive) that
// match f, in order. progress receives the number of frames processed.
func Filter(ctx context.Context, c *store.Capture, f *dfilter.Filter, from, to uint32, progress func(done int)) ([]uint32, error) {
	if to < from {
		return nil, nil
	}
	if f == nil || f.Empty() {
		out := make([]uint32, 0, to-from+1)
		for n := from; n <= to; n++ {
			out = append(out, n)
		}
		return out, nil
	}
	return Scan(ctx, c, dissect.Options{Want: WantFor(f)}, from, to, f.Match, progress)
}

// Scan dissects frames in parallel and returns those accepted by match.
func Scan(ctx context.Context, c *store.Capture, opt dissect.Options, from, to uint32, match Matcher, progress func(done int)) ([]uint32, error) {
	total := int(to - from + 1)
	hits := make([]bool, total)
	workers := runtime.GOMAXPROCS(0)
	const chunk = 2048
	var next atomic.Int64
	var done atomic.Int64
	var wg sync.WaitGroup
	sess := c.Session()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wk := sess.NewWorker(opt)
			for {
				if ctx.Err() != nil {
					return
				}
				start := int(next.Add(chunk)) - chunk
				if start >= total {
					return
				}
				end := min(start+chunk, total)
				for i := start; i < end; i++ {
					fi := c.Input(from + uint32(i))
					if fi == nil {
						continue
					}
					hits[i] = match(wk.Dissect(fi))
				}
				n := done.Add(int64(end - start))
				if progress != nil {
					progress(int(n))
				}
			}
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out []uint32
	for i, h := range hits {
		if h {
			out = append(out, from+uint32(i))
		}
	}
	return out, nil
}

// Workers is the number of goroutines used by Each.
func Workers() int { return runtime.GOMAXPROCS(0) }

// Each dissects the given frames in parallel and calls fn with the worker
// index (0 ≤ w < Workers()), so callers can accumulate results per worker
// without locking. Frames are visited in increasing order within a worker.
func Each(ctx context.Context, c *store.Capture, opt dissect.Options, frames []uint32, fn func(w int, num uint32, pi *dissect.PacketInfo)) error {
	workers := Workers()
	const chunk = 2048
	var next atomic.Int64
	var wg sync.WaitGroup
	sess := c.Session()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			wk := sess.NewWorker(opt)
			for ctx.Err() == nil {
				start := int(next.Add(chunk)) - chunk
				if start >= len(frames) {
					return
				}
				for _, num := range frames[start:min(start+chunk, len(frames))] {
					if fi := c.Input(num); fi != nil {
						fn(w, num, wk.Dissect(fi))
					}
				}
			}
		}(w)
	}
	wg.Wait()
	return ctx.Err()
}

// AllFrames returns 1..Count().
func AllFrames(c *store.Capture) []uint32 {
	out := make([]uint32, c.Count())
	for i := range out {
		out[i] = uint32(i + 1)
	}
	return out
}
