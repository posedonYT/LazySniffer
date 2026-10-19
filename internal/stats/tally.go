package stats

import (
	"context"
	"fmt"
	"math"

	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/engine"
	"github.com/poseydon/lazysniffer/internal/store"
)

// Tally counts the values of fields over the frames (all when nil): the
// result maps each field to value → occurrences.
func Tally(ctx context.Context, c *store.Capture, frames []uint32, fields ...string) (map[string]map[string]uint64, error) {
	if frames == nil {
		frames = engine.AllFrames(c)
	}
	fds := make([]*dissect.FieldDef, len(fields))
	want := make([]bool, dissect.NumFields())
	for i, f := range fields {
		fds[i] = dissect.LookupField(f)
		if fds[i] == nil {
			return nil, fmt.Errorf("unknown field %q", f)
		}
		want[fds[i].ID] = true
	}
	parts := make([][]map[string]uint64, engine.Workers())
	for w := range parts {
		parts[w] = make([]map[string]uint64, len(fields))
		for i := range fields {
			parts[w][i] = map[string]uint64{}
		}
	}
	err := engine.Each(ctx, c, dissect.Options{Want: want}, frames, func(w int, num uint32, pi *dissect.PacketInfo) {
		for i, fd := range fds {
			for _, v := range pi.Tree.Values(fd) {
				parts[w][i][fd.Display(v.V)]++
			}
		}
	})
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]uint64{}
	for i, f := range fields {
		m := map[string]uint64{}
		for w := range parts {
			for k, n := range parts[w][i] {
				m[k] += n
			}
		}
		out[f] = m
	}
	return out, nil
}

// NumStat summarizes a numeric field.
type NumStat struct {
	Count         uint64
	Min, Max, Sum float64
}

func (n NumStat) Avg() float64 {
	if n.Count == 0 {
		return 0
	}
	return n.Sum / float64(n.Count)
}

// Numeric summarizes a numeric (or relative time, in seconds) field.
func Numeric(ctx context.Context, c *store.Capture, frames []uint32, field string) (NumStat, error) {
	if frames == nil {
		frames = engine.AllFrames(c)
	}
	fd := dissect.LookupField(field)
	if fd == nil {
		return NumStat{}, fmt.Errorf("unknown field %q", field)
	}
	want := make([]bool, dissect.NumFields())
	want[fd.ID] = true
	parts := make([]NumStat, engine.Workers())
	for i := range parts {
		parts[i].Min = math.Inf(1)
	}
	err := engine.Each(ctx, c, dissect.Options{Want: want}, frames, func(w int, num uint32, pi *dissect.PacketInfo) {
		for _, v := range pi.Tree.Values(fd) {
			x := v.V.F
			switch v.V.T {
			case dissect.FtRelTime:
				x = float64(int64(v.V.U)) / 1e9
			case dissect.FtFloat, dissect.FtDouble:
			default:
				x = float64(v.V.U)
			}
			s := &parts[w]
			s.Count++
			s.Sum += x
			s.Min, s.Max = math.Min(s.Min, x), math.Max(s.Max, x)
		}
	})
	if err != nil {
		return NumStat{}, err
	}
	out := NumStat{Min: math.Inf(1)}
	for _, p := range parts {
		out.Count += p.Count
		out.Sum += p.Sum
		out.Min, out.Max = math.Min(out.Min, p.Min), math.Max(out.Max, p.Max)
	}
	if out.Count == 0 {
		out.Min = 0
	}
	return out, nil
}
