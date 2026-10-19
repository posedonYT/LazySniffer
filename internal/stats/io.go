package stats

import (
	"context"
	"fmt"
	"math"

	"github.com/poseydon/lazysniffer/internal/dfilter"
	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/engine"
	"github.com/poseydon/lazysniffer/internal/store"
)

// Metric is what an I/O graph series measures per interval.
type Metric int

const (
	Packets Metric = iota
	Bytes
	Bits
	Count // number of occurrences of Field
	Sum
	Min
	Max
	Avg
)

var MetricNames = []string{"Packets", "Bytes", "Bits", "COUNT(field)", "SUM(field)", "MIN(field)", "MAX(field)", "AVG(field)"}

func (m Metric) String() string { return MetricNames[m] }

// NeedsField reports whether the metric aggregates a field.
func (m Metric) NeedsField() bool { return m >= Count }

// IOSeries is one graph line: the packets matching Filter, measured by Metric.
type IOSeries struct {
	Name   string
	Filter string
	Metric Metric
	Field  string
}

// IOResult holds the values of every series per interval.
type IOResult struct {
	Interval int64 // ns
	Bins     int
	Series   [][]float64
	First    uint32 // first frame number of each bin (0 if none), per series
	StartTS  int64
}

// MaxBins bounds the graph resolution.
const MaxBins = 200000

// IO computes the series over the whole capture.
func IO(ctx context.Context, c *store.Capture, series []IOSeries, interval int64) (*IOResult, error) {
	n := c.Count()
	res := &IOResult{Interval: interval}
	if n == 0 || interval <= 0 {
		return res, nil
	}
	t0 := c.Frame(1).TS
	span := c.Frame(uint32(n)).TS - t0
	bins := int(span/interval) + 1
	if bins > MaxBins {
		return nil, fmt.Errorf("interval too small: %d intervals", bins)
	}
	res.Bins, res.StartTS = bins, t0
	type compiled struct {
		flt   *dfilter.Filter
		field *dissect.FieldDef
	}
	cs := make([]compiled, len(series))
	want := make([]bool, dissect.NumFields())
	for i, s := range series {
		if s.Filter != "" {
			f, err := dfilter.Compile(s.Filter)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", s.Name, err)
			}
			cs[i].flt = f
			f.Want(want)
		}
		if s.Metric.NeedsField() {
			fd := dissect.LookupField(s.Field)
			if fd == nil {
				return nil, fmt.Errorf("%s: unknown field %q", s.Name, s.Field)
			}
			cs[i].field = fd
			want[fd.ID] = true
		}
	}
	type acc struct{ sum, cnt, min, max []float64 }
	workers := engine.Workers()
	parts := make([][]acc, workers)
	for w := range parts {
		parts[w] = make([]acc, len(series))
		for i := range series {
			a := acc{make([]float64, bins), make([]float64, bins), make([]float64, bins), make([]float64, bins)}
			for b := range a.min {
				a.min[b] = math.Inf(1)
				a.max[b] = math.Inf(-1)
			}
			parts[w][i] = a
		}
	}
	err := engine.Each(ctx, c, dissect.Options{Want: want}, engine.AllFrames(c), func(w int, num uint32, pi *dissect.PacketInfo) {
		bin := int((pi.TS - t0) / interval)
		if bin < 0 || bin >= bins {
			return
		}
		for i, s := range series {
			if cs[i].flt != nil && !cs[i].flt.Match(pi) {
				continue
			}
			a := parts[w][i]
			switch s.Metric {
			case Packets:
				a.sum[bin]++
			case Bytes:
				a.sum[bin] += float64(pi.Len)
			case Bits:
				a.sum[bin] += float64(pi.Len) * 8
			default:
				for _, v := range pi.Tree.Values(cs[i].field) {
					x := v.V.F
					if v.V.T != dissect.FtFloat && v.V.T != dissect.FtDouble {
						x = float64(v.V.U)
						if v.V.T.IsSigned() {
							x = float64(v.V.Int())
						}
					}
					a.sum[bin] += x
					a.cnt[bin]++
					a.min[bin] = math.Min(a.min[bin], x)
					a.max[bin] = math.Max(a.max[bin], x)
				}
			}
		}
	})
	if err != nil {
		return nil, err
	}
	for i, s := range series {
		out := make([]float64, bins)
		for b := 0; b < bins; b++ {
			var sum, cnt float64
			mn, mx := math.Inf(1), math.Inf(-1)
			for w := range parts {
				a := parts[w][i]
				sum += a.sum[b]
				cnt += a.cnt[b]
				mn, mx = math.Min(mn, a.min[b]), math.Max(mx, a.max[b])
			}
			switch s.Metric {
			case Count:
				out[b] = cnt
			case Min:
				if cnt > 0 {
					out[b] = mn
				}
			case Max:
				if cnt > 0 {
					out[b] = mx
				}
			case Avg:
				if cnt > 0 {
					out[b] = sum / cnt
				}
			default:
				out[b] = sum
			}
		}
		res.Series = append(res.Series, out)
	}
	return res, nil
}
