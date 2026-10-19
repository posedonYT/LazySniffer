package ui

import (
	"image/color"
	"math"
	"strings"

	"charm.land/lipgloss/v2"
)

// chartSeries is one line of a braille chart.
type chartSeries struct {
	vals  []float64
	color color.Color
	bold  bool
}

var brailleBits = [2][4]rune{{0x01, 0x02, 0x04, 0x40}, {0x08, 0x10, 0x20, 0x80}}

// brailleCanvas is a w×h cell canvas with 2×4 dots per cell.
type brailleCanvas struct {
	w, h  int
	bits  []rune
	color []color.Color
}

func newBraille(w, h int) *brailleCanvas {
	return &brailleCanvas{w: w, h: h, bits: make([]rune, w*h), color: make([]color.Color, w*h)}
}

func (c *brailleCanvas) set(x, y int, col color.Color) {
	if x < 0 || y < 0 || x >= c.w*2 || y >= c.h*4 {
		return
	}
	i := (y/4)*c.w + x/2
	c.bits[i] |= brailleBits[x%2][y%4]
	c.color[i] = col
}

// line draws a line between two dot coordinates (Bresenham).
func (c *brailleCanvas) line(x0, y0, x1, y1 int, col color.Color) {
	dx, dy := absInt(x1-x0), -absInt(y1-y0)
	sx, sy := 1, 1
	if x0 > x1 {
		sx = -1
	}
	if y0 > y1 {
		sy = -1
	}
	err := dx + dy
	for {
		c.set(x0, y0, col)
		if x0 == x1 && y0 == y1 {
			return
		}
		e2 := 2 * err
		if e2 >= dy {
			err += dy
			x0 += sx
		}
		if e2 <= dx {
			err += dx
			y0 += sy
		}
	}
}

func absInt(a int) int {
	if a < 0 {
		return -a
	}
	return a
}

// lines renders the canvas row by row.
func (c *brailleCanvas) lines() []string {
	out := make([]string, c.h)
	for y := 0; y < c.h; y++ {
		var b strings.Builder
		for x := 0; x < c.w; x++ {
			i := y*c.w + x
			if c.bits[i] == 0 {
				b.WriteByte(' ')
				continue
			}
			ch := string(0x2800 + c.bits[i])
			if c.color[i] != nil {
				b.WriteString(lipgloss.NewStyle().Foreground(c.color[i]).Render(ch))
			} else {
				b.WriteString(ch)
			}
		}
		out[y] = b.String()
	}
	return out
}

// plot draws the series into a w×h cell canvas. ymax is the top of the
// axis; with log the axis is logarithmic. Bins are resampled to the width
// (maximum of the bins sharing a dot column).
func plot(w, h int, series []chartSeries, ymax float64, log bool) []string {
	cv := newBraille(w, h)
	dotsW, dotsH := w*2, h*4
	scale := func(v float64) int {
		if v <= 0 || ymax <= 0 {
			return dotsH - 1
		}
		f := v / ymax
		if log {
			f = math.Log10(1+v) / math.Log10(1+ymax)
		}
		return dotsH - 1 - int(math.Min(f, 1)*float64(dotsH-1))
	}
	draw := func(s chartSeries) {
		n := len(s.vals)
		if n == 0 {
			return
		}
		prevX, prevY := -1, 0
		for x := 0; x < dotsW; x++ {
			lo := x * n / dotsW
			hi := max((x+1)*n/dotsW, lo+1)
			var v float64
			for _, b := range s.vals[lo:min(hi, n)] {
				v = math.Max(v, b)
			}
			y := scale(v)
			if prevX >= 0 {
				cv.line(prevX, prevY, x, y, s.color)
			} else {
				cv.set(x, y, s.color)
			}
			prevX, prevY = x, y
		}
	}
	for _, s := range series {
		if !s.bold {
			draw(s)
		}
	}
	for _, s := range series {
		if s.bold {
			draw(s)
		}
	}
	return cv.lines()
}
