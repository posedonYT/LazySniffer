// Package store keeps the frame index of an open capture and runs the
// sequential first dissection pass over it.
package store

import (
	"context"
	"errors"
	"github.com/poseydon/lazysniffer/internal/keylog"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/pcapio"
)

// Frame flags.
const (
	FlagMarked uint16 = 1 << iota
	FlagIgnored
	FlagTimeRef
	FlagComment
	FlagMalformed
)

// FrameMeta is the fixed-size, pointer-free index entry of one frame.
type FrameMeta struct {
	Off      int64
	TS       int64
	CapLen   uint32
	Len      uint32
	EPBFlags uint32
	Iface    uint16
	Flags    uint16
	MaxSev   uint8
}

// Capture is an open capture file with its frame index.
type Capture struct {
	Path string

	mu        sync.RWMutex
	file      *pcapio.File
	frames    []FrameMeta
	comments  map[uint32][]string
	refs      []uint32 // time reference frames, sorted
	sess      *dissect.Session
	pass1     *dissect.Worker
	loaded    bool
	loadErr   error
	truncated bool
	modified  bool // marks/comments changed since open
	dirtyEdit bool // comments changed (needs save to persist)

	shift int64 // time shift (ns) added to every packet timestamp

	// Live is set while the file is still being written by a capture.
	Live bool
}

// Open opens a capture file. Call Load to build the index.
func Open(path string) (*Capture, error) {
	f, err := pcapio.Open(path)
	if err != nil {
		return nil, err
	}
	keylog.Default.Reset()
	for _, sec := range f.Secrets {
		if sec.Type == pcapio.SecretsTLSKeyLog {
			keylog.Default.AddData(sec.Data)
		}
	}
	c := &Capture{Path: path, file: f, comments: map[uint32][]string{}}
	c.sess = dissect.NewSession(f.Interfaces)
	c.sess.FrameBytes = c.frameBytes
	c.pass1 = c.sess.NewWorker(dissect.Options{Want: make([]bool, dissect.NumFields())})
	return c, nil
}

// Close releases the file.
func (c *Capture) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.file == nil {
		return nil
	}
	err := c.file.Close()
	c.file = nil
	return err
}

// File returns the underlying capture file.
func (c *Capture) File() *pcapio.File { return c.file }

// Session returns the dissection session.
func (c *Capture) Session() *dissect.Session { return c.sess }

// Count is the number of indexed frames.
func (c *Capture) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.frames)
}

// Loaded reports whether the initial load finished, and its error.
func (c *Capture) Loaded() (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.loaded, c.loadErr
}

// Truncated reports a file that ended in the middle of a record.
func (c *Capture) Truncated() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.truncated
}

// Frame returns the index entry of frame num (1-based).
func (c *Capture) Frame(num uint32) FrameMeta {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if num == 0 || int(num) > len(c.frames) {
		return FrameMeta{}
	}
	return c.frames[num-1]
}

// Progress is reported while loading.
type Progress struct {
	Frames int
	Bytes  int64
	Total  int64
}

// Load reads all complete records and runs the first dissection pass. It
// calls progress periodically. For live captures call Load again after the
// file grew to pick up new frames.
func (c *Capture) Load(ctx context.Context, progress func(Progress)) error {
	last := time.Now()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := c.loadBatch(4096)
		if progress != nil && (time.Since(last) > 50*time.Millisecond || err != nil || n == 0) {
			last = time.Now()
			progress(Progress{Frames: c.Count(), Bytes: c.file.Pos(), Total: c.file.Size()})
		}
		if err != nil {
			c.mu.Lock()
			c.loaded, c.loadErr = true, err
			c.mu.Unlock()
			return err
		}
		if n == 0 {
			c.mu.Lock()
			c.loaded = true
			c.truncated = !c.Live && c.file.Truncated()
			c.mu.Unlock()
			return nil
		}
	}
}

// Refresh re-maps a growing file and indexes new frames.
func (c *Capture) Refresh(ctx context.Context) (int, error) {
	before := c.Count()
	if err := c.file.Refresh(); err != nil {
		return 0, err
	}
	err := c.Load(ctx, nil)
	return c.Count() - before, err
}

func (c *Capture) loadBatch(max int) (int, error) {
	n := 0
	for n < max {
		rec, err := c.file.Next()
		if errors.Is(err, io.EOF) {
			return n, nil
		}
		if err != nil {
			return n, err
		}
		if len(c.file.Interfaces) != len(c.sess.Interfaces) {
			c.sess.Interfaces = c.file.Interfaces
		}
		m := FrameMeta{Off: rec.DataOff, TS: rec.TS, CapLen: rec.CapLen, Len: rec.OrigLen,
			EPBFlags: rec.Flags, Iface: uint16(rec.Iface)}
		if m.Len < m.CapLen {
			m.Len = m.CapLen
		}
		c.mu.Lock()
		num := uint32(len(c.frames) + 1)
		if len(rec.Comments) > 0 {
			c.comments[num] = rec.Comments
			m.Flags |= FlagComment
		}
		c.frames = append(c.frames, m)
		c.mu.Unlock()

		fi := c.input(num)
		pi := c.pass1.FirstPass(fi)
		c.mu.Lock()
		c.frames[num-1].MaxSev = uint8(pi.MaxSeverity)
		c.mu.Unlock()
		n++
	}
	return n, nil
}

func (c *Capture) frameBytes(num uint32) []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if num == 0 || int(num) > len(c.frames) || c.file == nil {
		return nil
	}
	m := c.frames[num-1]
	return c.file.Data(m.Off, m.CapLen)
}

// Input builds the dissector input for frame num.
// SetTimeShift adds ns to every timestamp shown (Edit → Time Shift).
func (c *Capture) SetTimeShift(ns int64) {
	c.mu.Lock()
	c.shift = ns
	c.mu.Unlock()
}

// TimeShift returns the current shift in nanoseconds.
func (c *Capture) TimeShift() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.shift
}

func (c *Capture) Input(num uint32) *dissect.FrameInput { return c.input(num) }

func (c *Capture) input(num uint32) *dissect.FrameInput {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if num == 0 || int(num) > len(c.frames) {
		return nil
	}
	m := c.frames[num-1]
	fi := &dissect.FrameInput{
		Num: num, TS: m.TS + c.shift, CapLen: m.CapLen, Len: m.Len, Iface: uint32(m.Iface),
		EPBFlags: m.EPBFlags, Comments: c.comments[num],
		Marked: m.Flags&FlagMarked != 0, Ignored: m.Flags&FlagIgnored != 0,
	}
	if c.file != nil {
		fi.Data = c.file.Data(m.Off, m.CapLen)
	}
	fi.RelTS = m.TS - c.refTSLocked(num)
	if num > 1 {
		fi.DeltaTS = m.TS - c.frames[num-2].TS
	}
	return fi
}

// refTSLocked is the timestamp frame num is relative to: the latest time
// reference at or before it, or the first frame.
func (c *Capture) refTSLocked(num uint32) int64 {
	i := sort.Search(len(c.refs), func(i int) bool { return c.refs[i] > num })
	if i > 0 {
		return c.frames[c.refs[i-1]-1].TS
	}
	if len(c.frames) > 0 {
		return c.frames[0].TS
	}
	return 0
}

// RelTS returns the frame time relative to the reference/first frame.
func (c *Capture) RelTS(num uint32) int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if num == 0 || int(num) > len(c.frames) {
		return 0
	}
	return c.frames[num-1].TS - c.refTSLocked(num)
}

// FirstTS is the timestamp of the first frame.
func (c *Capture) FirstTS() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.frames) == 0 {
		return 0
	}
	return c.frames[0].TS
}

// SetFlag sets or clears a frame flag.
func (c *Capture) SetFlag(num uint32, flag uint16, on bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if num == 0 || int(num) > len(c.frames) {
		return
	}
	f := &c.frames[num-1]
	if on {
		f.Flags |= flag
	} else {
		f.Flags &^= flag
	}
	if flag == FlagTimeRef {
		i := sort.Search(len(c.refs), func(i int) bool { return c.refs[i] >= num })
		has := i < len(c.refs) && c.refs[i] == num
		switch {
		case on && !has:
			c.refs = append(c.refs, 0)
			copy(c.refs[i+1:], c.refs[i:])
			c.refs[i] = num
		case !on && has:
			c.refs = append(c.refs[:i], c.refs[i+1:]...)
		}
	}
	c.modified = true
}

// ToggleFlag flips a frame flag and returns the new state.
func (c *Capture) ToggleFlag(num uint32, flag uint16) bool {
	on := c.Frame(num).Flags&flag == 0
	c.SetFlag(num, flag, on)
	return on
}

// ClearFlag clears a flag on all frames.
func (c *Capture) ClearFlag(flag uint16) {
	c.mu.Lock()
	for i := range c.frames {
		c.frames[i].Flags &^= flag
	}
	if flag == FlagTimeRef {
		c.refs = nil
	}
	c.mu.Unlock()
}

// Comments returns the comments of a frame.
func (c *Capture) Comments(num uint32) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]string(nil), c.comments[num]...)
}

// SetComments replaces the comments of a frame.
func (c *Capture) SetComments(num uint32, comments []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if num == 0 || int(num) > len(c.frames) {
		return
	}
	if len(comments) == 0 {
		delete(c.comments, num)
		c.frames[num-1].Flags &^= FlagComment
	} else {
		c.comments[num] = comments
		c.frames[num-1].Flags |= FlagComment
	}
	c.dirtyEdit = true
	c.modified = true
}

// Unsaved reports edits that only a save can persist.
func (c *Capture) Unsaved() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.dirtyEdit
}

// FramesWithFlag lists frame numbers having flag.
func (c *Capture) FramesWithFlag(flag uint16) []uint32 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []uint32
	for i, f := range c.frames {
		if f.Flags&flag != 0 {
			out = append(out, uint32(i+1))
		}
	}
	return out
}
