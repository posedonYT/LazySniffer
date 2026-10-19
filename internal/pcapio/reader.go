package pcapio

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"
	"os"
	"sync"
	"sync/atomic"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
)

const (
	pcapMagicMicro    = 0xa1b2c3d4
	pcapMagicNano     = 0xa1b23c4d
	pcapMagicModified = 0xa1b2cd34
	pcapngMagic       = 0x0a0d0d0a
	pcapngBOM         = 0x1a2b3c4d

	blockSHB  = 0x0a0d0d0a
	blockIDB  = 0x00000001
	blockPB   = 0x00000002
	blockSPB  = 0x00000003
	blockNRB  = 0x00000004
	blockISB  = 0x00000005
	blockEPB  = 0x00000006
	blockDSB  = 0x0000000a
	maxBlock  = 256 << 20
	maxSnap   = 1 << 30
	optEnd    = 0
	optComent = 1
)

// File is an open capture file. Packets are enumerated sequentially with Next
// and their bytes are fetched at any time with Data.
type File struct {
	Path       string
	Format     Format
	Section    SectionInfo
	Interfaces []Interface
	Secrets    []Secrets
	Names      []NameRecord

	f        *os.File
	tempPath string
	mapping  atomic.Pointer[[]byte]
	oldMaps  [][]byte
	mapMu    sync.Mutex
	size     int64
	pos      int64
	order    binary.ByteOrder
	modified bool // Kuznetzov modified pcap
	// pcapng section bookkeeping: interface ids are local to a section.
	sectionBase int
}

// Open opens a capture file. Compressed files (gzip, zstd, lz4) are
// transparently decompressed into a temporary file first.
func Open(path string) (*File, error) {
	osf, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	var magic [4]byte
	n, _ := io.ReadFull(osf, magic[:])
	if n < 4 {
		osf.Close()
		return nil, ErrUnknownFormat
	}
	var dec io.Reader
	switch {
	case magic[0] == 0x1f && magic[1] == 0x8b:
		osf.Seek(0, io.SeekStart)
		gz, err := gzip.NewReader(osf)
		if err != nil {
			osf.Close()
			return nil, err
		}
		dec = gz
	case bytes.Equal(magic[:], []byte{0x28, 0xb5, 0x2f, 0xfd}):
		osf.Seek(0, io.SeekStart)
		zr, err := zstd.NewReader(osf)
		if err != nil {
			osf.Close()
			return nil, err
		}
		defer zr.Close()
		dec = zr
	case bytes.Equal(magic[:], []byte{0x04, 0x22, 0x4d, 0x18}):
		osf.Seek(0, io.SeekStart)
		dec = lz4.NewReader(osf)
	}
	f := &File{Path: path}
	if dec != nil {
		tmp, err := os.CreateTemp("", "lazysniffer-*.cap")
		if err != nil {
			osf.Close()
			return nil, err
		}
		_, err = io.Copy(tmp, dec)
		osf.Close()
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return nil, fmt.Errorf("decompressing %s: %w", path, err)
		}
		f.tempPath = tmp.Name()
		osf = tmp
	}
	f.f = osf
	if err := f.remap(); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.readHeader(); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// Close releases the mapping and the file.
func (f *File) Close() error {
	f.mapMu.Lock()
	defer f.mapMu.Unlock()
	for _, m := range f.oldMaps {
		munmap(m)
	}
	f.oldMaps = nil
	if m := f.mapping.Load(); m != nil && len(*m) > 0 {
		munmap(*m)
	}
	f.mapping.Store(nil)
	var err error
	if f.f != nil {
		err = f.f.Close()
	}
	if f.tempPath != "" {
		os.Remove(f.tempPath)
	}
	return err
}

// Size is the number of bytes currently visible through the mapping.
func (f *File) Size() int64 { return f.size }

// Pos is the offset of the next unread block.
func (f *File) Pos() int64 { return f.pos }

// Refresh picks up data appended to the file since it was opened (live
// capture). Slices previously returned by Data stay valid.
func (f *File) Refresh() error { return f.remap() }

func (f *File) remap() error {
	f.mapMu.Lock()
	defer f.mapMu.Unlock()
	st, err := f.f.Stat()
	if err != nil {
		return err
	}
	size := st.Size()
	if size == f.size && f.mapping.Load() != nil {
		return nil
	}
	if size == 0 {
		empty := []byte{}
		f.mapping.Store(&empty)
		f.size = 0
		return nil
	}
	m, err := mmap(f.f, size)
	if err != nil {
		return err
	}
	if old := f.mapping.Load(); old != nil && len(*old) > 0 {
		// Readers may still hold slices of the old mapping; keep it alive.
		f.oldMaps = append(f.oldMaps, *old)
	}
	f.mapping.Store(&m)
	f.size = size
	return nil
}

func (f *File) bytes() []byte {
	if m := f.mapping.Load(); m != nil {
		return *m
	}
	return nil
}

// Data returns the packet bytes of a record. The slice aliases the mapping and
// must not be modified.
func (f *File) Data(off int64, n uint32) []byte {
	b := f.bytes()
	end := off + int64(n)
	if off < 0 || end > int64(len(b)) {
		return nil
	}
	return b[off:end:end]
}

func (f *File) readHeader() error {
	b := f.bytes()
	if len(b) < 4 {
		return ErrUnknownFormat
	}
	le := binary.LittleEndian.Uint32(b)
	be := binary.BigEndian.Uint32(b)
	switch {
	case le == pcapngMagic:
		return f.startSection(0)
	case le == pcapMagicMicro || le == pcapMagicNano || le == pcapMagicModified:
		f.order = binary.LittleEndian
		return f.readPcapHeader(le)
	case be == pcapMagicMicro || be == pcapMagicNano || be == pcapMagicModified:
		f.order = binary.BigEndian
		return f.readPcapHeader(be)
	}
	return ErrUnknownFormat
}

func (f *File) readPcapHeader(magic uint32) error {
	b := f.bytes()
	if len(b) < 24 {
		return ErrTruncated
	}
	f.Format = FormatPcap
	resol := uint8(6)
	if magic == pcapMagicNano {
		f.Format = FormatPcapNs
		resol = 9
	}
	f.modified = magic == pcapMagicModified
	snap := f.order.Uint32(b[16:])
	network := f.order.Uint32(b[20:])
	iface := Interface{
		LinkType: LinkType(network & 0x0fffffff),
		SnapLen:  snap,
		TSResol:  resol,
		FCSLen:   -1,
	}
	// Bits 28..31 of the link-type field may carry an FCS length (pcap 2.4+).
	if network&0x10000000 != 0 {
		iface.FCSLen = int8((network>>29)&0x7) * 2
	}
	f.Interfaces = []Interface{iface}
	f.pos = 24
	return nil
}

// Next returns the next packet record, or io.EOF when no complete record is
// available. On a growing file call Refresh and Next again; Next does not
// advance past an incomplete record.
func (f *File) Next() (Record, error) {
	if f.Format == FormatPcapng {
		return f.nextNg()
	}
	return f.nextPcap()
}

// Truncated reports whether bytes remain after the last complete record.
func (f *File) Truncated() bool { return f.pos < f.size }

func (f *File) nextPcap() (Record, error) {
	b := f.bytes()
	hdr := int64(16)
	if f.modified {
		hdr = 24
	}
	if f.pos+hdr > int64(len(b)) {
		return Record{}, io.EOF
	}
	h := b[f.pos : f.pos+hdr]
	sec := f.order.Uint32(h[0:])
	frac := f.order.Uint32(h[4:])
	capLen := f.order.Uint32(h[8:])
	origLen := f.order.Uint32(h[12:])
	if capLen > maxSnap {
		return Record{}, &FormatError{f.pos, fmt.Sprintf("packet length %d is too large", capLen)}
	}
	dataOff := f.pos + hdr
	if dataOff+int64(capLen) > int64(len(b)) {
		return Record{}, io.EOF
	}
	ts := int64(sec) * 1e9
	if f.Format == FormatPcapNs {
		ts += int64(frac)
	} else {
		ts += int64(frac) * 1e3
	}
	f.pos = dataOff + int64(capLen)
	return Record{DataOff: dataOff, CapLen: capLen, OrigLen: origLen, TS: ts}, nil
}

func (f *File) startSection(off int64) error {
	b := f.bytes()
	if off+28 > int64(len(b)) {
		return ErrTruncated
	}
	bom := b[off+8 : off+12]
	switch {
	case binary.LittleEndian.Uint32(bom) == pcapngBOM:
		f.order = binary.LittleEndian
	case binary.BigEndian.Uint32(bom) == pcapngBOM:
		f.order = binary.BigEndian
	default:
		return &FormatError{off, "bad byte-order magic in section header"}
	}
	f.Format = FormatPcapng
	total := int64(f.order.Uint32(b[off+4:]))
	if total < 28 || total%4 != 0 || off+total > int64(len(b)) {
		return &FormatError{off, "bad section header block length"}
	}
	f.sectionBase = len(f.Interfaces)
	if off == 0 {
		f.parseOptions(b[off+24:off+total-4], func(code uint16, v []byte) {
			switch code {
			case optComent:
				f.Section.Comments = append(f.Section.Comments, string(v))
			case 2:
				f.Section.Hardware = string(v)
			case 3:
				f.Section.OS = string(v)
			case 4:
				f.Section.Application = string(v)
			}
		})
	}
	f.pos = off + total
	return nil
}

func (f *File) parseOptions(b []byte, fn func(code uint16, val []byte)) {
	for len(b) >= 4 {
		code := f.order.Uint16(b)
		l := int(f.order.Uint16(b[2:]))
		if code == optEnd {
			return
		}
		if 4+l > len(b) {
			return
		}
		fn(code, b[4:4+l])
		adv := 4 + (l+3)&^3
		if adv > len(b) {
			return
		}
		b = b[adv:]
	}
}

func (f *File) nextNg() (Record, error) {
	for {
		b := f.bytes()
		if f.pos+12 > int64(len(b)) {
			return Record{}, io.EOF
		}
		// A section header may switch byte order, so peek at it raw.
		if binary.LittleEndian.Uint32(b[f.pos:]) == blockSHB {
			if f.pos+28 > int64(len(b)) {
				return Record{}, io.EOF
			}
			bomLE := binary.LittleEndian.Uint32(b[f.pos+8:]) == pcapngBOM
			ord := binary.ByteOrder(binary.BigEndian)
			if bomLE {
				ord = binary.LittleEndian
			}
			total := int64(ord.Uint32(b[f.pos+4:]))
			if f.pos+total > int64(len(b)) {
				return Record{}, io.EOF
			}
			if err := f.startSection(f.pos); err != nil {
				return Record{}, err
			}
			continue
		}
		typ := f.order.Uint32(b[f.pos:])
		total := int64(f.order.Uint32(b[f.pos+4:]))
		if total < 12 || total%4 != 0 || total > maxBlock {
			return Record{}, &FormatError{f.pos, fmt.Sprintf("bad block length %d", total)}
		}
		if f.pos+total > int64(len(b)) {
			return Record{}, io.EOF
		}
		start := f.pos
		body := b[start+8 : start+total-4]
		f.pos = start + total
		switch typ {
		case blockIDB:
			f.parseIDB(body)
		case blockEPB:
			return f.parseEPB(start, body)
		case blockSPB:
			if len(body) < 4 || len(f.Interfaces) <= f.sectionBase {
				continue
			}
			orig := f.order.Uint32(body)
			capLen := orig
			if snap := f.Interfaces[f.sectionBase].SnapLen; snap != 0 && capLen > snap {
				capLen = snap
			}
			if int64(capLen) > int64(len(body)-4) {
				capLen = uint32(len(body) - 4)
			}
			return Record{DataOff: start + 12, CapLen: capLen, OrigLen: orig, Iface: uint32(f.sectionBase)}, nil
		case blockPB:
			if len(body) < 20 {
				continue
			}
			iface := uint32(f.order.Uint16(body)) + uint32(f.sectionBase)
			ts := f.convTS(iface, uint64(f.order.Uint32(body[4:]))<<32|uint64(f.order.Uint32(body[8:])))
			capLen := f.order.Uint32(body[12:])
			if int64(capLen) > int64(len(body)-20) {
				return Record{}, &FormatError{start, "packet block captured length too large"}
			}
			return Record{DataOff: start + 28, CapLen: capLen, OrigLen: f.order.Uint32(body[16:]), TS: ts, Iface: iface}, nil
		case blockNRB:
			f.parseNRB(body)
		case blockDSB:
			if len(body) >= 8 {
				l := f.order.Uint32(body[4:])
				if int64(l) <= int64(len(body)-8) {
					data := append([]byte(nil), body[8:8+l]...)
					f.Secrets = append(f.Secrets, Secrets{Type: SecretsType(f.order.Uint32(body)), Data: data})
				}
			}
		}
	}
}

func (f *File) parseIDB(body []byte) {
	if len(body) < 8 {
		return
	}
	iface := Interface{
		LinkType: LinkType(f.order.Uint16(body)),
		SnapLen:  f.order.Uint32(body[4:]),
		TSResol:  6,
		FCSLen:   -1,
	}
	f.parseOptions(body[8:], func(code uint16, v []byte) {
		switch code {
		case 2:
			iface.Name = string(v)
		case 3:
			iface.Description = string(v)
		case 9:
			if len(v) >= 1 {
				iface.TSResol = v[0]
			}
		case 11:
			if len(v) > 1 {
				iface.Filter = string(v[1:])
			}
		case 12:
			iface.OS = string(v)
		case 13:
			if len(v) >= 1 {
				iface.FCSLen = int8(v[0])
			}
		case 14:
			if len(v) >= 8 {
				iface.TSOffset = int64(f.order.Uint64(v))
			}
		case 15:
			iface.Hardware = string(v)
		}
	})
	f.Interfaces = append(f.Interfaces, iface)
}

func (f *File) parseEPB(start int64, body []byte) (Record, error) {
	if len(body) < 20 {
		return Record{}, &FormatError{start, "enhanced packet block too short"}
	}
	iface := f.order.Uint32(body) + uint32(f.sectionBase)
	tsRaw := uint64(f.order.Uint32(body[4:]))<<32 | uint64(f.order.Uint32(body[8:]))
	capLen := f.order.Uint32(body[12:])
	orig := f.order.Uint32(body[16:])
	if int64(capLen) > int64(len(body)-20) {
		return Record{}, &FormatError{start, "enhanced packet block captured length too large"}
	}
	rec := Record{
		DataOff: start + 28,
		CapLen:  capLen,
		OrigLen: orig,
		TS:      f.convTS(iface, tsRaw),
		Iface:   iface,
	}
	optOff := 20 + (int(capLen)+3)&^3
	if optOff < len(body) {
		f.parseOptions(body[optOff:], func(code uint16, v []byte) {
			switch code {
			case optComent:
				rec.Comments = append(rec.Comments, string(v))
			case 2:
				if len(v) >= 4 {
					rec.Flags = f.order.Uint32(v)
				}
			case 5:
				if len(v) >= 8 {
					rec.PacketID = f.order.Uint64(v)
				}
			case 6:
				if len(v) >= 4 {
					rec.Queue = f.order.Uint32(v)
				}
			}
		})
	}
	return rec, nil
}

func (f *File) parseNRB(body []byte) {
	for len(body) >= 4 {
		typ := f.order.Uint16(body)
		l := int(f.order.Uint16(body[2:]))
		if typ == 0 || 4+l > len(body) {
			return
		}
		v := body[4 : 4+l]
		alen := 0
		switch typ {
		case 1:
			alen = 4
		case 2:
			alen = 16
		}
		if alen > 0 && len(v) > alen {
			rec := NameRecord{Addr: append([]byte(nil), v[:alen]...)}
			for _, n := range bytes.Split(v[alen:], []byte{0}) {
				if len(n) > 0 {
					rec.Names = append(rec.Names, string(n))
				}
			}
			f.Names = append(f.Names, rec)
		}
		adv := 4 + (l+3)&^3
		if adv > len(body) {
			return
		}
		body = body[adv:]
	}
}

// convTS converts a raw pcapng timestamp to nanoseconds since the epoch using
// the interface's if_tsresol and if_tsoffset.
func (f *File) convTS(iface uint32, raw uint64) int64 {
	resol := uint8(6)
	var offset int64
	if int(iface) < len(f.Interfaces) {
		resol = f.Interfaces[iface].TSResol
		offset = f.Interfaces[iface].TSOffset
	}
	return ConvertTS(raw, resol) + offset*1e9
}

// ConvertTS converts a timestamp in if_tsresol units to nanoseconds.
func ConvertTS(raw uint64, resol uint8) int64 {
	if resol&0x80 != 0 {
		exp := uint(resol & 0x7f)
		if exp > 63 {
			return 0
		}
		sec := raw >> exp
		frac := raw & (1<<exp - 1)
		var ns uint64
		if exp > 0 {
			// frac < 2^exp, so frac*1e9 >> exp < 1e9 fits in 64 bits.
			hi, lo := bits.Mul64(frac, 1e9)
			ns = hi<<(64-exp) | lo>>exp
		}
		return int64(sec)*1e9 + int64(ns)
	}
	switch {
	case resol == 9:
		return int64(raw)
	case resol < 9:
		mul := int64(1)
		for i := resol; i < 9; i++ {
			mul *= 10
		}
		return int64(raw) * mul
	default:
		div := uint64(1)
		for i := uint8(9); i < resol && i < 28; i++ {
			div *= 10
		}
		return int64(raw / div)
	}
}
