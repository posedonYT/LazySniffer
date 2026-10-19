package pcapio

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
)

// Writer writes packets to a capture file.
type Writer interface {
	// AddInterface registers an interface and returns its index. Classic pcap
	// supports exactly one interface.
	AddInterface(Interface) (uint32, error)
	WritePacket(rec Record, data []byte) error
	WriteSecrets(Secrets) error
	Flush() error
}

var le = binary.LittleEndian

// NgWriter writes pcapng. Timestamps are written with nanosecond resolution.
type NgWriter struct {
	w      *bufio.Writer
	ifaces int
	buf    []byte
}

// NewNgWriter writes a section header and returns a writer.
func NewNgWriter(w io.Writer, sec SectionInfo) (*NgWriter, error) {
	nw := &NgWriter{w: bufio.NewWriterSize(w, 1<<20)}
	body := make([]byte, 0, 64)
	body = le.AppendUint32(body, pcapngBOM)
	body = le.AppendUint16(body, 1)
	body = le.AppendUint16(body, 0)
	body = le.AppendUint64(body, ^uint64(0)) // section length unknown
	var opts []byte
	for _, c := range sec.Comments {
		opts = appendOpt(opts, optComent, []byte(c))
	}
	opts = appendStrOpt(opts, 2, sec.Hardware)
	opts = appendStrOpt(opts, 3, sec.OS)
	app := sec.Application
	if app == "" {
		app = "lazysniffer"
	}
	opts = appendStrOpt(opts, 4, app)
	body = append(body, endOpts(opts)...)
	return nw, nw.block(blockSHB, body)
}

func appendOpt(b []byte, code uint16, v []byte) []byte {
	b = le.AppendUint16(b, code)
	b = le.AppendUint16(b, uint16(len(v)))
	b = append(b, v...)
	for i := len(v); i%4 != 0; i++ {
		b = append(b, 0)
	}
	return b
}

func appendStrOpt(b []byte, code uint16, s string) []byte {
	if s == "" {
		return b
	}
	return appendOpt(b, code, []byte(s))
}

func endOpts(opts []byte) []byte {
	if len(opts) == 0 {
		return nil
	}
	return append(opts, 0, 0, 0, 0)
}

func pad4(b []byte) []byte {
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func (nw *NgWriter) block(typ uint32, body []byte) error {
	body = pad4(body)
	total := uint32(12 + len(body))
	hdr := nw.buf[:0]
	hdr = le.AppendUint32(hdr, typ)
	hdr = le.AppendUint32(hdr, total)
	nw.buf = hdr
	if _, err := nw.w.Write(hdr); err != nil {
		return err
	}
	if _, err := nw.w.Write(body); err != nil {
		return err
	}
	var tail [4]byte
	le.PutUint32(tail[:], total)
	_, err := nw.w.Write(tail[:])
	return err
}

// AddInterface writes an Interface Description Block.
func (nw *NgWriter) AddInterface(i Interface) (uint32, error) {
	body := make([]byte, 0, 64)
	body = le.AppendUint16(body, uint16(i.LinkType))
	body = le.AppendUint16(body, 0)
	body = le.AppendUint32(body, i.SnapLen)
	var opts []byte
	opts = appendStrOpt(opts, 2, i.Name)
	opts = appendStrOpt(opts, 3, i.Description)
	opts = appendOpt(opts, 9, []byte{9})
	if i.Filter != "" {
		opts = appendOpt(opts, 11, append([]byte{0}, i.Filter...))
	}
	opts = appendStrOpt(opts, 12, i.OS)
	if i.FCSLen >= 0 {
		opts = appendOpt(opts, 13, []byte{byte(i.FCSLen)})
	}
	opts = appendStrOpt(opts, 15, i.Hardware)
	body = append(body, endOpts(opts)...)
	if err := nw.block(blockIDB, body); err != nil {
		return 0, err
	}
	nw.ifaces++
	return uint32(nw.ifaces - 1), nil
}

// WritePacket writes an Enhanced Packet Block. rec.TS is in nanoseconds.
func (nw *NgWriter) WritePacket(rec Record, data []byte) error {
	if int(rec.Iface) >= nw.ifaces {
		return errors.New("pcapng: packet references an unknown interface")
	}
	body := make([]byte, 0, 32+len(data))
	ts := uint64(rec.TS)
	body = le.AppendUint32(body, rec.Iface)
	body = le.AppendUint32(body, uint32(ts>>32))
	body = le.AppendUint32(body, uint32(ts))
	body = le.AppendUint32(body, uint32(len(data)))
	orig := rec.OrigLen
	if orig < uint32(len(data)) {
		orig = uint32(len(data))
	}
	body = le.AppendUint32(body, orig)
	body = pad4(append(body, data...))
	var opts []byte
	for _, c := range rec.Comments {
		opts = appendOpt(opts, optComent, []byte(c))
	}
	if rec.Flags != 0 {
		opts = appendOpt(opts, 2, le.AppendUint32(nil, rec.Flags))
	}
	if rec.PacketID != 0 {
		opts = appendOpt(opts, 5, le.AppendUint64(nil, rec.PacketID))
	}
	body = append(body, endOpts(opts)...)
	return nw.block(blockEPB, body)
}

// WriteSecrets writes a Decryption Secrets Block.
func (nw *NgWriter) WriteSecrets(s Secrets) error {
	body := make([]byte, 0, 8+len(s.Data))
	body = le.AppendUint32(body, uint32(s.Type))
	body = le.AppendUint32(body, uint32(len(s.Data)))
	body = append(body, s.Data...)
	return nw.block(blockDSB, body)
}

// WriteNames writes a Name Resolution Block.
func (nw *NgWriter) WriteNames(recs []NameRecord) error {
	var body []byte
	for _, r := range recs {
		typ := uint16(1)
		if len(r.Addr) == 16 {
			typ = 2
		} else if len(r.Addr) != 4 {
			continue
		}
		v := append([]byte(nil), r.Addr...)
		for _, n := range r.Names {
			v = append(append(v, n...), 0)
		}
		body = appendOpt(body, typ, v)
	}
	body = append(body, 0, 0, 0, 0)
	return nw.block(blockNRB, body)
}

// Flush flushes buffered blocks to the underlying writer.
func (nw *NgWriter) Flush() error { return nw.w.Flush() }

// PcapWriter writes classic pcap with a single interface.
type PcapWriter struct {
	w     *bufio.Writer
	nanos bool
	have  bool
}

// NewPcapWriter returns a pcap writer; the header is written by AddInterface.
func NewPcapWriter(w io.Writer, nanos bool) *PcapWriter {
	return &PcapWriter{w: bufio.NewWriterSize(w, 1<<20), nanos: nanos}
}

// ErrMultipleInterfaces is returned when pcap cannot hold the interfaces.
var ErrMultipleInterfaces = errors.New("pcap files hold a single link type; save as pcapng instead")

func (pw *PcapWriter) AddInterface(i Interface) (uint32, error) {
	if pw.have {
		return 0, ErrMultipleInterfaces
	}
	pw.have = true
	var h [24]byte
	magic := uint32(pcapMagicMicro)
	if pw.nanos {
		magic = pcapMagicNano
	}
	le.PutUint32(h[0:], magic)
	le.PutUint16(h[4:], 2)
	le.PutUint16(h[6:], 4)
	snap := i.SnapLen
	if snap == 0 {
		snap = 262144
	}
	le.PutUint32(h[16:], snap)
	le.PutUint32(h[20:], uint32(i.LinkType))
	_, err := pw.w.Write(h[:])
	return 0, err
}

func (pw *PcapWriter) WritePacket(rec Record, data []byte) error {
	if !pw.have {
		return errors.New("pcap: no interface")
	}
	var h [16]byte
	le.PutUint32(h[0:], uint32(rec.TS/1e9))
	frac := rec.TS % 1e9
	if !pw.nanos {
		frac /= 1e3
	}
	le.PutUint32(h[4:], uint32(frac))
	le.PutUint32(h[8:], uint32(len(data)))
	orig := rec.OrigLen
	if orig < uint32(len(data)) {
		orig = uint32(len(data))
	}
	le.PutUint32(h[12:], orig)
	if _, err := pw.w.Write(h[:]); err != nil {
		return err
	}
	_, err := pw.w.Write(data)
	return err
}

// WriteSecrets is unsupported in pcap; secrets are silently dropped.
func (pw *PcapWriter) WriteSecrets(Secrets) error { return nil }

func (pw *PcapWriter) Flush() error { return pw.w.Flush() }
