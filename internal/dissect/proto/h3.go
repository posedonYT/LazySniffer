package proto

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	d "github.com/poseydon/lazysniffer/internal/dissect"
)

var (
	h3FrameNames = map[uint64]string{0: "DATA", 1: "HEADERS", 3: "CANCEL_PUSH", 4: "SETTINGS", 5: "PUSH_PROMISE", 7: "GOAWAY", 0xd: "MAX_PUSH_ID", 0xf0700: "PRIORITY_UPDATE", 0xf0701: "PRIORITY_UPDATE"}
	h3UniNames   = map[uint64]string{0: "Control Stream", 1: "Push Stream", 2: "QPACK Encoder Stream", 3: "QPACK Decoder Stream"}
	h3SettingIDs = map[uint64]string{1: "http3.settings.qpack.max_table_capacity", 6: "http3.settings.max_field_section_size", 7: "http3.settings.qpack.blocked_streams",
		8: "http3.settings.extended_connect", 0x33: "http3.settings.h3_datagram"}

	protoH3      = d.RegisterProto("HyperText Transfer Protocol 3", "HTTP3", "http3")
	hfH3Stream   = protoH3.Field("http3.stream", "HTTP/3 Stream", d.FtNone)
	hfH3UniType  = protoH3.Field("http3.stream_uni_type", "Unidirectional Stream Type", d.FtUint64, d.WithVS(h3UniNames))
	hfH3Frame    = protoH3.Field("http3.frame", "Frame", d.FtNone)
	hfH3FType    = protoH3.Field("http3.frame_type", "Type", d.FtUint64, d.WithBase(d.BaseHex), d.WithVS(h3FrameNames))
	hfH3FLen     = protoH3.Field("http3.frame_length", "Length", d.FtUint64)
	hfH3FPayload = protoH3.Field("http3.frame_payload", "Frame Payload", d.FtBytes)
	hfH3Data     = protoH3.Field("http3.data", "Data", d.FtBytes)
	hfH3HCount   = protoH3.Field("http3.headers.count", "Headers Count", d.FtUint32)
	hfH3Header   = protoH3.Field("http3.headers.header", "Header", d.FtNone)
	hfH3HName    = protoH3.Field("http3.header.header.name", "Name", d.FtString)
	hfH3HValue   = protoH3.Field("http3.headers.header.value", "Value", d.FtString)
	hfH3Method   = protoH3.Field("http3.headers.method", "Method", d.FtString)
	hfH3Path     = protoH3.Field("http3.headers.path", "Path", d.FtString)
	hfH3Auth     = protoH3.Field("http3.headers.authority", "Authority", d.FtString)
	hfH3Scheme   = protoH3.Field("http3.headers.scheme", "Scheme", d.FtString)
	hfH3Status   = protoH3.Field("http3.headers.status", "Status", d.FtUint16)
	hfH3CType    = protoH3.Field("http3.headers.content_type", "Content-Type", d.FtString)
	hfH3CLen     = protoH3.Field("http3.headers.content_length", "Content-Length", d.FtString)
	hfH3CEnc     = protoH3.Field("http3.headers.content_encoding", "Content-Encoding", d.FtString)
	hfH3UA       = protoH3.Field("http3.headers.user_agent", "User-Agent", d.FtString)
	hfH3Server   = protoH3.Field("http3.headers.server", "Server", d.FtString)
	hfH3FullURI  = protoH3.Field("http3.request.full_uri", "Full request URI", d.FtString)
	hfH3Blocked  = protoH3.Field("http3.header.qpack.blocked", "Blocked", d.FtBool)
	hfH3Settings = protoH3.Field("http3.settings", "Settings", d.FtNone)
	hfH3SetID    = protoH3.Field("http3.settings.id", "Settings Identifier", d.FtUint64, d.WithBase(d.BaseHex))
	hfH3SetVal   = protoH3.Field("http3.settings.value", "Settings Value", d.FtUint64)
	hfH3SetQCap  = protoH3.Field("http3.settings.qpack.max_table_capacity", "Max Table Capacity", d.FtUint64)
	hfH3SetQBlk  = protoH3.Field("http3.settings.qpack.blocked_streams", "Blocked Streams", d.FtUint64)
	hfH3SetMax   = protoH3.Field("http3.settings.max_field_section_size", "Max Field Section Size", d.FtUint64)
	hfH3QEnc     = protoH3.Field("http3.qpack.encoder", "QPACK encoder instruction", d.FtBytes)
	hfH3QText    = protoH3.Field("http3.qpack.encoder.text", "Instruction", d.FtString)
	hfH3QDec     = protoH3.Field("http3.qpack.decoder", "QPACK decoder stream", d.FtBytes)
	hfH3BodyData = protoH3.Field("http3.body.data", "Body data", d.FtBytes)
	hfH3BodyURI  = protoH3.Field("http3.body.uri", "Request URI", d.FtString)
	hfH3BodyType = protoH3.Field("http3.body.type", "Body content type", d.FtString)
	hfH3BodyDir  = protoH3.Field("http3.body.direction", "Body direction", d.FtString)
	hfH3Reasm    = protoH3.Field("http3.body.reassembled.data", "Reassembled body", d.FtBytes)
	eiH3Blocked  = protoH3.Expert("http3.expert.header_decoding.blocked", d.GroupUndecoded, d.SevNote, "QPACK: header block waits for encoder stream instructions")
	eiH3Failed   = protoH3.Expert("http3.expert.header_decoding.failed", d.GroupMalformed, d.SevWarn, "QPACK decoding failed")
)

type h3Key struct {
	dir int
	id  uint64
}

type h3Stream struct {
	buf      []byte
	next     uint64
	ooo      map[uint64][]byte
	uniKnown bool
	uniType  uint64
	skip     uint64 // payload bytes of an oversized frame still to skip
	req      *h3Req
}

type h3Req struct {
	hdr    [2][]qpackHF
	body   [2][]byte
	frames [2][]d.FragRef
}

// h3Rec is one HTTP/3 element found by the first pass.
type h3Rec struct {
	stream   uint64
	uni      bool
	uniType  uint64
	hasType  bool
	ftype    uint64
	flen     uint64
	headers  []qpackHF
	blocked  bool
	failed   string
	settings [][2]uint64
	data     []byte
	qinst    []string
	qraw     []byte
	dir      int
	body     []byte
	bodyDone bool
	req      *h3Req
	sec      *h3Section
}

// h3Section is a HEADERS block that may be decoded later.
type h3Section struct {
	raw  []byte
	dec  int // decoder direction
	rec  *h3Rec
	done bool
}

type h3Conn struct {
	reqs    map[uint64]*h3Req
	streams map[h3Key]*h3Stream
	qdec    [2]*qpackDec
	blocked []*h3Section
}

func (c *h3Conn) stream(dir int, id uint64) *h3Stream {
	k := h3Key{dir, id}
	s := c.streams[k]
	if s == nil {
		s = &h3Stream{ooo: map[uint64][]byte{}}
		c.streams[k] = s
	}
	return s
}

func newH3Conn() *h3Conn {
	return &h3Conn{reqs: map[uint64]*h3Req{}, streams: map[h3Key]*h3Stream{}, qdec: [2]*qpackDec{{}, {}}}
}

func readVarint(b []byte) (v uint64, n int, ok bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	n = 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0, false
	}
	v = uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n, true
}

const h3MaxFrame = 4 << 20

// feed delivers STREAM frame data (first pass) and returns the elements
// that became complete.
func (c *h3Conn) feed(dir int, sid, off uint64, data []byte, fin bool) []*h3Rec {
	st := c.stream(dir, sid)
	var out []*h3Rec
	deliver := func(b []byte) { out = append(out, c.process(dir, sid, st, b, false)...) }
	switch {
	case off > st.next:
		st.ooo[off] = append([]byte(nil), data...)
		return nil
	case off+uint64(len(data)) <= st.next && !(fin && len(data) == 0):
		return nil // retransmission
	}
	if skip := st.next - off; skip < uint64(len(data)) {
		deliver(data[skip:])
		st.next = off + uint64(len(data))
	}
	for {
		b, ok := st.ooo[st.next]
		if !ok {
			break
		}
		delete(st.ooo, st.next)
		deliver(b)
		st.next += uint64(len(b))
	}
	if fin {
		out = append(out, c.process(dir, sid, st, nil, true)...)
	}
	return out
}

func (c *h3Conn) process(dir int, sid uint64, st *h3Stream, b []byte, fin bool) []*h3Rec {
	var out []*h3Rec
	uni := sid&2 != 0
	if st.skip > 0 && len(b) > 0 {
		n := min(uint64(len(b)), st.skip)
		st.skip -= n
		b = b[n:]
	}
	st.buf = append(st.buf, b...)
	if uni && !st.uniKnown {
		v, n, ok := readVarint(st.buf)
		if !ok {
			return nil
		}
		st.uniType, st.uniKnown = v, true
		st.buf = st.buf[n:]
		out = append(out, &h3Rec{stream: sid, dir: dir, uni: true, uniType: v, hasType: true})
	}
	if uni && st.uniKnown && (st.uniType == 2 || st.uniType == 3) {
		if len(st.buf) > 0 {
			rec := &h3Rec{stream: sid, dir: dir, uni: true, uniType: st.uniType}
			if st.uniType == 2 {
				rec.qraw = append([]byte(nil), st.buf...)
				rec.qinst = c.qdec[dir].feed(st.buf)
				c.retryBlocked(&out)
			} else {
				rec.qraw = append([]byte(nil), st.buf...)
			}
			st.buf = nil
			out = append(out, rec)
		}
		return out
	}
	if uni && st.uniKnown && st.uniType != 0 {
		st.buf = nil // push / unknown streams are not parsed
		return out
	}
	// HTTP/3 frames
	for len(st.buf) > 0 {
		ft, n1, ok := readVarint(st.buf)
		if !ok {
			break
		}
		fl, n2, ok := readVarint(st.buf[n1:])
		if !ok {
			break
		}
		hl := n1 + n2
		rec := &h3Rec{stream: sid, dir: dir, uni: uni, ftype: ft, flen: fl}
		if !uni {
			if st.req == nil {
				if c.reqs[sid] == nil {
					c.reqs[sid] = &h3Req{}
				}
				st.req = c.reqs[sid]
			}
			rec.req = st.req
		}
		if fl > h3MaxFrame {
			// Oversized: keep nothing but account for the bytes.
			have := uint64(len(st.buf) - hl)
			if have > fl {
				have = fl
			}
			st.skip = fl - have
			st.buf = st.buf[hl+int(have):]
			out = append(out, rec)
			continue
		}
		if uint64(len(st.buf)-hl) < fl {
			break
		}
		payload := st.buf[hl : hl+int(fl)]
		c.frame(rec, st, dir, payload)
		st.buf = st.buf[hl+int(fl):]
		out = append(out, rec)
	}
	if fin && st.req != nil && !uni {
		if len(out) > 0 && out[len(out)-1].ftype == 0 {
			out[len(out)-1].bodyDone = true
			out[len(out)-1].body = st.req.body[dir]
		} else {
			out = append(out, &h3Rec{stream: sid, dir: dir, ftype: 0xffff, req: st.req, bodyDone: true, body: st.req.body[dir]})
		}
	}
	return out
}

func (c *h3Conn) frame(rec *h3Rec, st *h3Stream, dir int, payload []byte) {
	switch rec.ftype {
	case 0: // DATA
		rec.data = append([]byte(nil), payload[:min(len(payload), 64<<10)]...)
		if st.req != nil && len(st.req.body[dir])+len(payload) <= 16<<20 {
			st.req.body[dir] = append(st.req.body[dir], payload...)
		}
	case 1, 5: // HEADERS, PUSH_PROMISE
		raw := payload
		if rec.ftype == 5 {
			_, n, ok := readVarint(raw)
			if !ok {
				rec.failed = "short PUSH_PROMISE"
				return
			}
			raw = raw[n:]
		}
		sec := &h3Section{raw: append([]byte(nil), raw...), dec: dir, rec: rec}
		rec.sec = sec
		c.tryDecode(sec, st)
	case 4: // SETTINGS
		for p := payload; len(p) > 0; {
			id, n, ok := readVarint(p)
			if !ok {
				break
			}
			v, m, ok := readVarint(p[n:])
			if !ok {
				break
			}
			rec.settings = append(rec.settings, [2]uint64{id, v})
			if id == 1 {
				c.qdec[1-dir].maxCap = v // limits the peer's encoder
			}
			p = p[n+m:]
		}
	default:
		rec.data = append([]byte(nil), payload[:min(len(payload), 4096)]...)
	}
}

func (c *h3Conn) tryDecode(sec *h3Section, st *h3Stream) {
	fields, _, blocked, err := c.qdec[sec.dec].decode(sec.raw)
	switch {
	case blocked:
		sec.rec.blocked = true
		c.blocked = append(c.blocked, sec)
	case err != nil:
		sec.rec.failed = err.Error()
		sec.done = true
	default:
		sec.rec.headers, sec.rec.blocked, sec.done = fields, false, true
		if st != nil && st.req != nil && sec.rec.ftype == 1 {
			st.req.hdr[sec.dec] = fields
		}
	}
}

// retryBlocked decodes sections that were waiting for encoder instructions.
func (c *h3Conn) retryBlocked(out *[]*h3Rec) {
	keep := c.blocked[:0]
	for _, sec := range c.blocked {
		c.tryDecode(sec, nil)
		if sec.done {
			if sec.rec.req != nil && sec.rec.ftype == 1 {
				sec.rec.req.hdr[sec.dec] = sec.rec.headers
			}
			continue
		}
		keep = append(keep, sec)
	}
	c.blocked = keep
}

// ---- display ----

var h3Special = map[string]*d.FieldDef{":method": hfH3Method, ":path": hfH3Path, ":authority": hfH3Auth, ":scheme": hfH3Scheme,
	"content-type": hfH3CType, "content-length": hfH3CLen, "content-encoding": hfH3CEnc, "user-agent": hfH3UA, "server": hfH3Server}

// h3Show renders the records of one STREAM frame and returns Info text.
func h3Show(fn *d.Node, pi *d.PacketInfo, recs []*h3Rec) []string {
	var infos []string
	for _, r := range recs {
		st := fn.AddText(nil, 0, 0, "HTTP/3 Stream: ")
		st.AddValue(hfH3Stream, nil, 0, 0, d.Value{})
		switch {
		case r.uni && r.hasType:
			st.SetText("HTTP/3 Stream: %s", orDefault(h3UniNames[r.uniType], "Unknown Stream"))
			st.AddValue(hfH3UniType, nil, 0, 0, d.UintValue(d.FtUint64, r.uniType))
			continue
		case r.uni && r.uniType == 2:
			st.SetText("HTTP/3 Stream: QPACK Encoder Stream")
			st.AddValue(hfH3QEnc, nil, 0, 0, d.BytesValue(d.FtBytes, r.qraw))
			for _, s := range r.qinst {
				st.AddValue(hfH3QText, nil, 0, 0, d.StringValue(s))
			}
			infos = append(infos, fmt.Sprintf("QPACK ENC[%d]", len(r.qinst)))
		case r.uni && r.uniType == 3:
			st.SetText("HTTP/3 Stream: QPACK Decoder Stream")
			st.AddValue(hfH3QDec, nil, 0, 0, d.BytesValue(d.FtBytes, r.qraw))
			infos = append(infos, fmt.Sprintf("QPACK DEC[%d]", qpackDecoderInstructions(r.qraw)))
		default:
			name := orDefault(h3FrameNames[r.ftype], fmt.Sprintf("Unknown (0x%x)", r.ftype))
			if r.ftype == 0xffff {
				st.SetText("HTTP/3 Stream: end of stream")
				if r.bodyDone && len(r.body) > 0 {
					h3Body(st, pi, r)
				}
				continue
			}
			st.SetText("HTTP/3 Stream: %s", name)
			fr := st.AddValue(hfH3Frame, nil, 0, 0, d.Value{})
			fr.AddValue(hfH3FType, nil, 0, 0, d.UintValue(d.FtUint64, r.ftype))
			fr.AddValue(hfH3FLen, nil, 0, 0, d.UintValue(d.FtUint64, r.flen))
			info := name
			switch r.ftype {
			case 1, 5:
				if r.blocked {
					fr.AddValue(hfH3Blocked, nil, 0, 0, d.BoolValue(true))
					fr.AddExpert(eiH3Blocked, "")
					break
				}
				if r.failed != "" {
					fr.AddExpert(eiH3Failed, "%s", r.failed)
					break
				}
				fr.AddValue(hfH3HCount, nil, 0, 0, d.UintValue(d.FtUint32, uint64(len(r.headers))))
				var method, path, auth, scheme, status string
				for _, h := range r.headers {
					hn := fr.AddText(nil, 0, 0, "Header: %s: %s", h.Name, h.Value)
					hn.AddValue(hfH3Header, nil, 0, 0, d.Value{})
					hn.AddValue(hfH3HName, nil, 0, 0, d.StringValue(h.Name))
					hn.AddValue(hfH3HValue, nil, 0, 0, d.StringValue(h.Value))
					if f := h3Special[h.Name]; f != nil {
						hn.AddValue(f, nil, 0, 0, d.StringValue(h.Value))
					}
					switch h.Name {
					case ":method":
						method = h.Value
					case ":path":
						path = h.Value
					case ":authority":
						auth = h.Value
					case ":scheme":
						scheme = h.Value
					case ":status":
						status = h.Value
						code, _ := strconv.Atoi(h.Value)
						hn.AddValue(hfH3Status, nil, 0, 0, d.UintValue(d.FtUint16, uint64(code)))
					}
				}
				if method != "" {
					full := scheme + "://" + auth + path
					fr.AddGenerated(hfH3FullURI, d.StringValue(full))
					info += ": " + method + " " + full
				} else if status != "" {
					code, _ := strconv.Atoi(status)
					info += ": " + status
					if t := http.StatusText(code); t != "" {
						info += " " + t
					}
				}
			case 4:
				sn := fr.AddValue(hfH3Settings, nil, 0, 0, d.Value{})
				for _, s := range r.settings {
					sn.AddValue(hfH3SetID, nil, 0, 0, d.UintValue(d.FtUint64, s[0]))
					sn.AddValue(hfH3SetVal, nil, 0, 0, d.UintValue(d.FtUint64, s[1]))
					switch s[0] {
					case 1:
						sn.AddValue(hfH3SetQCap, nil, 0, 0, d.UintValue(d.FtUint64, s[1]))
					case 6:
						sn.AddValue(hfH3SetMax, nil, 0, 0, d.UintValue(d.FtUint64, s[1]))
					case 7:
						sn.AddValue(hfH3SetQBlk, nil, 0, 0, d.UintValue(d.FtUint64, s[1]))
					}
				}
			case 0:
				fr.AddValue(hfH3Data, nil, 0, 0, d.BytesValue(d.FtBytes, r.data))
			}
			infos = append(infos, info)
		}
		if r.bodyDone && len(r.body) > 0 {
			h3Body(st, pi, r)
		}
	}
	return infos
}

func h3Body(tree *d.Node, pi *d.PacketInfo, r *h3Rec) {
	data := r.body
	var ct, enc string
	req := r.req
	if req != nil {
		resp := req.hdr[1-clientDirOfH3(r)]
		own := req.hdr[r.dir]
		for _, h := range own {
			if h.Name == "content-type" {
				ct = h.Value
			}
			if h.Name == "content-encoding" {
				enc = h.Value
			}
		}
		_ = resp
	}
	if enc != "" {
		if dec, err := decompress(enc, data); err == nil {
			data = dec
		}
	}
	src := pi.AddSource("Reassembled HTTP/3 body", data)
	bn := tree.AddText(src, 0, src.Len(), "Body (%d bytes)", src.Len())
	if b, _ := bn.AddBytes(hfH3BodyData, src, 0, src.Len()); b != nil {
		b.SetHidden()
	}
	uri := ""
	if req != nil {
		var method, path, auth, scheme string
		for _, h := range req.hdr[0] {
			switch h.Name {
			case ":method":
				method = h.Value
			case ":path":
				path = h.Value
			case ":authority":
				auth = h.Value
			case ":scheme":
				scheme = h.Value
			}
		}
		if method != "" {
			uri = scheme + "://" + auth + path
		}
	}
	bn.AddGenerated(hfH3BodyURI, d.StringValue(uri)).SetHidden()
	mt := strings.TrimSpace(strings.SplitN(ct, ";", 2)[0])
	bn.AddGenerated(hfH3BodyType, d.StringValue(mt)).SetHidden()
	bn.AddGenerated(hfH3BodyDir, d.StringValue(map[int]string{0: "request", 1: "response"}[r.dir])).SetHidden()
	if src.Len() > 0 {
		DissectMedia(mt, src, pi, bn)
	}
}

// clientDirOfH3: the client is direction 0 of the QUIC connection.
func clientDirOfH3(r *h3Rec) int { return 0 }

// qpackDecoderInstructions counts the instructions of a decoder stream
// (section acknowledgment, stream cancellation, insert count increment).
func qpackDecoderInstructions(b []byte) int {
	n := 0
	for len(b) > 0 {
		prefix := 6
		if b[0]&0x80 != 0 {
			prefix = 7
		}
		_, u, err := qpackInt(b, prefix)
		if err != nil {
			break
		}
		b = b[u:]
		n++
	}
	return n
}
