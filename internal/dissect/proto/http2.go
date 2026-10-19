package proto

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/net/http2/hpack"

	d "github.com/poseydon/lazysniffer/internal/dissect"
)

const h2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

var (
	h2Types = map[uint64]string{0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM", 4: "SETTINGS", 5: "PUSH_PROMISE",
		6: "PING", 7: "GOAWAY", 8: "WINDOW_UPDATE", 9: "CONTINUATION", 10: "ALTSVC", 12: "ORIGIN", 16: "PRIORITY_UPDATE"}
	h2Errors = map[uint64]string{0: "NO_ERROR", 1: "PROTOCOL_ERROR", 2: "INTERNAL_ERROR", 3: "FLOW_CONTROL_ERROR",
		4: "SETTINGS_TIMEOUT", 5: "STREAM_CLOSED", 6: "FRAME_SIZE_ERROR", 7: "REFUSED_STREAM", 8: "CANCEL",
		9: "COMPRESSION_ERROR", 10: "CONNECT_ERROR", 11: "ENHANCE_YOUR_CALM", 12: "INADEQUATE_SECURITY", 13: "HTTP_1_1_REQUIRED"}
	h2Settings = map[uint64]string{1: "Header table size", 2: "Enable PUSH", 3: "Max concurrent streams",
		4: "Initial Windows size", 5: "Max frame size", 6: "Max header list size", 8: "Enable CONNECT Protocol"}

	protoH2      = d.RegisterProto("HyperText Transfer Protocol 2", "HTTP2", "http2")
	hfH2Magic    = protoH2.Field("http2.magic", "Magic", d.FtString)
	hfH2Stream   = protoH2.Field("http2.stream", "Stream", d.FtNone)
	hfH2Length   = protoH2.Field("http2.length", "Length", d.FtUint24)
	hfH2Type     = protoH2.Field("http2.type", "Type", d.FtUint8, d.WithVS(h2Types))
	hfH2Flags    = protoH2.Field("http2.flags", "Flags", d.FtUint8, d.WithBase(d.BaseHex))
	hfH2EndStr   = protoH2.Field("http2.flags.end_stream", "End Stream", d.FtBool, d.WithMask(0x01), d.WithParentBits(8), d.WithTFS(d.TFSTrue))
	hfH2EndHdr   = protoH2.Field("http2.flags.eh", "End Headers", d.FtBool, d.WithMask(0x04), d.WithParentBits(8), d.WithTFS(d.TFSTrue))
	hfH2Padded   = protoH2.Field("http2.flags.padded", "Padded", d.FtBool, d.WithMask(0x08), d.WithParentBits(8), d.WithTFS(d.TFSTrue))
	hfH2Prio     = protoH2.Field("http2.flags.priority", "Priority", d.FtBool, d.WithMask(0x20), d.WithParentBits(8), d.WithTFS(d.TFSTrue))
	hfH2Ack      = protoH2.Field("http2.flags.ack", "Ack", d.FtBool, d.WithMask(0x01), d.WithParentBits(8), d.WithTFS(d.TFSTrue))
	hfH2R        = protoH2.Field("http2.r", "Reserved", d.FtBool, d.WithMask(0x80000000), d.WithParentBits(32))
	hfH2StreamID = protoH2.Field("http2.streamid", "Stream Identifier", d.FtUint32, d.WithMask(0x7fffffff), d.WithParentBits(32))
	hfH2Padlen   = protoH2.Field("http2.padding", "Pad Length", d.FtUint8)
	hfH2Data     = protoH2.Field("http2.data.data", "Data", d.FtBytes)
	hfH2Dlen     = protoH2.Field("http2.data.length", "Data length", d.FtUint32)
	hfH2HdrLen   = protoH2.Field("http2.headers", "Header", d.FtNone)
	hfH2HName    = protoH2.Field("http2.header.name", "Name", d.FtString)
	hfH2HValue   = protoH2.Field("http2.header.value", "Value", d.FtString)
	hfH2HNameLen = protoH2.Field("http2.header.name.length", "Name Length", d.FtUint32)
	hfH2HValLen  = protoH2.Field("http2.header.value.length", "Value Length", d.FtUint32)
	hfH2Method   = protoH2.Field("http2.headers.method", "Method", d.FtString)
	hfH2Path     = protoH2.Field("http2.headers.path", "Path", d.FtString)
	hfH2Auth     = protoH2.Field("http2.headers.authority", "Authority", d.FtString)
	hfH2Scheme   = protoH2.Field("http2.headers.scheme", "Scheme", d.FtString)
	hfH2Status   = protoH2.Field("http2.headers.status", "Status", d.FtString)
	hfH2CType    = protoH2.Field("http2.headers.content_type", "Content-Type", d.FtString)
	hfH2CEnc     = protoH2.Field("http2.headers.content_encoding", "Content-Encoding", d.FtString)
	hfH2CLen     = protoH2.Field("http2.headers.content_length", "Content-Length", d.FtString)
	hfH2UA       = protoH2.Field("http2.headers.user_agent", "User-Agent", d.FtString)
	hfH2Server   = protoH2.Field("http2.headers.server", "Server", d.FtString)
	hfH2Cookie   = protoH2.Field("http2.headers.cookie", "Cookie", d.FtString)
	hfH2Accept   = protoH2.Field("http2.headers.accept", "Accept", d.FtString)
	hfH2Referer  = protoH2.Field("http2.headers.referer", "Referer", d.FtString)
	hfH2Hdrs     = protoH2.Field("http2.header.repeat", "Header repeated", d.FtBool)
	hfH2ExclDep  = protoH2.Field("http2.exclusive", "Exclusive", d.FtBool, d.WithMask(0x80000000), d.WithParentBits(32))
	hfH2DepID    = protoH2.Field("http2.stream_dependency", "Stream Dependency", d.FtUint32, d.WithMask(0x7fffffff), d.WithParentBits(32))
	hfH2Weight   = protoH2.Field("http2.headers.weight", "Weight", d.FtUint8)
	hfH2RstErr   = protoH2.Field("http2.rst_stream.error", "Error", d.FtUint32, d.WithVS(h2Errors))
	hfH2SetID    = protoH2.Field("http2.settings.id", "Identifier", d.FtUint16, d.WithVS(h2Settings))
	hfH2SetVal   = protoH2.Field("http2.settings.value", "Value", d.FtUint32)
	hfH2SetNamed = map[uint64]*d.FieldDef{
		1: protoH2.Field("http2.settings.header_table_size", "Header table size", d.FtUint32),
		2: protoH2.Field("http2.settings.enable_push", "Enable PUSH", d.FtUint32),
		3: protoH2.Field("http2.settings.max_concurrent_streams", "Max concurrent streams", d.FtUint32),
		4: protoH2.Field("http2.settings.initial_window_size", "Initial Windows size", d.FtUint32),
		5: protoH2.Field("http2.settings.max_frame_size", "Max frame size", d.FtUint32),
		6: protoH2.Field("http2.settings.max_header_list_size", "Max header list size", d.FtUint32),
		8: protoH2.Field("http2.settings.extended_connect", "Enable CONNECT Protocol", d.FtUint32),
	}
	hfH2WinInc   = protoH2.Field("http2.window_update.window_size_increment", "Window Size Increment", d.FtUint32, d.WithMask(0x7fffffff), d.WithParentBits(32))
	hfH2Ping     = protoH2.Field("http2.ping", "Ping", d.FtBytes)
	hfH2GoLast   = protoH2.Field("http2.goaway.last_stream_id", "Last Stream-ID", d.FtUint32, d.WithMask(0x7fffffff), d.WithParentBits(32))
	hfH2GoErr    = protoH2.Field("http2.goaway.error", "Error", d.FtUint32, d.WithVS(h2Errors))
	hfH2GoData   = protoH2.Field("http2.goaway.addldata", "Additional Debug Data", d.FtBytes)
	hfH2Promised = protoH2.Field("http2.push_promise.promised_stream_id", "Promised-Stream-ID", d.FtUint32, d.WithMask(0x7fffffff), d.WithParentBits(32))
	hfH2Frag     = protoH2.Field("http2.header.block_fragment", "Header Block Fragment", d.FtBytes)
	hfH2ReqIn    = protoH2.Field("http2.request_in", "Request in frame", d.FtFrameNum)
	hfH2RespIn   = protoH2.Field("http2.response_in", "Response in frame", d.FtFrameNum)
	hfH2ReqFull  = protoH2.Field("http2.request.full_uri", "Full request URI", d.FtString)
	hfH2Time     = protoH2.Field("http2.time", "Time since request", d.FtRelTime)
	hfH2Reasm    = protoH2.Field("http2.body.reassembled.data", "Reassembled body", d.FtBytes)
	hfH2ReasmLn  = protoH2.Field("http2.body.reassembled.length", "Reassembled body length", d.FtUint32)
	hfH2ReasmIn  = protoH2.Field("http2.body.fragments", "Body fragments", d.FtNone)
	hfH2BodyData = protoH2.Field("http2.body.data", "Body data", d.FtBytes)
	hfH2BodyURI  = protoH2.Field("http2.body.uri", "Request URI", d.FtString)
	hfH2BodyType = protoH2.Field("http2.body.type", "Body content type", d.FtString)
	hfH2BodyDir  = protoH2.Field("http2.body.direction", "Body direction", d.FtString)
	hfH2Unknown  = protoH2.Field("http2.unknown", "Unknown payload", d.FtBytes)
	eiH2HPACK    = protoH2.Expert("http2.hpack.error", d.GroupMalformed, d.SevWarn, "HPACK decoding failed (missing dynamic table state?)")
	eiH2Preface  = protoH2.Expert("http2.bad_preface", d.GroupProtocol, d.SevWarn, "Invalid HTTP/2 connection preface")
	h2Handle     = d.RegisterHandle("http2", d.NewHandle(protoH2, dissectHTTP2))
)

func init() {
	TCPHeur.Add("http2_tcp", protoH2, func(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) bool {
		if tvb.Len() < 24 || string(tvb.Bytes(0, 24)) != h2Preface {
			return false
		}
		SetTCPAppHandle(pi, h2Handle)
		dissectHTTP2(tvb, pi, tree)
		return true
	})
	TCPPortTable.Add(8083, h2Handle)
}

// h2Msg is a decoded header block.
type h2Msg struct {
	fields  []hpack.HeaderField
	err     bool
	method  string
	path    string
	auth    string
	scheme  string
	status  string
	ctype   string
	cenc    string
	isReq   bool
	pushID  uint32
	stream  uint32
	reqFrm  uint32
	respFrm uint32
}

type h2Stream struct {
	req, resp *h2Msg
	reqFrame  uint32
	respFrame uint32
	reqTS     int64
	respTS    int64
	frags     [2][]d.FragRef
	size      [2]int
	ctype     string
	cenc      string
	grpc      bool
}

type h2Pending struct {
	stream uint32
	buf    []byte
	push   uint32
}

type h2Conn struct {
	dec      [2]*hpack.Decoder
	pending  [2]*h2Pending
	streams  map[uint32]*h2Stream
	clientIs int // direction index (0 = conversation A) of the client
}

type h2Body struct {
	frags  []d.FragRef
	total  int
	stream *h2Stream
	dir    int
}

func h2ConnOf(pi *d.PacketInfo) *h2Conn {
	if pi.Conv == nil {
		return &h2Conn{streams: map[uint32]*h2Stream{}}
	}
	c, _ := pi.Conv.Data(protoH2).(*h2Conn)
	if c == nil {
		c = &h2Conn{streams: map[uint32]*h2Stream{}}
		for i := range c.dec {
			c.dec[i] = hpack.NewDecoder(1<<20, nil)
		}
		if !pi.Visited {
			pi.Conv.SetData(protoH2, c)
		}
	}
	return c
}

func h2PDULen(tvb *d.Tvb, off int) int {
	if tvb.Remaining(off) >= 4 && string(tvb.Bytes(off, 4)) == "PRI " {
		return len(h2Preface)
	}
	l := int(tvb.U24(off))
	if l > 1<<24 {
		return -1
	}
	return 9 + l
}

func dissectHTTP2(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	c := h2ConnOf(pi)
	dir := 0
	if pi.Conv != nil && !pi.Conv.FromA(pi.Src, pi.SrcPort) {
		dir = 1
	}
	pt := tree.AddProtocol(protoH2, tvb, 0, -1)
	pi.SetProtocol("HTTP2")
	var infos []string
	idx := 0
	n := TCPDissectPDUs(tvb, pi, pt, 4, h2PDULen, func(t *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
		info := dissectH2Frame(t, pi, tree, c, dir, uint32(idx))
		idx++
		if info != "" {
			infos = append(infos, info)
		}
		return t.Len()
	})
	if len(infos) > 0 {
		pi.SetInfo(strings.Join(infos, ", "))
	} else if tvb.Len() > 0 {
		pi.SetInfo("HTTP2 (reassembling)")
	}
	return n
}

func h2Fields(h *h2Msg) {
	for _, f := range h.fields {
		switch f.Name {
		case ":method":
			h.method, h.isReq = f.Value, true
		case ":path":
			h.path = f.Value
		case ":authority":
			h.auth = f.Value
		case ":scheme":
			h.scheme = f.Value
		case ":status":
			h.status = f.Value
		case "content-type":
			h.ctype = f.Value
		case "content-encoding":
			h.cenc = f.Value
		}
	}
}

func dissectH2Frame(t *d.Tvb, pi *d.PacketInfo, tree *d.Node, c *h2Conn, dir int, idx uint32) string {
	sess := pi.Sess
	if string(t.Bytes(0, min(4, t.Len()))) == "PRI " {
		mt := tree.AddText(t, 0, t.Len(), "Magic")
		_, s := mt.AddString(hfH2Magic, t, 0, t.Len())
		if s != h2Preface {
			mt.AddExpert(eiH2Preface, "")
		}
		if !pi.Visited && pi.Conv != nil {
			c.clientIs = dir
		}
		return "Magic"
	}
	length := int(t.U24(0))
	typ := uint64(t.U8(3))
	flags := t.U8(4)
	sid := t.U32(5) & 0x7fffffff
	name := h2Types[typ]
	if name == "" {
		name = fmt.Sprintf("Unknown (%d)", typ)
	}
	ft := tree.AddText(t, 0, t.Len(), "")
	ft.AddUint(hfH2Length, t, 0, 3)
	ft.AddUint(hfH2Type, t, 3, 1)
	ft.AddUint(hfH2Flags, t, 4, 1)
	ft.AddBits(hfH2R, t, 5, 4, uint64(t.U32(5)))
	ft.AddBits(hfH2StreamID, t, 5, 4, uint64(t.U32(5)))
	label := fmt.Sprintf("%s[%d]", name, sid)
	body := t.Sub(9, length)
	h2ExtraFlags(ft, t, typ, flags)
	p := 0
	end := body.Len()
	var padLen int
	if (typ == 0 || typ == 1 || typ == 5) && flags&0x08 != 0 && end > 0 {
		padLen = int(body.U8(0))
		ft.AddUint(hfH2Padlen, body, 0, 1)
		p = 1
		end -= padLen
		if end < p {
			end = p
		}
	}
	info := label
	switch typ {
	case 0: // DATA
		ft.AddUintValue(hfH2Dlen, body, p, end-p, uint64(end-p))
		ft.AddBytes(hfH2Data, body, p, end-p)
		st := c.streams[sid]
		if st == nil && !pi.Visited {
			st = &h2Stream{}
			c.streams[sid] = st
		}
		var hb *h2Body
		if pi.Visited {
			hb, _ = sess.FrameData(protoH2, pi.Num, 100+idx).(*h2Body)
		} else if st != nil {
			ref := pi.Ref(t, 9+p, end-p, st.size[dir])
			if st.size[dir]+(end-p) <= maxReasm {
				st.frags[dir] = append(st.frags[dir], ref)
				st.size[dir] += end - p
			}
			if flags&1 != 0 {
				hb = &h2Body{frags: st.frags[dir], total: st.size[dir], stream: st, dir: dir}
				sess.SetFrameData(protoH2, pi.Num, 100+idx, hb)
			}
		}
		if st != nil {
			ct := st.ctype
			if ct == "" {
				if m := st.req; m != nil && dir == c.clientIs {
					ct = m.ctype
				}
			}
			if mt := strings.SplitN(ct, ";", 2)[0]; hb != nil && h2HasMediaDissector(mt) {
				info += " (" + mt + ")"
			}
		}
		if hb != nil {
			h2Body_(ft, pi, c, hb, dir)
		}
	case 1, 9, 5: // HEADERS, CONTINUATION, PUSH_PROMISE
		var push uint32
		if typ == 5 {
			push = body.U32(p) & 0x7fffffff
			ft.AddBits(hfH2Promised, body, p, 4, uint64(body.U32(p)))
			p += 4
		}
		if typ == 1 && flags&0x20 != 0 {
			ft.AddBits(hfH2ExclDep, body, p, 4, uint64(body.U32(p)))
			ft.AddBits(hfH2DepID, body, p, 4, uint64(body.U32(p)))
			ft.AddUint(hfH2Weight, body, p+4, 1)
			p += 5
		}
		frag := body.Bytes(p, end-p)
		ft.AddBytes(hfH2Frag, body, p, end-p)
		var msg *h2Msg
		if pi.Visited {
			msg, _ = sess.FrameData(protoH2, pi.Num, idx).(*h2Msg)
		} else {
			pend := c.pending[dir]
			if typ != 9 || pend == nil {
				pend = &h2Pending{stream: sid, push: push}
				c.pending[dir] = pend
			}
			pend.buf = append(pend.buf, frag...)
			if flags&0x04 != 0 {
				msg = &h2Msg{stream: sid, pushID: pend.push}
				dec := c.dec[dir]
				fields, err := dec.DecodeFull(pend.buf)
				msg.fields = fields
				msg.err = err != nil
				h2Fields(msg)
				c.pending[dir] = nil
				h2Link(pi, c, sid, dir, msg, flags)
				sess.SetFrameData(protoH2, pi.Num, idx, msg)
			}
		}
		if msg != nil {
			info = h2ShowHeaders(ft, pi, c, msg, label, dir)
			if flags&1 != 0 && typ != 9 {
				_ = flags
			}
		} else if flags&0x04 == 0 {
			info += " (header block continues)"
		}
	case 2: // PRIORITY
		ft.AddBits(hfH2ExclDep, body, 0, 4, uint64(body.U32(0)))
		ft.AddBits(hfH2DepID, body, 0, 4, uint64(body.U32(0)))
		ft.AddUint(hfH2Weight, body, 4, 1)
	case 3:
		_, ec := ft.AddUint(hfH2RstErr, body, 0, 4)
		info += " (" + h2Errors[ec] + ")"
	case 4:
		for o := 0; o+6 <= body.Len(); o += 6 {
			sn := ft.AddText(body, o, 6, "Settings")
			_, id := sn.AddUint(hfH2SetID, body, o, 2)
			_, v := sn.AddUint(hfH2SetVal, body, o+2, 4)
			if nf := hfH2SetNamed[id]; nf != nil {
				sn.AddValue(nf, body, o+2, 4, d.UintValue(d.FtUint32, v))
			}
			sn.SetText("Settings - %s: %d", h2Settings[id], v)

		}
	case 6:
		ft.AddBytes(hfH2Ping, body, 0, min(8, body.Len()))
		if flags&1 != 0 {
			info += " (ACK)"
		}
	case 7:
		ft.AddBits(hfH2GoLast, body, 0, 4, uint64(body.U32(0)))
		_, ec := ft.AddUint(hfH2GoErr, body, 4, 4)
		if body.Len() > 8 {
			ft.AddBytes(hfH2GoData, body, 8, body.Len()-8)
		}
		info += " (" + h2Errors[ec] + ")"
	case 8:
		ft.AddBits(hfH2WinInc, body, 0, 4, uint64(body.U32(0)))
		info += fmt.Sprintf(" (+%d)", body.U32(0)&0x7fffffff)
	default:
		if body.Len() > 0 {
			ft.AddBytes(hfH2Unknown, body, 0, body.Len())
		}
	}
	if (typ == 0 || typ == 1) && !(typ == 1 && dir == c.clientIs) {
		if st := c.streams[sid]; st != nil && st.req != nil {
			ft.AddGenerated(hfH2ReqFull, d.StringValue(st.req.scheme+"://"+st.req.auth+st.req.path))
		}
	}

	ft.SetText("HTTP2 Stream: %s, Stream ID: %d, Length %d", name, sid, length)
	return info
}

func h2ExtraFlags(ft *d.Node, t *d.Tvb, typ uint64, flags uint8) bool {
	switch typ {
	case 0:
		ft.AddBits(hfH2Padded, t, 4, 1, uint64(flags))
		ft.AddBits(hfH2EndStr, t, 4, 1, uint64(flags))
	case 1:
		ft.AddBits(hfH2Prio, t, 4, 1, uint64(flags))
		ft.AddBits(hfH2Padded, t, 4, 1, uint64(flags))
		ft.AddBits(hfH2EndHdr, t, 4, 1, uint64(flags))
		ft.AddBits(hfH2EndStr, t, 4, 1, uint64(flags))
	case 9, 5:
		ft.AddBits(hfH2EndHdr, t, 4, 1, uint64(flags))
		if typ == 5 {
			ft.AddBits(hfH2Padded, t, 4, 1, uint64(flags))
		}
	case 4, 6:
		ft.AddBits(hfH2Ack, t, 4, 1, uint64(flags))
	}
	return true
}

// h2Link pairs requests and responses (first pass).
func h2Link(pi *d.PacketInfo, c *h2Conn, sid uint32, dir int, msg *h2Msg, flags uint8) {
	if msg.pushID != 0 {
		return
	}
	st := c.streams[sid]
	if st == nil {
		st = &h2Stream{}
		c.streams[sid] = st
	}
	switch {
	case msg.isReq:
		st.req, st.reqFrame, st.reqTS = msg, pi.Num, pi.TS
		msg.reqFrm = pi.Num
	case msg.status != "" && st.resp == nil && !strings.HasPrefix(msg.status, "1"):
		st.resp, st.respFrame, st.respTS = msg, pi.Num, pi.TS
		st.ctype, st.cenc = msg.ctype, msg.cenc
		st.grpc = strings.HasPrefix(msg.ctype, "application/grpc")
		if st.req != nil {
			msg.reqFrm = st.reqFrame
			st.req.respFrm = pi.Num
		}
	case st.req != nil && st.resp != nil && msg.status == "":
		// Trailers: keep gRPC status visible.
	}
	if msg.isReq {
		st.grpc = strings.HasPrefix(msg.ctype, "application/grpc")
	}
}

var h2Special = map[string]*d.FieldDef{
	":method": hfH2Method, ":path": hfH2Path, ":authority": hfH2Auth, ":scheme": hfH2Scheme, ":status": hfH2Status,
	"content-type": hfH2CType, "content-encoding": hfH2CEnc, "content-length": hfH2CLen, "user-agent": hfH2UA,
	"server": hfH2Server, "cookie": hfH2Cookie, "accept": hfH2Accept, "referer": hfH2Referer,
}

func h2ShowHeaders(ft *d.Node, pi *d.PacketInfo, c *h2Conn, msg *h2Msg, label string, dir int) string {
	if msg.err {
		ft.AddExpert(eiH2HPACK, "")
	}
	for _, f := range msg.fields {
		hn := ft.AddText(nil, 0, 0, "Header: %s: %s", f.Name, f.Value)
		hn.AddValue(hfH2HName, nil, 0, 0, d.StringValue(f.Name))
		hn.AddValue(hfH2HValue, nil, 0, 0, d.StringValue(f.Value))
		if hf := h2Special[f.Name]; hf != nil {
			hn.AddValue(hf, nil, 0, 0, d.StringValue(f.Value))
		}
	}
	info := label
	switch {
	case msg.isReq:
		info += ": " + msg.method + " " + msg.path
		full := msg.scheme + "://" + msg.auth + msg.path
		ft.AddGenerated(hfH2ReqFull, d.StringValue(full))
		if msg.respFrm != 0 {
			ft.AddGenerated(hfH2RespIn, d.Value{U: uint64(msg.respFrm)}).SetLink(msg.respFrm)
		}
	case msg.status != "":
		code, _ := strconv.Atoi(msg.status)
		info += ": " + msg.status
		if txt := http.StatusText(code); txt != "" {
			info += " " + txt
		}
		if msg.reqFrm != 0 {
			ft.AddGenerated(hfH2ReqIn, d.Value{U: uint64(msg.reqFrm)}).SetLink(msg.reqFrm)
			if st := c.streams[msg.stream]; st != nil && st.respTS >= st.reqTS {
				ft.AddGenerated(hfH2Time, d.RelTimeValue(st.respTS-st.reqTS))
			}
		}
	}
	return info
}

func h2Body_(ft *d.Node, pi *d.PacketInfo, c *h2Conn, hb *h2Body, dir int) {
	data := pi.Sess.Assemble(hb.frags, hb.total)
	st := hb.stream
	var ct, enc string
	if dir == c.clientIs {
		if st.req != nil {
			ct, enc = st.req.ctype, st.req.cenc
		}
	} else {
		ct, enc = st.ctype, st.cenc
	}
	if len(hb.frags) > 1 {
		rn := ft.AddText(nil, 0, 0, "Reassembled body (%d bytes in %d DATA frames)", hb.total, len(hb.frags))
		for _, f := range hb.frags {
			rn.AddText(nil, 0, 0, "Frame %d: %d bytes", f.Frame, f.Len).SetLink(f.Frame)
		}
	}
	if enc != "" {
		if dec, err := decompress(enc, data); err == nil {
			data = dec
		}
	}
	src := pi.AddSource("Reassembled HTTP2 body", data)
	rn := ft.AddText(src, 0, src.Len(), "Body (%d bytes)", src.Len())
	rn.AddGenerated(hfH2ReasmLn, d.UintValue(d.FtUint32, uint64(src.Len())))
	mt := strings.TrimSpace(strings.SplitN(ct, ";", 2)[0])
	if bn, _ := rn.AddBytes(hfH2BodyData, src, 0, src.Len()); bn != nil {
		bn.SetHidden()
	}
	if len(hb.frags) > 1 {
		rn.AddBytes(hfH2Reasm, src, 0, src.Len())
	}
	uri := ""
	if st.req != nil {
		uri = st.req.scheme + "://" + st.req.auth + st.req.path
	}
	rn.AddGenerated(hfH2BodyURI, d.StringValue(uri)).SetHidden()
	rn.AddGenerated(hfH2BodyType, d.StringValue(mt)).SetHidden()
	rn.AddGenerated(hfH2BodyDir, d.StringValue(map[bool]string{true: "request", false: "response"}[dir == c.clientIs])).SetHidden()
	if src.Len() > 0 {
		DissectMedia(mt, src, pi, rn)
	}
}

// h2HasMediaDissector reports whether the body of a type is dissected, which
// makes Wireshark append the content type to the Info column.
func h2HasMediaDissector(mt string) bool {
	return strings.HasPrefix(mt, "text/") || strings.HasSuffix(mt, "+json") || mt == "application/json" || strings.HasSuffix(mt, "+xml") ||
		mt == "application/xml" || mt == "application/x-www-form-urlencoded" || mt == "application/javascript"
}
