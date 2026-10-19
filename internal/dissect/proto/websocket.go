package proto

import (
	"fmt"
	"strings"
	"unicode/utf8"

	d "github.com/poseydon/lazysniffer/internal/dissect"
)

var (
	wsOpcodes = map[uint64]string{0: "Continuation", 1: "Text", 2: "Binary", 8: "Connection Close", 9: "Ping", 10: "Pong"}
	wsClose   = map[uint64]string{1000: "Normal Closure", 1001: "Going Away", 1002: "Protocol error", 1003: "Unsupported Data",
		1005: "No Status Rcvd", 1006: "Abnormal Closure", 1007: "Invalid frame payload data", 1008: "Policy Violation",
		1009: "Message Too Big", 1010: "Mandatory Ext.", 1011: "Internal Server", 1015: "TLS handshake"}

	protoWS       = d.RegisterProto("WebSocket", "WebSocket", "websocket")
	hfWSFin       = protoWS.Field("websocket.fin", "Fin", d.FtBool, d.WithMask(0x80), d.WithParentBits(8), d.WithTFS(d.TFSTrue))
	hfWSRsv       = protoWS.Field("websocket.rsv", "Reserved", d.FtUint8, d.WithMask(0x70), d.WithBase(d.BaseHex))
	hfWSPMC       = protoWS.Field("websocket.pmc", "Per-Message Compressed", d.FtBool, d.WithMask(0x40), d.WithParentBits(8), d.WithTFS(d.TFSTrue))
	hfWSOpcode    = protoWS.Field("websocket.opcode", "Opcode", d.FtUint8, d.WithMask(0x0f), d.WithVS(wsOpcodes))
	hfWSMask      = protoWS.Field("websocket.mask", "Mask", d.FtBool, d.WithMask(0x80), d.WithParentBits(8), d.WithTFS(d.TFSTrue))
	hfWSLen       = protoWS.Field("websocket.payload_length", "Payload length", d.FtUint8, d.WithMask(0x7f))
	hfWSLen16     = protoWS.Field("websocket.payload_length_ext_16", "Extended Payload length (16 bits)", d.FtUint16)
	hfWSLen64     = protoWS.Field("websocket.payload_length_ext_64", "Extended Payload length (64 bits)", d.FtUint64)
	hfWSMaskKey   = protoWS.Field("websocket.masking_key", "Masking-Key", d.FtBytes)
	hfWSPayload   = protoWS.Field("websocket.payload", "Payload", d.FtBytes)
	hfWSUnmasked  = protoWS.Field("websocket.unmasked_payload", "Unmasked Payload", d.FtBytes)
	hfWSText      = protoWS.Field("websocket.payload.text", "Text", d.FtString)
	hfWSCloseCode = protoWS.Field("websocket.payload.close.status_code", "Status code", d.FtUint16, d.WithVS(wsClose))
	hfWSCloseRsn  = protoWS.Field("websocket.payload.close.reason", "Reason", d.FtString)
	hfWSPing      = protoWS.Field("websocket.payload.ping", "Ping", d.FtBytes)
	wsHandle      = d.RegisterHandle("websocket", d.NewHandle(protoWS, dissectWebSocket))
)

func dissectWebSocket(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	return TCPDissectPDUs(tvb, pi, tree, 2, wsFrameLen, dissectWSFrame)
}

func wsFrameLen(tvb *d.Tvb, off int) int {
	b1 := tvb.U8(off + 1)
	n := 2
	l := int(b1 & 0x7f)
	switch l {
	case 126:
		if !tvb.Has(off+2, 2) {
			return 4 // ask for the extended length first
		}
		n += 2
		l = int(tvb.U16(off + 2))
	case 127:
		if !tvb.Has(off+2, 8) {
			return 10
		}
		n += 8
		v := tvb.U64(off + 2)
		if v > maxReasm {
			return -1
		}
		l = int(v)
	}
	if b1&0x80 != 0 {
		n += 4
	}
	return n + l
}

// wsDeflate keeps permessage-deflate state per direction (first pass).
type wsDeflate struct{ dict [2][]byte }

func dissectWSFrame(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	b0, b1 := tvb.U8(0), tvb.U8(1)
	op := uint64(b0 & 0x0f)
	wt := tree.AddProtocol(protoWS, tvb, 0, -1)
	pi.SetProtocol("WebSocket")
	wt.AddBits(hfWSFin, tvb, 0, 1, uint64(b0))
	wt.AddBits(hfWSRsv, tvb, 0, 1, uint64(b0))
	wt.AddBits(hfWSPMC, tvb, 0, 1, uint64(b0))
	wt.AddBits(hfWSOpcode, tvb, 0, 1, uint64(b0))
	wt.AddBits(hfWSMask, tvb, 1, 1, uint64(b1))
	wt.AddBits(hfWSLen, tvb, 1, 1, uint64(b1))
	off := 2
	switch b1 & 0x7f {
	case 126:
		wt.AddUint(hfWSLen16, tvb, 2, 2)
		off = 4
	case 127:
		wt.AddUint(hfWSLen64, tvb, 2, 8)
		off = 10
	}
	var key []byte
	if b1&0x80 != 0 {
		_, key = wt.AddBytes(hfWSMaskKey, tvb, off, 4)
		off += 4
	}
	name := wsOpcodes[op]
	if name == "" {
		name = fmt.Sprintf("Unknown (%d)", op)
	}
	flags := ""
	if b0&0x80 != 0 {
		flags += " [FIN]"
	}
	if key != nil {
		flags += " [MASKED]"
	}
	wt.SetText("WebSocket %s%s", name, flags)
	pi.AppendInfoSep(" ", "WebSocket "+name+flags)
	payload := tvb.Sub(off, -1)
	if payload.Len() == 0 {
		return tvb.Len()
	}
	wt.AddBytes(hfWSPayload, payload, 0, payload.Len())
	data := payload.Raw()
	if key != nil {
		un := make([]byte, len(data))
		for i, c := range data {
			un[i] = c ^ key[i%4]
		}
		data = un
	}
	src := payload
	if key != nil {
		src = pi.AddSource("Unmasked data", data)
		wt.AddBytes(hfWSUnmasked, src, 0, src.Len())
	}
	if b0&0x40 != 0 && (op == 1 || op == 2) {
		if dec, err := inflateRaw(data, nil); err == nil {
			data = dec
			src = pi.AddSource("Decompressed data", dec)
		}
	}
	switch op {
	case 1:
		text := string(data)
		if !utf8.ValidString(text) {
			text = strings.ToValidUTF8(text, "�")
		}
		wt.AddValue(hfWSText, src, 0, src.Len(), d.StringValue(text)).SetText("Text: %s", text)
		if t := strings.TrimSpace(text); strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
			pi.Call(jsonHandle, src, tree)
		}
	case 8:
		if len(data) >= 2 {
			wt.AddUint(hfWSCloseCode, src, 0, 2)
			if len(data) > 2 {
				wt.AddString(hfWSCloseRsn, src, 2, len(data)-2)
			}
		}
	case 9, 10:
		wt.AddBytes(hfWSPing, src, 0, src.Len())
	}
	return tvb.Len()
}
