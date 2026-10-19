package proto

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	d "github.com/poseydon/lazysniffer/internal/dissect"
)

var sipMethods = []string{"INVITE", "ACK", "BYE", "CANCEL", "OPTIONS", "REGISTER", "PRACK", "SUBSCRIBE", "NOTIFY", "PUBLISH", "INFO", "REFER", "MESSAGE", "UPDATE"}

var (
	protoSIP      = d.RegisterProto("Session Initiation Protocol", "SIP", "sip")
	hfSIPReqLine  = protoSIP.Field("sip.Request-Line", "Request-Line", d.FtString)
	hfSIPMethod   = protoSIP.Field("sip.Method", "Method", d.FtString)
	hfSIPRURI     = protoSIP.Field("sip.r-uri", "Request-URI", d.FtString)
	hfSIPStatusLn = protoSIP.Field("sip.Status-Line", "Status-Line", d.FtString)
	hfSIPStatus   = protoSIP.Field("sip.Status-Code", "Status-Code", d.FtUint16)
	hfSIPCallID   = protoSIP.Field("sip.Call-ID", "Call-ID", d.FtString)
	hfSIPFrom     = protoSIP.Field("sip.From", "From", d.FtString)
	hfSIPFromUser = protoSIP.Field("sip.from.user", "SIP from address User Part", d.FtString)
	hfSIPTo       = protoSIP.Field("sip.To", "To", d.FtString)
	hfSIPToUser   = protoSIP.Field("sip.to.user", "SIP to address User Part", d.FtString)
	hfSIPCSeq     = protoSIP.Field("sip.CSeq", "CSeq", d.FtString)
	hfSIPCSeqMeth = protoSIP.Field("sip.CSeq.method", "Method", d.FtString)
	hfSIPVia      = protoSIP.Field("sip.Via", "Via", d.FtString)
	hfSIPContact  = protoSIP.Field("sip.Contact", "Contact", d.FtString)
	hfSIPUA       = protoSIP.Field("sip.User-Agent", "User-Agent", d.FtString)
	hfSIPCType    = protoSIP.Field("sip.Content-Type", "Content-Type", d.FtString)
	hfSIPCLen     = protoSIP.Field("sip.Content-Length", "Content-Length", d.FtUint32)
	hfSIPAuth     = protoSIP.Field("sip.Authorization", "Authorization", d.FtString)
	hfSIPHeader   = protoSIP.Field("sip.header", "Header", d.FtString)
	hfSIPBody     = protoSIP.Field("sip.msg_body", "Message Body", d.FtBytes)
	sipHandle     = d.RegisterHandle("sip", d.NewHandle(protoSIP, dissectSIPUDP))
	sipTCP        = d.RegisterHandle("sip-tcp", d.NewHandle(protoSIP, dissectSIPTCP))

	protoSDP     = d.RegisterProto("Session Description Protocol", "SDP", "sdp")
	hfSDPVersion = protoSDP.Field("sdp.version", "Session Description Protocol Version (v)", d.FtString)
	hfSDPOwner   = protoSDP.Field("sdp.owner", "Owner/Creator, Session Id (o)", d.FtString)
	hfSDPUser    = protoSDP.Field("sdp.owner.username", "Owner Username", d.FtString)
	hfSDPName    = protoSDP.Field("sdp.session_name", "Session Name (s)", d.FtString)
	hfSDPConn    = protoSDP.Field("sdp.connection_info", "Connection Information (c)", d.FtString)
	hfSDPAddr    = protoSDP.Field("sdp.connection_info.address", "Connection Address", d.FtString)
	hfSDPMedia   = protoSDP.Field("sdp.media", "Media Description, name and address (m)", d.FtString)
	hfSDPMType   = protoSDP.Field("sdp.media.media", "Media Type", d.FtString)
	hfSDPMPort   = protoSDP.Field("sdp.media.port", "Media Port", d.FtUint16)
	hfSDPMProto  = protoSDP.Field("sdp.media.proto", "Media Protocol", d.FtString)
	hfSDPMFmt    = protoSDP.Field("sdp.media.format", "Media Format", d.FtString)
	hfSDPAttr    = protoSDP.Field("sdp.media_attr", "Media Attribute (a)", d.FtString)
	hfSDPRtpmap  = protoSDP.Field("sdp.mime.type", "MIME Type", d.FtString)
	hfSDPTime    = protoSDP.Field("sdp.time", "Time Description, active time (t)", d.FtString)
)

func init() {
	UDPPortTable.Add(5060, sipHandle)
	TCPPortTable.Add(5060, sipTCP)
	UDPPortTable.Add(5061, sipHandle)
	MediaTypes["application/sdp"] = d.NewHandle(protoSDP, dissectSDP)
}

func isSIP(raw []byte) bool {
	s := string(raw[:min(len(raw), 16)])
	if strings.HasPrefix(s, "SIP/2.0") {
		return true
	}
	for _, m := range sipMethods {
		if strings.HasPrefix(s, m+" ") {
			return true
		}
	}
	return false
}

func dissectSIPUDP(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	if tvb.Len() < 10 || !isSIP(tvb.Raw()) {
		return 0
	}
	_, info := dissectSIPMessage(tvb, 0, pi, tree)
	pi.SetProtocol(sipProtoName(tvb))
	pi.SetInfo(info + " |")
	return tvb.Len()
}

func dissectSIPTCP(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	var infos []string
	off := 0
	for off < tvb.Len() {
		raw := tvb.Raw()[off:]
		if !isSIP(raw) {
			break
		}
		he := strings.Index(string(raw), "\r\n\r\n")
		if he < 0 {
			pi.Desegment(off, d.DesegmentOneMore)
			break
		}
		cl := 0
		for _, l := range strings.Split(string(raw[:he]), "\r\n") {
			if k, v, ok := strings.Cut(l, ":"); ok && (strings.EqualFold(strings.TrimSpace(k), "Content-Length") || strings.TrimSpace(k) == "l") {
				cl, _ = strconv.Atoi(strings.TrimSpace(v))
			}
		}
		total := he + 4 + cl
		if len(raw) < total {
			pi.Desegment(off, total-len(raw))
			break
		}
		_, info := dissectSIPMessage(tvb.Sub(off, total), 0, pi, tree)
		infos = append(infos, info)
		off += total
	}
	if len(infos) == 0 {
		return 0
	}
	pi.SetProtocol("SIP")
	pi.SetInfo(strings.Join(infos, " | ") + " |")
	return tvb.Len()
}

var sipCompact = map[string]string{"i": "call-id", "f": "from", "t": "to", "v": "via", "m": "contact", "c": "content-type", "l": "content-length"}

func dissectSIPMessage(tvb *d.Tvb, off int, pi *d.PacketInfo, tree *d.Node) (int, string) {
	raw := tvb.Raw()
	he := strings.Index(string(raw), "\r\n\r\n")
	hdrEnd := len(raw)
	if he >= 0 {
		hdrEnd = he + 4
	}
	st := tree.AddProtocol(protoSIP, tvb, 0, -1)
	lines := strings.Split(strings.TrimRight(string(raw[:hdrEnd]), "\r\n"), "\r\n")
	first := lines[0]
	var cseqMethod string
	info := first
	if strings.HasPrefix(first, "SIP/2.0") {
		code, _ := strconv.Atoi(strings.Fields(first + " 0 0")[1])
		sl := st.AddText(tvb, 0, len(first)+2, "Status-Line: %s", first)
		sl.AddValue(hfSIPStatusLn, tvb, 0, len(first), d.StringValue(first))
		sl.AddUintValue(hfSIPStatus, tvb, 8, 3, uint64(code))
		info = "Status: " + strings.TrimPrefix(first, "SIP/2.0 ")
		cseqMethod = ""
		for _, l := range lines[1:] {
			if k, v, ok := strings.Cut(l, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "CSeq") {
				if f := strings.Fields(v); len(f) == 2 {
					cseqMethod = f[1]
				}
			}
		}
		if code >= 200 && cseqMethod != "" {
			info += " (" + cseqMethod + ")"
		}
	} else {
		f := strings.Fields(first)
		rl := st.AddText(tvb, 0, len(first)+2, "Request-Line: %s", first)
		rl.AddValue(hfSIPReqLine, tvb, 0, len(first), d.StringValue(first))
		if len(f) >= 2 {
			rl.AddValue(hfSIPMethod, tvb, 0, len(f[0]), d.StringValue(f[0]))
			rl.AddValue(hfSIPRURI, tvb, len(f[0])+1, len(f[1]), d.StringValue(f[1]))
			info = "Request: " + f[0] + " " + f[1]
		}
	}
	pos := len(first) + 2
	var ctype string
	var cl int
	var callID string
	hn := st.AddText(tvb, pos, max(hdrEnd-pos-2, 0), "Message Header")
	for _, l := range lines[1:] {
		start := pos
		pos += len(l) + 2
		name, val, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		val = strings.TrimSpace(val)
		key := strings.ToLower(name)
		if full, ok := sipCompact[key]; ok {
			key = full
		}
		line := hn.AddText(tvb, start, len(l)+2, "%s: %s", name, val)
		sv := d.StringValue(val)
		switch key {
		case "call-id":
			line.AddValue(hfSIPCallID, nil, 0, 0, sv)
			callID = val
		case "from":
			line.AddValue(hfSIPFrom, nil, 0, 0, sv)
			line.AddValue(hfSIPFromUser, nil, 0, 0, d.StringValue(sipUser(val)))
		case "to":
			line.AddValue(hfSIPTo, nil, 0, 0, sv)
			line.AddValue(hfSIPToUser, nil, 0, 0, d.StringValue(sipUser(val)))
		case "cseq":
			line.AddValue(hfSIPCSeq, nil, 0, 0, sv)
			if f := strings.Fields(val); len(f) == 2 {
				line.AddValue(hfSIPCSeqMeth, nil, 0, 0, d.StringValue(f[1]))
			}
		case "via":
			line.AddValue(hfSIPVia, nil, 0, 0, sv)
		case "contact":
			line.AddValue(hfSIPContact, nil, 0, 0, sv)
		case "user-agent", "server":
			line.AddValue(hfSIPUA, nil, 0, 0, sv)
		case "authorization", "proxy-authorization":
			line.AddValue(hfSIPAuth, nil, 0, 0, sv)
		case "content-type":
			line.AddValue(hfSIPCType, nil, 0, 0, sv)
			ctype = strings.ToLower(strings.TrimSpace(strings.SplitN(val, ";", 2)[0]))
		case "content-length":
			cl, _ = strconv.Atoi(val)
			line.AddValue(hfSIPCLen, nil, 0, 0, d.UintValue(d.FtUint32, uint64(cl)))
		default:
			line.AddValue(hfSIPHeader, nil, 0, 0, sv)
		}
	}
	if hdrEnd < len(raw) {
		body := tvb.Sub(hdrEnd, len(raw)-hdrEnd)
		bt := st.AddText(body, 0, body.Len(), "Message Body")
		bt.AddBytes(hfSIPBody, body, 0, body.Len())
		if ctype != "" {
			DissectMedia(ctype, body, pi, bt)
		}
	}
	_ = callID
	return len(raw), info
}

func sipUser(v string) string {
	i := strings.Index(v, "sip:")
	if i < 0 {
		i = strings.Index(v, "sips:")
		if i < 0 {
			return ""
		}
		i++
	}
	u := v[i+4:]
	if j := strings.IndexAny(u, "@>;"); j >= 0 && u[j] == '@' {
		return u[:j]
	}
	return ""
}

// ---------------- SDP ----------------

// rtpExpect records the media endpoints announced in SDP so that the RTP
// and RTCP packets to them are decoded.
type rtpExpect struct {
	endpoints map[string]uint32 // "ip:port" → frame of the SDP
}

func rtpState(pi *d.PacketInfo) *rtpExpect {
	s, _ := pi.Sess.ProtoState(protoRTP).(*rtpExpect)
	if s == nil && !pi.Visited {
		s = &rtpExpect{endpoints: map[string]uint32{}}
		pi.Sess.SetProtoState(protoRTP, s)
	}
	return s
}

func dissectSDP(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	st := tree.AddProtocol(protoSDP, tvb, 0, -1)
	raw := string(tvb.Raw())
	pos := 0
	var session netip.Addr
	var mediaPorts []int
	var connPerMedia = map[int]netip.Addr{}
	cur := -1
	for _, l := range strings.Split(raw, "\n") {
		line := strings.TrimRight(l, "\r")
		ln := st.AddText(tvb, pos, len(l)+1, "%s", line)
		pos += len(l) + 1
		if len(line) < 3 || line[1] != '=' {
			continue
		}
		v := line[2:]
		sv := d.StringValue(v)
		switch line[0] {
		case 'v':
			ln.AddValue(hfSDPVersion, nil, 0, 0, sv)
		case 'o':
			ln.AddValue(hfSDPOwner, nil, 0, 0, sv)
			ln.AddValue(hfSDPUser, nil, 0, 0, d.StringValue(strings.Fields(v + " ")[0]))
		case 's':
			ln.AddValue(hfSDPName, nil, 0, 0, sv)
		case 't':
			ln.AddValue(hfSDPTime, nil, 0, 0, sv)
		case 'c':
			ln.AddValue(hfSDPConn, nil, 0, 0, sv)
			f := strings.Fields(v)
			if len(f) >= 3 {
				addr := strings.SplitN(f[2], "/", 2)[0]
				ln.AddValue(hfSDPAddr, nil, 0, 0, d.StringValue(addr))
				if a, err := netip.ParseAddr(addr); err == nil {
					if cur >= 0 {
						connPerMedia[cur] = a
					} else {
						session = a
					}
				}
			}
		case 'm':
			ln.AddValue(hfSDPMedia, nil, 0, 0, sv)
			f := strings.Fields(v)
			if len(f) >= 4 {
				ln.AddValue(hfSDPMType, nil, 0, 0, d.StringValue(f[0]))
				port, _ := strconv.Atoi(strings.SplitN(f[1], "/", 2)[0])
				ln.AddValue(hfSDPMPort, nil, 0, 0, d.UintValue(d.FtUint16, uint64(port)))
				ln.AddValue(hfSDPMProto, nil, 0, 0, d.StringValue(f[2]))
				for _, fm := range f[3:] {
					ln.AddValue(hfSDPMFmt, nil, 0, 0, d.StringValue(fm))
				}
				mediaPorts = append(mediaPorts, port)
				cur = len(mediaPorts) - 1
			}
		case 'a':
			ln.AddValue(hfSDPAttr, nil, 0, 0, sv)
			if strings.HasPrefix(v, "rtpmap:") {
				if f := strings.Fields(v); len(f) == 2 {
					ln.AddValue(hfSDPRtpmap, nil, 0, 0, d.StringValue(f[1]))
				}
			}
		}
	}
	if !pi.Visited {
		if rs := rtpState(pi); rs != nil {
			for i, port := range mediaPorts {
				if port == 0 {
					continue
				}
				a := connPerMedia[i]
				if !a.IsValid() {
					a = session
				}
				if a.IsValid() {
					rs.endpoints[fmt.Sprintf("%s:%d", a, port)] = pi.Num
					rs.endpoints[fmt.Sprintf("%s:%d", a, port+1)] = pi.Num // RTCP
				}
			}
		}
	}
	return tvb.Len()
}

func sipProtoName(tvb *d.Tvb) string {
	if strings.Contains(strings.ToLower(string(tvb.Raw())), "content-type: application/sdp") {
		return "SIP/SDP"
	}
	return "SIP"
}
