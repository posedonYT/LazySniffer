package proto

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	d "github.com/poseydon/lazysniffer/internal/dissect"
)

// lineSpec describes a line-oriented client/server protocol.
type lineSpec struct {
	proto     *d.Proto
	short     string
	ports     []uint64
	reqCmd    *d.FieldDef
	reqArg    *d.FieldDef
	respCode  *d.FieldDef // numeric code (nil for +OK/-ERR protocols)
	respArg   *d.FieldDef
	respInd   *d.FieldDef // POP3 +OK / -ERR
	line      *d.FieldDef
	response  func(line string) (code, rest string, ok bool)
	startTLS  func(client, server string) bool // client command and server reply that switch to TLS
	isClient  func(pi *d.PacketInfo) bool
	multiline bool // 3-digit codes with "-" continuation
}

type lineState struct {
	lastCmd [2]string
	inData  bool
	auth    int // SMTP AUTH LOGIN stage
}

func numericResp(line string) (string, string, bool) {
	if len(line) >= 3 && line[0] >= '1' && line[0] <= '9' && line[1] >= '0' && line[1] <= '9' && line[2] >= '0' && line[2] <= '9' {
		if len(line) == 3 {
			return line[:3], "", true
		}
		if line[3] == ' ' || line[3] == '-' {
			return line[:3], line[4:], true
		}
	}
	return "", "", false
}

func clientByPort(ports []uint64) func(pi *d.PacketInfo) bool {
	return func(pi *d.PacketInfo) bool {
		for _, p := range ports {
			if uint64(pi.DstPort) == p {
				return true
			}
		}
		for _, p := range ports {
			if uint64(pi.SrcPort) == p {
				return false
			}
		}
		return pi.SrcPort > pi.DstPort
	}
}

func (sp *lineSpec) dissect(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	var st *lineState
	if pi.Conv != nil {
		st, _ = pi.Conv.Data(sp.proto).(*lineState)
		if st == nil {
			st = &lineState{}
			if !pi.Visited {
				pi.Conv.SetData(sp.proto, st)
			}
		}
	} else {
		st = &lineState{}
	}
	client := sp.isClient(pi)
	dir := 0
	if !client {
		dir = 1
	}
	pt := tree.AddProtocol(sp.proto, tvb, 0, -1)
	pi.SetProtocol(sp.short)
	var infos []string
	raw := tvb.Raw()
	// SMTP DATA state is first-pass state: remember it per frame.
	inData := st.inData
	if pi.Visited {
		inData, _ = pi.Sess.FrameData(sp.proto, pi.Num, 0).(bool)
	} else {
		pi.Sess.SetFrameData(sp.proto, pi.Num, 0, inData)
	}
	for off := 0; off < len(raw); {
		nl := strings.IndexByte(string(raw[off:]), '\n')
		if nl < 0 {
			if len(raw)-off < 16<<10 {
				pi.Desegment(off, d.DesegmentOneMore)
				if off == 0 {
					return tvb.Len()
				}
			}
			nl = len(raw) - off - 1
		}
		l := nl + 1
		line := strings.TrimRight(string(raw[off:off+nl]), "\r")
		if client && inData {
			// SMTP DATA body (kept as one block until the terminating dot).
			end := strings.Index(string(raw[off:]), "\r\n.\r\n")
			bodyLen := len(raw) - off
			if end >= 0 {
				bodyLen = end + 5
			}
			bn := pt.AddText(tvb, off, bodyLen, "C: DATA fragment, %d bytes", bodyLen)
			_ = bn
			if end >= 0 {
				inData = false
				if !pi.Visited {
					st.inData = false
				}
			}
			infos = append(infos, fmt.Sprintf("C: DATA fragment, %d bytes", bodyLen))
			off += bodyLen
			continue
		}
		ln := pt.AddText(tvb, off, l, "%s", line)
		if client {
			cmd, arg, _ := strings.Cut(line, " ")
			if sp.short == "IMAP" {
				// "tag COMMAND args"
				tag := cmd
				cmd, arg, _ = strings.Cut(arg, " ")
				ln.SetText("Request: %s", line)
				if sp.line != nil {
					ln.AddValue(sp.line, nil, 0, 0, d.StringValue(line+"\r\n"))
				}
				_ = tag
			} else {
				ln.SetText("Request: %s", line)
			}
			if sp.reqCmd != nil {
				ln.AddValue(sp.reqCmd, nil, 0, 0, d.StringValue(strings.ToUpper(cmd)))
			}
			if sp.reqArg != nil && arg != "" {
				ln.AddValue(sp.reqArg, nil, 0, 0, d.StringValue(arg))
			}
			if !pi.Visited {
				st.lastCmd[dir] = strings.ToUpper(cmd)
				if sp.short == "SMTP" && strings.EqualFold(cmd, "DATA") {
					st.inData = true
				}
			}
			if sp.short == "SMTP" || sp.short == "POP" {
				infos = append(infos, "C: "+line)
			} else {
				infos = append(infos, "Request: "+line)
			}
			if sp.short == "FTP" {
				ftpControlRequest(pi, cmd, arg)
			}
		} else {
			code, rest, ok := sp.response(line)
			if ok {
				ln.SetText("Response: %s", line)
				if sp.respCode != nil {
					ln.AddValue(sp.respCode, nil, 0, 0, d.UintValue(d.FtUint16, atoiU(code)))
				}
				if sp.respInd != nil {
					ln.AddValue(sp.respInd, nil, 0, 0, d.StringValue(code))
				}
				if sp.respArg != nil {
					ln.AddValue(sp.respArg, nil, 0, 0, d.StringValue(rest))
				}
				if sp.line != nil && sp.short == "IMAP" {
					ln.AddValue(sp.line, nil, 0, 0, d.StringValue(line+"\r\n"))
				}
				if sp.short == "FTP" {
					ftpPassiveFields(ln, code, rest)
					ftpControlResponse(pi, code, rest, st.lastCmd[0])
					infos = append(infos, "Response: "+line)
				} else if sp.short == "SMTP" || sp.short == "POP" {
					infos = append(infos, "S: "+line)
				} else {
					infos = append(infos, "Response: "+line)
				}
				if sp.startTLS != nil && !pi.Visited && sp.startTLS(st.lastCmd[0], line) {
					SetTCPAppHandle(pi, FindHandleLazy("tls"))
				}
			} else {
				ln.SetText("Response: %s", line)
				infos = append(infos, "Response: "+line)
			}
		}
		off += l
	}
	if len(infos) > 0 {
		if sp.short == "SMTP" || sp.short == "POP" {
			// Wireshark prefixes only the first item with C: / S:
			for i := 1; i < len(infos); i++ {
				infos[i] = strings.TrimPrefix(strings.TrimPrefix(infos[i], "C: "), "S: ")
			}
		}
		pi.SetInfo(strings.Join(infos, " | "))
	}
	return tvb.Len()
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func atoiU(s string) uint64 {
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}

var (
	// ---- FTP ----
	protoFTP      = d.RegisterProto("File Transfer Protocol (FTP)", "FTP", "ftp")
	hfFTPReqCmd   = protoFTP.Field("ftp.request.command", "Request command", d.FtString)
	hfFTPReqArg   = protoFTP.Field("ftp.request.arg", "Request arg", d.FtString)
	hfFTPRespCode = protoFTP.Field("ftp.response.code", "Response code", d.FtUint16)
	hfFTPRespArg  = protoFTP.Field("ftp.response.arg", "Response arg", d.FtString)
	hfFTPPassive  = protoFTP.Field("ftp.passive.port", "Passive port", d.FtUint16)
	hfFTPPassIP   = protoFTP.Field("ftp.passive.ip", "Passive IP address", d.FtIPv4)
	protoFTPData  = d.RegisterProto("FTP Data", "FTP-DATA", "ftp-data")
	hfFTPDSetup   = protoFTPData.Field("ftp-data.setup-frame", "Setup frame", d.FtFrameNum)
	hfFTPDCmd     = protoFTPData.Field("ftp-data.command", "Setup command", d.FtString)
	hfFTPDLen     = protoFTPData.Field("ftp-data.len", "Data length", d.FtUint32)
	hfFTPDData    = protoFTPData.Field("ftp-data.data", "Data", d.FtBytes)

	// ---- SMTP ----
	protoSMTP    = d.RegisterProto("Simple Mail Transfer Protocol", "SMTP", "smtp")
	hfSMTPReqCmd = protoSMTP.Field("smtp.req.command", "Command", d.FtString)
	hfSMTPReqPar = protoSMTP.Field("smtp.req.parameter", "Request parameter", d.FtString)
	hfSMTPRespCd = protoSMTP.Field("smtp.response.code", "Response code", d.FtUint16)
	hfSMTPRespPa = protoSMTP.Field("smtp.rsp.parameter", "Response parameter", d.FtString)

	// ---- POP3 ----
	protoPOP     = d.RegisterProto("Post Office Protocol", "POP", "pop")
	hfPOPReqCmd  = protoPOP.Field("pop.request.command", "Request command", d.FtString)
	hfPOPReqPar  = protoPOP.Field("pop.request.parameter", "Request parameter", d.FtString)
	hfPOPRespInd = protoPOP.Field("pop.response.indicator", "Response indicator", d.FtString)
	hfPOPRespDes = protoPOP.Field("pop.response.description", "Response description", d.FtString)

	// ---- IMAP ----
	protoIMAP  = d.RegisterProto("Internet Message Access Protocol", "IMAP", "imap")
	hfIMAPCmd  = protoIMAP.Field("imap.request.command", "Request command", d.FtString)
	hfIMAPArg  = protoIMAP.Field("imap.request.parameter", "Request parameter", d.FtString)
	hfIMAPLine = protoIMAP.Field("imap.line", "Line", d.FtString)
)

var (
	ftpSpec = &lineSpec{proto: protoFTP, short: "FTP", ports: []uint64{21}, reqCmd: hfFTPReqCmd, reqArg: hfFTPReqArg,
		respCode: hfFTPRespCode, respArg: hfFTPRespArg, response: numericResp,
		startTLS: func(c, s string) bool { return strings.HasPrefix(c, "AUTH ") && strings.HasPrefix(s, "234") }}
	smtpSpec = &lineSpec{proto: protoSMTP, short: "SMTP", ports: []uint64{25, 587, 2525}, reqCmd: hfSMTPReqCmd, reqArg: hfSMTPReqPar,
		respCode: hfSMTPRespCd, respArg: hfSMTPRespPa, response: numericResp,
		startTLS: func(c, s string) bool { return strings.HasPrefix(c, "STARTTLS") && strings.HasPrefix(s, "220") }}
	popSpec = &lineSpec{proto: protoPOP, short: "POP", ports: []uint64{110}, reqCmd: hfPOPReqCmd, reqArg: hfPOPReqPar,
		respInd: hfPOPRespInd, respArg: hfPOPRespDes,
		response: func(l string) (string, string, bool) {
			if strings.HasPrefix(l, "+OK") {
				return "+OK", strings.TrimSpace(l[3:]), true
			}
			if strings.HasPrefix(l, "-ERR") {
				return "-ERR", strings.TrimSpace(l[4:]), true
			}
			return "", "", false
		},
		startTLS: func(c, s string) bool { return strings.HasPrefix(c, "STLS") && strings.HasPrefix(s, "+OK") }}
	imapSpec = &lineSpec{proto: protoIMAP, short: "IMAP", ports: []uint64{143}, reqCmd: hfIMAPCmd, reqArg: hfIMAPArg, line: hfIMAPLine,
		response: func(l string) (string, string, bool) {
			if strings.HasPrefix(l, "* ") || strings.HasPrefix(l, "+ ") {
				return l[:1], l[2:], true
			}
			if f := strings.SplitN(l, " ", 3); len(f) >= 2 && (f[1] == "OK" || f[1] == "NO" || f[1] == "BAD") {
				return f[1], strings.Join(f[2:], " "), true
			}
			return "", "", false
		},
		startTLS: func(c, s string) bool { return strings.HasPrefix(c, "STARTTLS") && strings.Contains(s, "OK") }}
)

func init() {
	for _, sp := range []*lineSpec{ftpSpec, smtpSpec, popSpec, imapSpec} {
		sp.isClient = clientByPort(sp.ports)
		h := d.RegisterHandle(strings.ToLower(sp.short), d.NewHandle(sp.proto, sp.dissect))
		for _, p := range sp.ports {
			TCPPortTable.Add(p, h)
		}
	}
	ftpDataHandle := d.RegisterHandle("ftp-data", d.NewHandle(protoFTPData, dissectFTPData))
	_ = ftpDataHandle
	// Implicit TLS variants carry the same protocols inside TLS.
	for p, name := range map[uint64]string{465: "smtp", 993: "imap", 995: "pop", 990: "ftp"} {
		TCPPortTable.Add(p, FindHandleLazyTLS(name))
	}
	tlsInnerPorts[993], tlsInnerPorts[995], tlsInnerPorts[465], tlsInnerPorts[990] = "imap", "pop", "smtp", "ftp"
}

// FindHandleLazyTLS returns the TLS handle for implicit-TLS ports.
func FindHandleLazyTLS(string) *d.Handle { return tlsHandle }

// ---- FTP data connections ----

type ftpExpect struct {
	frame uint32
	cmd   string
	mode  string // PASV or PORT
}

type ftpState struct {
	expect  map[string]ftpExpect // "ip:port" of the data connection
	lastKey string               // the data connection announced last
}

func ftpSession(pi *d.PacketInfo) *ftpState {
	s, _ := pi.Sess.ProtoState(protoFTP).(*ftpState)
	if s == nil && !pi.Visited {
		s = &ftpState{expect: map[string]ftpExpect{}}
		pi.Sess.SetProtoState(protoFTP, s)
	}
	return s
}

func ftpControlRequest(pi *d.PacketInfo, cmd, arg string) {
	if pi.Visited {
		return
	}
	st := ftpSession(pi)
	switch strings.ToUpper(cmd) {
	case "RETR", "STOR", "LIST", "NLST", "APPE", "MLSD":
		if e, ok := st.expect[st.lastKey]; ok && e.cmd == "" {
			e.cmd = strings.TrimSpace(strings.ToUpper(cmd) + " " + arg)
			st.expect[st.lastKey] = e
		}
	case "PORT":
		f := strings.Split(arg, ",")
		if len(f) == 6 {
			p1, _ := strconv.Atoi(f[4])
			p2, _ := strconv.Atoi(f[5])
			st.lastKey = fmt.Sprintf("%s.%s.%s.%s:%d", f[0], f[1], f[2], f[3], p1<<8|p2)
			st.expect[st.lastKey] = ftpExpect{frame: pi.Num, mode: "PORT"}
		}
	}
}

func ftpControlResponse(pi *d.PacketInfo, code, rest, lastCmd string) {
	if pi.Visited {
		return
	}
	st := ftpSession(pi)
	switch code {
	case "227": // Entering Passive Mode (h1,h2,h3,h4,p1,p2)
		if i, j := strings.IndexByte(rest, '('), strings.IndexByte(rest, ')'); i >= 0 && j > i {
			f := strings.Split(rest[i+1:j], ",")
			if len(f) == 6 {
				p1, _ := strconv.Atoi(f[4])
				p2, _ := strconv.Atoi(f[5])
				st.lastKey = fmt.Sprintf("%s.%s.%s.%s:%d", f[0], f[1], f[2], f[3], p1<<8|p2)
				st.expect[st.lastKey] = ftpExpect{frame: pi.Num, mode: "PASV"}
			}
		}
	case "229": // Entering Extended Passive Mode (|||port|)
		if i := strings.Index(rest, "(|||"); i >= 0 {
			if j := strings.Index(rest[i:], "|)"); j > 0 {
				port := rest[i+4 : i+j]
				st.lastKey = fmt.Sprintf("%s:%s", pi.Src, port)
				st.expect[st.lastKey] = ftpExpect{frame: pi.Num, mode: "PASV"}
			}
		}
	}
}

// ftpPassiveFields adds the parsed address of a 227/229 reply.
func ftpPassiveFields(ln *d.Node, code, rest string) {
	switch code {
	case "227":
		if i, j := strings.IndexByte(rest, '('), strings.IndexByte(rest, ')'); i >= 0 && j > i {
			f := strings.Split(rest[i+1:j], ",")
			if len(f) == 6 {
				p1, _ := strconv.Atoi(f[4])
				p2, _ := strconv.Atoi(f[5])
				var ip uint64
				for k := 0; k < 4; k++ {
					v, _ := strconv.Atoi(f[k])
					ip = ip<<8 | uint64(v&0xff)
				}
				ln.AddGenerated(hfFTPPassIP, d.UintValue(d.FtIPv4, ip))
				ln.AddGenerated(hfFTPPassive, d.UintValue(d.FtUint16, uint64(p1<<8|p2)))
			}
		}
	case "229":
		if i := strings.Index(rest, "(|||"); i >= 0 {
			if j := strings.Index(rest[i:], "|)"); j > 0 {
				p, _ := strconv.Atoi(rest[i+4 : i+j])
				ln.AddGenerated(hfFTPPassive, d.UintValue(d.FtUint16, uint64(p)))
			}
		}
	}
}

// ftpDataFor returns the setup of a data connection a packet belongs to.
func ftpDataFor(pi *d.PacketInfo) (ftpExpect, bool) {
	st, _ := pi.Sess.ProtoState(protoFTP).(*ftpState)
	if st == nil || len(st.expect) == 0 {
		return ftpExpect{}, false
	}
	for _, k := range []string{fmt.Sprintf("%s:%d", pi.Dst, pi.DstPort), fmt.Sprintf("%s:%d", pi.Src, pi.SrcPort)} {
		if e, ok := st.expect[k]; ok {
			return e, true
		}
	}
	return ftpExpect{}, false
}

func dissectFTPData(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	ft := tree.AddProtocol(protoFTPData, tvb, 0, -1)
	pi.SetProtocol("FTP-DATA")
	if e, ok := ftpDataFor(pi); ok {
		ft.AddGenerated(hfFTPDSetup, d.UintValue(d.FtFrameNum, uint64(e.frame))).SetLink(e.frame)
	}
	if e, ok := ftpDataFor(pi); ok && e.cmd != "" {
		ft.AddGenerated(hfFTPDCmd, d.StringValue(e.cmd))
	}
	ft.AddUintValue(hfFTPDLen, tvb, 0, 0, uint64(tvb.Len()))
	if tvb.Len() > 0 {
		ft.AddBytes(hfFTPDData, tvb, 0, tvb.Len())
	}
	info := fmt.Sprintf("FTP Data: %d bytes", tvb.Len())
	if e, ok := ftpDataFor(pi); ok {
		info += " (" + e.mode + ")"
		if e.cmd != "" {
			info += " (" + e.cmd + ")"
		}
	}
	pi.SetInfo(info)
	return tvb.Len()
}

// ---------------- Telnet ----------------

var (
	telnetCmds = map[byte]string{240: "SE", 241: "NOP", 242: "Data Mark", 243: "Break", 244: "Interrupt Process", 245: "Abort output",
		246: "Are You There", 247: "Erase character", 248: "Erase Line", 249: "Go ahead", 250: "SB", 251: "Will", 252: "Won't", 253: "Do", 254: "Don't"}
	telnetOpts = map[byte]string{0: "Binary Transmission", 1: "Echo", 3: "Suppress Go Ahead", 5: "Status", 6: "Timing Mark", 24: "Terminal Type",
		31: "Negotiate About Window Size", 32: "Terminal Speed", 33: "Remote Flow Control", 34: "Linemode", 35: "X Display Location",
		36: "Environment Option", 39: "New Environment Option"}
	protoTelnet  = d.RegisterProto("Telnet", "TELNET", "telnet")
	hfTelnetData = protoTelnet.Field("telnet.data", "Data", d.FtString)
	hfTelnetCmd  = protoTelnet.Field("telnet.cmd", "Command", d.FtUint8, d.WithVS(vsFromMapByte(telnetCmds)))
	hfTelnetOpt  = protoTelnet.Field("telnet.option", "Option", d.FtUint8, d.WithVS(vsFromMapByte(telnetOpts)))
	telnetHandle = d.RegisterHandle("telnet", d.NewHandle(protoTelnet, dissectTelnet))
)

func vsFromMapByte(m map[byte]string) map[uint64]string {
	o := map[uint64]string{}
	for k, v := range m {
		o[uint64(k)] = v
	}
	return o
}

func init() { TCPPortTable.Add(23, telnetHandle) }

func dissectTelnet(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	tt := tree.AddProtocol(protoTelnet, tvb, 0, -1)
	pi.SetProtocol("TELNET")
	var infos []string
	raw := tvb.Raw()
	for off := 0; off < len(raw); {
		if raw[off] == 255 && off+1 < len(raw) {
			c := raw[off+1]
			n := 2
			s := telnetCmds[c]
			cn := tt.AddText(tvb, off, 2, "Command: %s", s)
			cn.AddUint(hfTelnetCmd, tvb, off+1, 1)
			if c >= 251 && c <= 254 && off+2 < len(raw) {
				n = 3
				cn.SetLen(3)
				cn.AddUint(hfTelnetOpt, tvb, off+2, 1)
				cn.SetText("Command: %s %s", s, orDefault(telnetOpts[raw[off+2]], fmt.Sprint(raw[off+2])))
				infos = append(infos, fmt.Sprintf("%s %s", s, orDefault(telnetOpts[raw[off+2]], fmt.Sprint(raw[off+2]))))
			} else if c == 250 {
				e := strings.Index(string(raw[off:]), "\xff\xf0")
				if e < 0 {
					e = len(raw) - off - 2
				}
				n = e + 2
				cn.SetLen(n)
				infos = append(infos, "Suboption")
			} else if c == 255 {
				// escaped 0xff data byte
			}
			off += n
			continue
		}
		e := off + 1 // always make progress (a lone trailing IAC is data)
		for e < len(raw) && raw[e] != 255 {
			e++
		}
		tt.AddString(hfTelnetData, tvb, off, e-off)
		infos = append(infos, fmt.Sprintf("%d bytes data", e-off))
		off = e
	}
	pi.SetInfo(strings.Join(dedupeStrings(infos), ", "))
	return tvb.Len()
}

func dedupeStrings(in []string) []string {
	out := in[:0:0]
	for _, s := range in {
		if len(out) == 0 || out[len(out)-1] != s {
			out = append(out, s)
		}
	}
	return out
}

// ---------------- SOCKS ----------------

var (
	protoSOCKS    = d.RegisterProto("Socks Protocol", "SOCKS", "socks")
	hfSOCKSVer    = protoSOCKS.Field("socks.version", "Version", d.FtUint8)
	hfSOCKSCmd    = protoSOCKS.Field("socks.command", "Command", d.FtUint8, d.WithVS(map[uint64]string{1: "Connect", 2: "Bind", 3: "UDP Associate"}))
	hfSOCKSPort   = protoSOCKS.Field("socks.port", "Remote Port", d.FtUint16)
	hfSOCKSIP     = protoSOCKS.Field("socks.dst", "Remote Address", d.FtIPv4)
	hfSOCKSHost   = protoSOCKS.Field("socks.remote_name", "Remote name", d.FtString)
	hfSOCKSUser   = protoSOCKS.Field("socks.username", "User name", d.FtString)
	hfSOCKSPass   = protoSOCKS.Field("socks.password", "Password", d.FtString)
	hfSOCKSMeth   = protoSOCKS.Field("socks.auth_method", "Method", d.FtUint8, d.WithVS(map[uint64]string{0: "No authentication", 1: "GSSAPI", 2: "Username/Password", 255: "No acceptable methods"}))
	hfSOCKSStatus = protoSOCKS.Field("socks.results", "Results", d.FtUint8)
	socksHandle   = d.RegisterHandle("socks", d.NewHandle(protoSOCKS, dissectSOCKS))
)

func init() { TCPPortTable.Add(1080, socksHandle) }

func dissectSOCKS(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	if tvb.Len() < 2 {
		return 0
	}
	client := pi.DstPort == 1080
	v := tvb.U8(0)
	st := tree.AddProtocol(protoSOCKS, tvb, 0, -1)
	pi.SetProtocol("Socks")
	st.AddUint(hfSOCKSVer, tvb, 0, 1)
	switch {
	case v == 4 && client && tvb.Len() >= 8:
		_, cmd := st.AddUint(hfSOCKSCmd, tvb, 1, 1)
		_, port := st.AddUint(hfSOCKSPort, tvb, 2, 2)
		st.AddIPv4(hfSOCKSIP, tvb, 4)
		pi.SetInfo(fmt.Sprintf("Version: 4, Command: %s, Port: %d", map[uint64]string{1: "Connect", 2: "Bind"}[cmd], port))
	case v == 5 && client && tvb.Len() >= 7 && tvb.U8(1) <= 3 && tvb.U8(2) == 0:
		_, cmd := st.AddUint(hfSOCKSCmd, tvb, 1, 1)
		atyp := tvb.U8(3)
		var host string
		p := 4
		switch atyp {
		case 1:
			st.AddIPv4(hfSOCKSIP, tvb, p)
			host = fmt.Sprintf("%d.%d.%d.%d", tvb.U8(p), tvb.U8(p+1), tvb.U8(p+2), tvb.U8(p+3))
			p += 4
		case 3:
			l := int(tvb.U8(p))
			_, host = st.AddString(hfSOCKSHost, tvb, p+1, l)
			p += 1 + l
		case 4:
			p += 16
		}
		_, port := st.AddUint(hfSOCKSPort, tvb, p, 2)
		pi.SetInfo("Version: 5 Command Request - " + map[uint64]string{1: "Connect", 2: "Bind", 3: "UDP Associate"}[cmd])
		_, _ = host, port
	case v == 5 && client:
		n := int(tvb.U8(1))
		for i := 0; i < n && 2+i < tvb.Len(); i++ {
			st.AddUint(hfSOCKSMeth, tvb, 2+i, 1)
		}
		pi.SetInfo("Version: 5 Connect to server request")
	case v == 5:
		if tvb.Len() == 2 {
			st.AddUint(hfSOCKSMeth, tvb, 1, 1)
			pi.SetInfo("Version: 5 Connect to server response")
		} else {
			_, r := st.AddUint(hfSOCKSStatus, tvb, 1, 1)
			pi.SetInfo(fmt.Sprintf("Version: 5, Reply: %d", r))
		}
	case v == 1 && client:
		// RFC 1929 username/password
		ul := int(tvb.U8(1))
		_, u := st.AddString(hfSOCKSUser, tvb, 2, ul)
		pl := int(tvb.U8(2 + ul))
		st.AddString(hfSOCKSPass, tvb, 3+ul, pl)
		pi.SetInfo("Username/Password authentication, user: " + u)
	case v == 0 && !client:
		st.AddUint(hfSOCKSStatus, tvb, 1, 1)
		pi.SetInfo("Version: 4 (reply)")
	default:
		return 0
	}
	return tvb.Len()
}

// decodeBase64Auth decodes a SASL PLAIN payload into user and password.
func decodeBase64Auth(s string) (user, pass string, ok bool) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return "", "", false
	}
	parts := strings.Split(string(b), "\x00")
	if len(parts) == 3 {
		return parts[1], parts[2], true
	}
	return "", "", false
}
