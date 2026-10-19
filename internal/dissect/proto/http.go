package proto

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	d "github.com/poseydon/lazysniffer/internal/dissect"
)

var (
	httpStatus = map[uint64]string{100: "Continue", 101: "Switching Protocols", 102: "Processing", 103: "Early Hints",
		200: "OK", 201: "Created", 202: "Accepted", 203: "Non-authoritative Information", 204: "No Content",
		205: "Reset Content", 206: "Partial Content", 207: "Multi-Status", 300: "Multiple Choices", 301: "Moved Permanently",
		302: "Found", 303: "See Other", 304: "Not Modified", 305: "Use Proxy", 307: "Temporary Redirect",
		308: "Permanent Redirect", 400: "Bad Request", 401: "Unauthorized", 402: "Payment Required", 403: "Forbidden",
		404: "Not Found", 405: "Method Not Allowed", 406: "Not Acceptable", 407: "Proxy Authentication Required",
		408: "Request Time-out", 409: "Conflict", 410: "Gone", 411: "Length Required", 412: "Precondition Failed",
		413: "Request Entity Too Large", 414: "Request-URI Too Long", 415: "Unsupported Media Type",
		416: "Requested Range Not Satisfiable", 417: "Expectation Failed", 418: "I'm a teapot", 421: "Misdirected Request",
		422: "Unprocessable Entity", 425: "Too Early", 426: "Upgrade Required", 428: "Precondition Required",
		429: "Too Many Requests", 431: "Request Header Fields Too Large", 451: "Unavailable For Legal Reasons",
		500: "Internal Server Error", 501: "Not Implemented", 502: "Bad Gateway", 503: "Service Unavailable",
		504: "Gateway Time-out", 505: "HTTP Version not supported", 511: "Network Authentication Required"}
	httpMethods = []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
		"PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "REPORT", "SEARCH", "PRI", "M-SEARCH",
		"NOTIFY", "SUBSCRIBE", "UNSUBSCRIBE", "PURGE", "BREW"}

	protoHTTP = d.RegisterProto("Hypertext Transfer Protocol", "HTTP", "http")

	hfHTTPRequest       = protoHTTP.Field("http.request", "Request", d.FtBool)
	hfHTTPResponse      = protoHTTP.Field("http.response", "Response", d.FtBool)
	hfHTTPMethod        = protoHTTP.Field("http.request.method", "Request Method", d.FtString)
	hfHTTPURI           = protoHTTP.Field("http.request.uri", "Request URI", d.FtString)
	hfHTTPURIPath       = protoHTTP.Field("http.request.uri.path", "Request URI Path", d.FtString)
	hfHTTPURIQuery      = protoHTTP.Field("http.request.uri.query", "Request URI Query", d.FtString)
	hfHTTPURIParam      = protoHTTP.Field("http.request.uri.query.parameter", "Request URI Query Parameter", d.FtString)
	hfHTTPReqVersion    = protoHTTP.Field("http.request.version", "Request Version", d.FtString)
	hfHTTPReqLine       = protoHTTP.Field("http.request.line", "Request line", d.FtString)
	hfHTTPRespVersion   = protoHTTP.Field("http.response.version", "Response Version", d.FtString)
	hfHTTPCode          = protoHTTP.Field("http.response.code", "Status Code", d.FtUint16)
	hfHTTPCodeDesc      = protoHTTP.Field("http.response.code.desc", "Status Code Description", d.FtString)
	hfHTTPPhrase        = protoHTTP.Field("http.response.phrase", "Response Phrase", d.FtString)
	hfHTTPRespLine      = protoHTTP.Field("http.response.line", "Response line", d.FtString)
	hfHTTPFullURI       = protoHTTP.Field("http.request.full_uri", "Full request URI", d.FtString)
	hfHTTPReqNum        = protoHTTP.Field("http.request_number", "HTTP request", d.FtUint32)
	hfHTTPRespNum       = protoHTTP.Field("http.response_number", "HTTP response", d.FtUint32)
	hfHTTPRespIn        = protoHTTP.Field("http.response_in", "Response in frame", d.FtFrameNum)
	hfHTTPReqIn         = protoHTTP.Field("http.request_in", "Request in frame", d.FtFrameNum)
	hfHTTPTime          = protoHTTP.Field("http.time", "Time since request", d.FtRelTime)
	hfHTTPFileData      = protoHTTP.Field("http.file_data", "File Data", d.FtBytes)
	hfHTTPCLen          = protoHTTP.Field("http.content_length", "Content length", d.FtUint64)
	hfHTTPChunkSize     = protoHTTP.Field("http.chunk_size", "Chunk size", d.FtUint32, d.WithUnit("octets"))
	hfHTTPChunkData     = protoHTTP.Field("http.chunk_data", "Chunk data", d.FtBytes)
	hfHTTPChunkBoundary = protoHTTP.Field("http.chunk_boundary", "Chunk boundary", d.FtBytes)
	hfHTTPAuthBasic     = protoHTTP.Field("http.authbasic", "Credentials", d.FtString)
	hfHTTPAuthCit       = protoHTTP.Field("http.authcitrix", "Bearer token", d.FtString)
	hfHTTPCookiePair    = protoHTTP.Field("http.cookie_pair", "Cookie pair", d.FtString)
	hfHTTPUnknownHdr    = protoHTTP.Field("http.unknown_header", "Unknown header", d.FtString)
	hfHTTPContinue      = protoHTTP.Field("http.continuation", "Continuation", d.FtBytes)
	hfHTTPDecoded       = protoHTTP.Field("http.decompressed", "Content-encoded entity body", d.FtString)
	eiHTTPChat          = protoHTTP.Expert("http.chat", d.GroupSequence, d.SevChat, "Request/response line")
	eiHTTPDecompFail    = protoHTTP.Expert("http.decompression_failed", d.GroupUndecoded, d.SevWarn, "Decompression failed")
	eiHTTPLeadingCRLF   = protoHTTP.Expert("http.leading_crlf", d.GroupMalformed, d.SevError, "Leading CRLF previous message in the stream may have extra CRLF")

	// Header fields by lower-case name (Wireshark's http.* header fields).
	httpHeaderFields = map[string]*d.FieldDef{}

	httpHandle = d.RegisterHandle("http", d.NewHandle(protoHTTP, dissectHTTP))
)

func init() {
	for name, abbrev := range map[string]string{
		"host": "http.host", "user-agent": "http.user_agent", "accept": "http.accept", "accept-encoding": "http.accept_encoding",
		"accept-language": "http.accept_language", "referer": "http.referer", "cookie": "http.cookie", "set-cookie": "http.set_cookie",
		"content-type": "http.content_type", "content-length": "http.content_length_header", "content-encoding": "http.content_encoding",
		"transfer-encoding": "http.transfer_encoding", "connection": "http.connection", "location": "http.location",
		"server": "http.server", "authorization": "http.authorization", "proxy-authorization": "http.proxy_authorization",
		"proxy-authenticate": "http.proxy_authenticate", "www-authenticate": "http.www_authenticate",
		"cache-control": "http.cache_control", "date": "http.date", "last-modified": "http.last_modified",
		"x-forwarded-for": "http.x_forwarded_for", "upgrade": "http.upgrade", "sec-websocket-key": "http.sec_websocket_key",
		"sec-websocket-accept": "http.sec_websocket_accept", "sec-websocket-version": "http.sec_websocket_version",
		"sec-websocket-protocol": "http.sec_websocket_protocol", "sec-websocket-extensions": "http.sec_websocket_extensions",
		"origin": "http.origin", "etag": "http.etag", "if-modified-since": "http.if_modified_since", "if-none-match": "http.if_none_match",
		"keep-alive": "http.keep_alive", "range": "http.range", "content-range": "http.content_range", "vary": "http.vary",
		"via": "http.via", "x-powered-by": "http.x_powered_by", "expires": "http.expires", "pragma": "http.pragma",
		"accept-ranges": "http.accept_ranges", "strict-transport-security": "http.strict_transport_security",
		"access-control-allow-origin": "http.access_control_allow_origin", "alt-svc": "http.alt_svc",
		"content-security-policy": "http.content_security_policy", "x-real-ip": "http.x_real_ip", "forwarded": "http.forwarded",
		"content-disposition": "http.content_disposition", "te": "http.te", "expect": "http.expect", "dnt": "http.dnt",
		"user-agent-client-hints": "http.ua_ch",
	} {
		t := d.FtString
		httpHeaderFields[name] = protoHTTP.Field(abbrev, headerTitle(name), t)
	}
	for _, p := range []uint64{80, 8080, 8000, 8008, 8088, 8888, 3128, 3132, 591, 81, 5985} {
		TCPPortTable.Add(p, httpHandle)
	}
	TCPHeur.Add("http_tcp", protoHTTP, func(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) bool {
		if !looksLikeHTTP(tvb.Raw()) {
			return false
		}
		dissectHTTP(tvb, pi, tree)
		return true
	})
}

func headerTitle(name string) string {
	parts := strings.Split(name, "-")
	for i, p := range parts {
		if p != "" {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, "-")
}

func looksLikeHTTP(b []byte) bool {
	if bytes.HasPrefix(b, []byte("HTTP/1.")) {
		return true
	}
	for _, m := range httpMethods {
		if len(b) > len(m) && bytes.HasPrefix(b, []byte(m)) && b[len(m)] == ' ' {
			return true
		}
	}
	return false
}

type httpReq struct {
	path   string
	frame  uint32
	ts     int64
	uri    string
	method string
	num    uint32
}

type httpConvState struct {
	queue    []*httpReq
	reqCount uint32
	resCount uint32
}

type httpMatch struct {
	req      *httpReq
	respIn   uint32
	respNum  uint32
	isResp   bool
	infoOnly bool
}

type httpFrameCtx struct{ msg int }

// DissectHTTP lets other dissectors (TLS decryption, proxies) hand over
// HTTP/1.x data.
func DissectHTTP(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int { return dissectHTTP(tvb, pi, tree) }

func dissectHTTP(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	if tvb.Len() >= 14 && string(tvb.Bytes(0, 14)) == "PRI * HTTP/2.0" {
		// Prior-knowledge HTTP/2 on an HTTP port.
		SetTCPAppHandle(pi, h2Handle)
		return dissectHTTP2(tvb, pi, tree)
	}
	off := 0
	var infos []string
	for off < tvb.Len() {
		n, info := dissectHTTPMessage(tvb, off, pi, tree)
		if info != "" {
			infos = append(infos, info)
		}
		if n <= 0 {
			break
		}
		off += n
	}
	if len(infos) > 0 {
		pi.SetProtocol("HTTP")
		pi.SetInfo(strings.Join(infos, " , "))
	}
	return tvb.Len()
}

func findHeaderEnd(b []byte) int {
	if i := bytes.Index(b, []byte("\r\n\r\n")); i >= 0 {
		return i + 4
	}
	if i := bytes.Index(b, []byte("\n\n")); i >= 0 {
		return i + 2
	}
	return -1
}

// dissectHTTPMessage dissects one message at off; it returns bytes consumed
// (0 when more data was requested) and an Info summary.
func dissectHTTPMessage(tvb *d.Tvb, off int, pi *d.PacketInfo, tree *d.Node) (int, string) {
	raw := tvb.Raw()[off:]
	if !looksLikeHTTP(raw) {
		// Body data of a message we did not see the start of.
		if bytes.HasPrefix(raw, []byte("\r\n")) {
			ht := tree.AddProtocol(protoHTTP, tvb, off, 2)
			ht.AddExpert(eiHTTPLeadingCRLF, "")
			return 2, ""
		}
		ht := tree.AddProtocol(protoHTTP, tvb, off, -1)
		ht.AddBytes(hfHTTPContinue, tvb, off, -1)
		pi.SetProtocol("HTTP")
		return tvb.Len() - off, "Continuation"
	}
	hend := findHeaderEnd(raw)
	if hend < 0 {
		if raw := tvb.Remaining(off); raw < 64<<10 {
			pi.Desegment(off, d.DesegmentOneMore)
			return 0, ""
		}
		hend = len(raw)
	}
	lines := strings.Split(strings.TrimRight(string(raw[:hend]), "\r\n"), "\n")
	first := strings.TrimRight(lines[0], "\r")
	headers := map[string]string{}
	type hdr struct {
		name, value string
		start, len  int
	}
	var hdrs []hdr
	pos := off + len(lines[0]) + 1
	for _, l := range lines[1:] {
		ll := len(l) + 1
		line := strings.TrimRight(l, "\r")
		if name, value, ok := strings.Cut(line, ":"); ok {
			n := strings.ToLower(strings.TrimSpace(name))
			v := strings.TrimSpace(value)
			if prev, ok := headers[n]; ok && n != "set-cookie" {
				headers[n] = prev + ", " + v
			} else {
				headers[n] = v
			}
			hdrs = append(hdrs, hdr{strings.TrimSpace(name), v, pos, ll})
		}
		pos += ll
	}
	isResp := strings.HasPrefix(first, "HTTP/")
	var method, uri, version, phrase string
	var code int
	if isResp {
		f := strings.SplitN(first, " ", 3)
		version = f[0]
		if len(f) > 1 {
			code, _ = strconv.Atoi(f[1])
		}
		if len(f) > 2 {
			phrase = f[2]
		}
	} else {
		f := strings.SplitN(first, " ", 3)
		method = f[0]
		if len(f) > 1 {
			uri = f[1]
		}
		if len(f) > 2 {
			version = f[2]
		}
	}

	// Body length.
	bodyLen := 0
	chunked := strings.Contains(strings.ToLower(headers["transfer-encoding"]), "chunked")
	cl, hasCL := int64(-1), false
	if v, ok := headers["content-length"]; ok {
		if n, err := strconv.ParseInt(strings.TrimSpace(strings.Split(v, ",")[0]), 10, 64); err == nil && n >= 0 {
			cl, hasCL = n, true
		}
	}
	avail := tvb.Remaining(off + hend)
	noBody := isResp && (code/100 == 1 || code == 204 || code == 304 || pi.Sess != nil && headMethodPending(pi))
	switch {
	case noBody || (!isResp && !hasCL && !chunked):
		bodyLen = 0
	case chunked:
		n, complete := chunkedLength(tvb.Raw()[off+hend:])
		if !complete {
			pi.Desegment(off, d.DesegmentOneMore)
			return 0, ""
		}
		bodyLen = n
	case hasCL:
		if int64(avail) < cl {
			pi.Desegment(off, int(cl)-avail)
			return 0, ""
		}
		bodyLen = int(cl)
	default:
		bodyLen = avail // until the connection closes
	}
	total := hend + bodyLen

	ht := tree.AddProtocol(protoHTTP, tvb, off, total)
	var info string
	if isResp {
		ht.AddHidden(hfHTTPResponse, tvb, off, len(first), d.BoolValue(true))
		rl := ht.AddValue(hfHTTPRespLine, tvb, off, len(lines[0])+1, d.StringValue(first))
		rl.SetText("%s\\r\\n", first)
		rl.AddExpert(eiHTTPChat, "%s\\r\\n", first)
		rl.AddValue(hfHTTPRespVersion, tvb, off, len(version), d.StringValue(version))
		rl.AddValue(hfHTTPCode, tvb, off+len(version)+1, 3, d.Value{U: uint64(code)})
		if desc, ok := httpStatus[uint64(code)]; ok {
			rl.AddGenerated(hfHTTPCodeDesc, d.StringValue(desc))
		}
		rl.AddValue(hfHTTPPhrase, tvb, off+len(version)+5, len(phrase), d.StringValue(phrase))
		info = first
		if ct := headers["content-type"]; ct != "" {
			info += "  (" + strings.TrimSpace(strings.Split(ct, ";")[0]) + ")"
		}
	} else {
		ht.AddHidden(hfHTTPRequest, tvb, off, len(first), d.BoolValue(true))
		rl := ht.AddValue(hfHTTPReqLine, tvb, off, len(lines[0])+1, d.StringValue(first))
		rl.SetText("%s\\r\\n", first)
		rl.AddExpert(eiHTTPChat, "%s\\r\\n", first)
		rl.AddValue(hfHTTPMethod, tvb, off, len(method), d.StringValue(method))
		un := rl.AddValue(hfHTTPURI, tvb, off+len(method)+1, len(uri), d.StringValue(uri))
		if u, err := url.ParseRequestURI(uri); err == nil {
			un.AddValue(hfHTTPURIPath, nil, 0, 0, d.StringValue(u.Path))
			if u.RawQuery != "" {
				un.AddValue(hfHTTPURIQuery, nil, 0, 0, d.StringValue(u.RawQuery))
				for _, kv := range strings.Split(u.RawQuery, "&") {
					un.AddValue(hfHTTPURIParam, nil, 0, 0, d.StringValue(kv))
				}
			}
		}
		rl.AddValue(hfHTTPReqVersion, tvb, off+len(method)+len(uri)+2, len(version), d.StringValue(version))
		info = first
	}
	for _, h := range hdrs {
		n := strings.ToLower(h.name)
		line := ht.AddText(tvb, h.start, h.len, "%s: %s\\r\\n", h.name, h.value)
		if f := httpHeaderFields[n]; f != nil {
			line = ht.AddValue(f, tvb, h.start, h.len, d.StringValue(h.value))
			line.SetText("%s: %s\\r\\n", h.name, h.value)
		} else {
			line.AddValue(hfHTTPUnknownHdr, tvb, h.start, h.len, d.StringValue(h.name+": "+h.value)).SetHidden()
		}
		switch n {
		case "content-length":
			if hasCL {
				line.AddGenerated(hfHTTPCLen, d.Value{U: uint64(cl)})
			}
		case "authorization", "proxy-authorization":
			scheme, cred, _ := strings.Cut(h.value, " ")
			switch strings.ToLower(scheme) {
			case "basic":
				if dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cred)); err == nil {
					line.AddGenerated(hfHTTPAuthBasic, d.StringValue(string(dec)))
				}
			case "bearer":
				line.AddGenerated(hfHTTPAuthCit, d.StringValue(strings.TrimSpace(cred)))
			}
		case "cookie":
			for _, c := range strings.Split(h.value, ";") {
				line.AddValue(hfHTTPCookiePair, nil, 0, 0, d.StringValue(strings.TrimSpace(c)))
			}
		}
	}
	ht.AddText(tvb, off+hend-2, 2, "\\r\\n")
	if !isResp {
		host := headers["host"]
		if host != "" && strings.HasPrefix(uri, "/") {
			scheme := "http"
			if TLSSession(pi) != nil {
				scheme = "https"
			}
			ht.AddGenerated(hfHTTPFullURI, d.StringValue(scheme+"://"+host+uri))
		}
	}
	httpMatchMessage(pi, ht, isResp, method, uri, headers, code)
	if bodyLen > 0 {
		dissectHTTPBody(tvb, off+hend, bodyLen, chunked, headers, pi, ht, tree)
	}
	if isResp && code == 101 || (isResp && method == "" && code/100 == 2 && connectPending(pi)) {
		httpSwitchProtocol(pi, headers, code)
	}
	return total, info
}

func chunkedLength(b []byte) (int, bool) {
	pos := 0
	for {
		i := bytes.Index(b[pos:], []byte("\r\n"))
		if i < 0 {
			return 0, false
		}
		sizeStr := strings.TrimSpace(strings.SplitN(string(b[pos:pos+i]), ";", 2)[0])
		n, err := strconv.ParseInt(sizeStr, 16, 64)
		if err != nil || n < 0 {
			return len(b), true // malformed: take the rest
		}
		pos += i + 2
		if n == 0 {
			// Trailer section ends with an empty line.
			j := bytes.Index(b[pos:], []byte("\r\n"))
			for j > 0 {
				pos += j + 2
				j = bytes.Index(b[pos:], []byte("\r\n"))
			}
			if j < 0 {
				return 0, false
			}
			return pos + 2, true
		}
		if pos+int(n)+2 > len(b) {
			return 0, false
		}
		pos += int(n) + 2
	}
}

func dechunk(b []byte, tvb *d.Tvb, base int, tree *d.Node) []byte {
	var out []byte
	pos := 0
	for pos < len(b) {
		i := bytes.Index(b[pos:], []byte("\r\n"))
		if i < 0 {
			break
		}
		n, err := strconv.ParseInt(strings.TrimSpace(strings.SplitN(string(b[pos:pos+i]), ";", 2)[0]), 16, 64)
		if err != nil {
			break
		}
		cn := tree.AddText(tvb, base+pos, min(i+2+int(n)+2, len(b)-pos), "Data chunk (%d octets)", n)
		cn.AddUintValue(hfHTTPChunkSize, tvb, base+pos, i, uint64(n))
		pos += i + 2
		if n == 0 {
			cn.SetText("End of chunked encoding")
			break
		}
		end := min(pos+int(n), len(b))
		cn.AddBytes(hfHTTPChunkData, tvb, base+pos, end-pos)
		out = append(out, b[pos:end]...)
		pos = end + 2
	}
	return out
}

func dissectHTTPBody(tvb *d.Tvb, off, l int, chunked bool, headers map[string]string, pi *d.PacketInfo, ht, tree *d.Node) {
	body := tvb.Raw()[off : off+l]
	data := body
	src := tvb.Sub(off, l)
	if chunked {
		ct := ht.AddText(tvb, off, l, "HTTP chunked response")
		data = dechunk(body, tvb, off, ct)
		src = pi.AddSource("De-chunked entity body", data)
	}
	if enc := headers["content-encoding"]; enc != "" && !strings.EqualFold(enc, "identity") {
		ce := ht.AddText(src, 0, src.Len(), "Content-encoded entity body (%s): %d bytes", enc, len(data))
		dec, err := decompress(enc, data)
		if err != nil {
			ce.AddExpert(eiHTTPDecompFail, "Decompression failed: %v", err)
		} else {
			ce.AppendText(" -> %d bytes", len(dec))
			data = dec
			src = pi.AddSource("Uncompressed entity body", dec)
		}
	}
	fd, _ := ht.AddBytes(hfHTTPFileData, src, 0, src.Len())
	fd.SetText("File Data: %d bytes", src.Len())
	ctype := strings.ToLower(strings.TrimSpace(strings.Split(headers["content-type"], ";")[0]))
	DissectMedia(ctype, src, pi, tree)
}

// headMethodPending reports whether the response being parsed answers a
// HEAD request (no body even with Content-Length).
func headMethodPending(pi *d.PacketInfo) bool {
	if pi.Visited {
		c, _ := pi.Scratch(protoHTTP).(*httpFrameCtx)
		k := uint32(1)
		if c != nil {
			k = uint32(c.msg + 1)
		}
		m, _ := pi.Sess.FrameData(protoHTTP, pi.Num, k).(*httpMatch)
		return m != nil && m.req != nil && m.req.method == "HEAD"
	}
	st := httpState(pi)
	return st != nil && len(st.queue) > 0 && st.queue[0].method == "HEAD"
}

func connectPending(pi *d.PacketInfo) bool {
	if m, ok := pi.Sess.FrameData(protoHTTP, pi.Num, httpMsgKey(pi, false)).(*httpMatch); ok && m.req != nil {
		return m.req.method == "CONNECT"
	}
	return false
}

func httpState(pi *d.PacketInfo) *httpConvState {
	if pi.Conv == nil {
		return nil
	}
	st, _ := pi.Conv.Data(protoHTTP).(*httpConvState)
	if st == nil && !pi.Visited {
		st = &httpConvState{}
		pi.Conv.SetData(protoHTTP, st)
	}
	return st
}

// httpMsgKey numbers messages within a frame (several may share a segment).
func httpMsgKey(pi *d.PacketInfo, next bool) uint32 {
	c, _ := pi.Scratch(protoHTTP).(*httpFrameCtx)
	if c == nil {
		c = &httpFrameCtx{}
		pi.SetScratch(protoHTTP, c)
	}
	if next {
		c.msg++
	}
	return uint32(c.msg)
}

func httpMatchMessage(pi *d.PacketInfo, ht *d.Node, isResp bool, method, uri string, headers map[string]string, code int) {
	key := httpMsgKey(pi, true)
	sess := pi.Sess
	if !pi.Visited {
		if st := httpState(pi); st != nil {
			if !isResp {
				st.reqCount++
				r := &httpReq{frame: pi.Num, ts: pi.TS, uri: uri, path: uri, method: method, num: st.reqCount}
				if host := headers["host"]; host != "" && strings.HasPrefix(uri, "/") {
					scheme := "http"
					if TLSSession(pi) != nil {
						scheme = "https"
					}
					r.uri = scheme + "://" + host + uri
				}
				st.queue = append(st.queue, r)
				sess.SetFrameData(protoHTTP, pi.Num, key, &httpMatch{req: r})
			} else if code/100 == 1 && code != 101 {
				sess.SetFrameData(protoHTTP, pi.Num, key, &httpMatch{isResp: true, infoOnly: true})
			} else if len(st.queue) > 0 {
				r := st.queue[0]
				st.queue = st.queue[1:]
				st.resCount++
				if m, ok := sess.FrameData(protoHTTP, r.frame, findReqKey(sess, r)).(*httpMatch); ok {
					m.respIn = pi.Num
				}
				sess.SetFrameData(protoHTTP, pi.Num, key, &httpMatch{req: r, isResp: true, respNum: st.resCount})
			}
		}
	}
	m, _ := sess.FrameData(protoHTTP, pi.Num, key).(*httpMatch)
	if m == nil || m.req == nil {
		return
	}
	if !isResp {
		ht.AddGenerated(hfHTTPReqNum, d.Value{U: uint64(m.req.num)}).SetText("[HTTP request %d]", m.req.num)
		if m.respIn != 0 {
			ht.AddGenerated(hfHTTPRespIn, d.Value{U: uint64(m.respIn)}).SetLink(m.respIn)
		}
		return
	}
	ht.AddGenerated(hfHTTPRespNum, d.Value{U: uint64(m.respNum)}).SetText("[HTTP response %d]", m.respNum)
	ht.AddGenerated(hfHTTPTime, d.RelTimeValue(pi.TS-m.req.ts)).SetText("[Time since request: %s seconds]", d.FormatRelTime(pi.TS-m.req.ts))
	ht.AddGenerated(hfHTTPReqIn, d.Value{U: uint64(m.req.frame)}).SetLink(m.req.frame)
	// Like Wireshark 4.x, the response carries the request URI fields.
	ht.AddGenerated(hfHTTPFullURI, d.StringValue(m.req.uri)).SetText("[Request URI: %s]", m.req.uri)
	if m.req.path != "" {
		ht.AddGenerated(hfHTTPURI, d.StringValue(m.req.path)).SetHidden()
	}
}

// findReqKey locates the message key of a request inside its frame.
func findReqKey(sess *d.Session, r *httpReq) uint32 {
	for k := uint32(1); k < 64; k++ {
		if m, ok := sess.FrameData(protoHTTP, r.frame, k).(*httpMatch); ok && m.req == r {
			return k
		}
	}
	return 1
}

// httpSwitchProtocol hands the rest of the connection to another protocol
// after CONNECT or an Upgrade.
func httpSwitchProtocol(pi *d.PacketInfo, headers map[string]string, code int) {
	var h *d.Handle
	up := strings.ToLower(headers["upgrade"])
	switch {
	case code == 101 && strings.Contains(up, "websocket"):
		h = FindHandleLazy("websocket")
	case code == 101 && strings.Contains(up, "h2c"):
		h = FindHandleLazy("http2")
	case code/100 == 2:
		h = tlsHandle // CONNECT tunnels are almost always TLS
	}
	if h != nil {
		SetTCPAppHandle(pi, h)
	}
}

// FindHandleLazy looks a handle up by name at call time.
func FindHandleLazy(name string) *d.Handle { return d.FindHandle(name) }

// ---- media types ----

// MediaTypes maps content types to body dissectors (Wireshark's "media_type" table).
var MediaTypes = map[string]*d.Handle{}

var (
	protoTextLines = d.RegisterProto("Line-based text data", "Line-based text data", "data-text-lines")
	hfTextLine     = protoTextLines.Field("data-text-lines.line", "Line", d.FtString)
	protoMedia     = d.RegisterProto("Media Type", "Media", "media")
	hfMediaType    = protoMedia.Field("media.type", "Media type", d.FtString)
	hfMediaData    = protoMedia.Field("media.data", "Media data", d.FtBytes)
	protoForm      = d.RegisterProto("HTML Form URL Encoded", "URLENCODED-FORM", "urlencoded-form")
	hfFormKey      = protoForm.Field("urlencoded-form.key", "Key", d.FtString)
	hfFormValue    = protoForm.Field("urlencoded-form.value", "Value", d.FtString)
)

// DissectMedia dissects a body by content type.
func DissectMedia(ctype string, tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) {
	if tvb.Len() == 0 {
		return
	}
	if h := MediaTypes[ctype]; h != nil {
		if pi.Call(h, tvb, tree) > 0 {
			return
		}
	}
	switch {
	case strings.HasSuffix(ctype, "+json") || ctype == "application/json" || ctype == "text/json":
		if h := d.FindHandle("json"); h != nil && pi.Call(h, tvb, tree) > 0 {
			return
		}
	case ctype == "application/x-www-form-urlencoded":
		ft := tree.AddProtocol(protoForm, tvb, 0, -1)
		for _, kv := range strings.Split(string(tvb.Raw()), "&") {
			k, v, _ := strings.Cut(kv, "=")
			ku, _ := url.QueryUnescape(k)
			vu, _ := url.QueryUnescape(v)
			it := ft.AddText(nil, 0, 0, "Form item: \"%s\" = \"%s\"", ku, vu)
			it.AddValue(hfFormKey, nil, 0, 0, d.StringValue(ku))
			it.AddValue(hfFormValue, nil, 0, 0, d.StringValue(vu))
		}
		return
	case strings.HasPrefix(ctype, "text/") || ctype == "application/xml" || ctype == "application/javascript" ||
		strings.HasSuffix(ctype, "+xml") || ctype == "application/x-ndjson":
		dissectTextLines(tvb, ctype, tree)
		return
	}
	mt := tree.AddProtocol(protoMedia, tvb, 0, -1)
	if ctype == "" {
		ctype = "unknown"
	}
	mt.SetText("Media Type")
	mt.AddGenerated(hfMediaType, d.StringValue(ctype))
	mt.AddBytes(hfMediaData, tvb, 0, tvb.Len())
}

func dissectTextLines(tvb *d.Tvb, ctype string, tree *d.Node) {
	raw := tvb.Raw()
	n := bytes.Count(raw, []byte("\n"))
	if len(raw) > 0 && raw[len(raw)-1] != '\n' {
		n++
	}
	lt := tree.AddProtocol(protoTextLines, tvb, 0, -1)
	lt.SetText("Line-based text data: %s (%d lines)", ctype, n)
	pos := 0
	for i := 0; pos < len(raw) && i < 2000; i++ {
		e := bytes.IndexByte(raw[pos:], '\n')
		if e < 0 {
			e = len(raw) - pos
		} else {
			e++
		}
		line := strings.TrimRight(string(raw[pos:pos+e]), "\r\n")
		lt.AddValue(hfTextLine, tvb, pos, e, d.StringValue(line)).SetText("%s", fmt.Sprintf("%q", line)[1:len(fmt.Sprintf("%q", line))-1])
		pos += e
	}
}
