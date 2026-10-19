package proto

import (
	"fmt"
	"strconv"
	"strings"

	d "github.com/poseydon/lazysniffer/internal/dissect"
)

// ---------------- Redis (RESP) ----------------

var (
	protoRESP    = d.RegisterProto("RESP", "RESP", "resp")
	hfRESPSimple = protoRESP.Field("resp.string", "Simple string", d.FtString)
	hfRESPError  = protoRESP.Field("resp.error", "Error", d.FtString)
	hfRESPInt    = protoRESP.Field("resp.integer", "Integer", d.FtInt64)
	hfRESPBulk   = protoRESP.Field("resp.bulk_string.value", "Bulk string value", d.FtBytes)
	hfRESPBulkN  = protoRESP.Field("resp.bulk_string", "Bulk string", d.FtNone)
	hfRESPBulkLn = protoRESP.Field("resp.bulk_string.length", "Bulk string length", d.FtInt32)
	hfRESPArray  = protoRESP.Field("resp.array.length", "Array length", d.FtInt64)
	hfRESPArrayN = protoRESP.Field("resp.array", "Array", d.FtNone)
	hfRESPCmd    = protoRESP.Field("resp.command", "Command", d.FtString)
	respHandle   = d.RegisterHandle("resp", d.NewHandle(protoRESP, dissectRESP))
)

func init() { TCPPortTable.Add(6379, respHandle) }

// respValue parses one RESP value at off. It returns the end offset, a
// printable summary and whether the value is complete.
func respValue(raw []byte, off int, tvb *d.Tvb, tree *d.Node, depth int) (int, string, bool) {
	if off >= len(raw) {
		return off, "", false
	}
	eol := strings.Index(string(raw[off:]), "\r\n")
	if eol < 0 {
		return off, "", false
	}
	if eol < 1 {
		return len(raw), "", true // not RESP
	}
	line := string(raw[off+1 : off+eol])
	next := off + eol + 2
	switch raw[off] {
	case '+':
		tree.AddString(hfRESPSimple, tvb, off+1, len(line))
		return next, line, true
	case '-':
		tree.AddString(hfRESPError, tvb, off+1, len(line))
		return next, "ERR " + line, true
	case ':':
		n, _ := strconv.ParseInt(line, 10, 64)
		tree.AddValue(hfRESPInt, tvb, off+1, len(line), d.IntValue(d.FtInt64, n))
		return next, line, true
	case '$':
		n, err := strconv.Atoi(line)
		if err != nil || n < 0 {
			return next, "(nil)", err == nil
		}
		if next+n+2 > len(raw) {
			return off, "", false
		}
		bn := tree.AddText(tvb, off, next+n+2-off, "Bulk string")
		bn.AddValue(hfRESPBulkN, nil, 0, 0, d.Value{})
		bn.AddValue(hfRESPBulkLn, tvb, off+1, len(line), d.IntValue(d.FtInt32, int64(n)))
		bn.AddBytes(hfRESPBulk, tvb, next, n)
		return next + n + 2, string(raw[next : next+n]), true
	case '*':
		n, err := strconv.Atoi(line)
		if err != nil || n < 0 || depth > 8 {
			return next, "(nil)", err == nil
		}
		an := tree.AddText(tvb, off, 0, "Array")
		an.AddValue(hfRESPArrayN, nil, 0, 0, d.Value{})
		an.AddValue(hfRESPArray, tvb, off+1, len(line), d.IntValue(d.FtInt64, int64(n)))
		tree = an
		var parts []string
		p := next
		for i := 0; i < n; i++ {
			np, s, ok := respValue(raw, p, tvb, tree, depth+1)
			if !ok {
				return off, "", false
			}
			parts = append(parts, s)
			p = np
		}
		return p, strings.Join(parts, " "), true
	}
	return len(raw), "", true
}

func dissectRESP(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	rt := tree.AddProtocol(protoRESP, tvb, 0, -1)
	pi.SetProtocol("RESP")
	raw := tvb.Raw()
	client := pi.DstPort == 6379
	var infos []string
	for off := 0; off < len(raw); {
		end, s, ok := respValue(raw, off, tvb, rt, 0)
		if !ok {
			pi.Desegment(off, d.DesegmentOneMore)
			break
		}
		if client {
			rt.AddValue(hfRESPCmd, nil, 0, 0, d.StringValue(strings.ToUpper(strings.SplitN(s, " ", 2)[0])))
			infos = append(infos, "Request: "+s)
		} else {
			infos = append(infos, "Response: "+s)
		}
		off = end
	}
	pi.SetInfo(strings.Join(infos, " | "))
	return tvb.Len()
}

// ---------------- PostgreSQL ----------------

var (
	pgFront = map[byte]string{'Q': "Simple query", 'P': "Parse", 'B': "Bind", 'E': "Execute", 'S': "Sync", 'X': "Terminate", 'p': "Password message",
		'D': "Describe", 'C': "Close", 'H': "Flush", 'F': "Function call", 'd': "Copy data", 'c': "Copy done"}
	pgBack = map[byte]string{'R': "Authentication request", 'S': "Parameter status", 'K': "BackendKeyData", 'Z': "Ready for query", 'T': "Row description",
		'D': "Data row", 'C': "Command completion", 'E': "Error", 'N': "Notice", '1': "Parse completion", '2': "Bind completion",
		'3': "Close completion", 'I': "Empty query", 'n': "No data", 't': "Parameter description", 'A': "Notification response",
		'G': "Copy in response", 'H': "Copy out response", 'd': "Copy data", 'c': "Copy done", 's': "Portal suspended"}
	protoPG     = d.RegisterProto("PostgreSQL", "PGSQL", "pgsql")
	hfPGType    = protoPG.Field("pgsql.type", "Type", d.FtString)
	hfPGLen     = protoPG.Field("pgsql.length", "Length", d.FtUint32)
	hfPGQuery   = protoPG.Field("pgsql.query", "Query", d.FtString)
	hfPGUser    = protoPG.Field("pgsql.user", "User", d.FtString)
	hfPGDB      = protoPG.Field("pgsql.database", "Database", d.FtString)
	hfPGParam   = protoPG.Field("pgsql.parameter_name", "Parameter name", d.FtString)
	hfPGValue   = protoPG.Field("pgsql.parameter_value", "Parameter value", d.FtString)
	hfPGAuth    = protoPG.Field("pgsql.authtype", "Authentication type", d.FtUint32, d.WithVS(map[uint64]string{0: "Success", 3: "Plaintext password", 5: "MD5 password", 10: "SASL", 11: "SASL continue", 12: "SASL final"}))
	hfPGPass    = protoPG.Field("pgsql.password", "Password", d.FtString)
	hfPGTag     = protoPG.Field("pgsql.tag", "Tag", d.FtString)
	hfPGSev     = protoPG.Field("pgsql.severity", "Severity", d.FtString)
	hfPGMsg     = protoPG.Field("pgsql.message", "Message", d.FtString)
	hfPGStatus  = protoPG.Field("pgsql.status", "Status", d.FtString)
	hfPGVersion = protoPG.Field("pgsql.version_major", "Version major", d.FtUint16)
	pgHandle    = d.RegisterHandle("pgsql", d.NewHandle(protoPG, dissectPG))
)

type pgState struct {
	started [2]bool // startup message / SSL negotiation done per direction
	ssl     bool
}

func init() { TCPPortTable.Add(5432, pgHandle) }

func dissectPG(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	client := pi.DstPort == 5432
	var st *pgState
	if pi.Conv != nil {
		st, _ = pi.Conv.Data(protoPG).(*pgState)
		if st == nil {
			st = &pgState{}
			if !pi.Visited {
				pi.Conv.SetData(protoPG, st)
			}
		}
	} else {
		st = &pgState{}
	}
	pt := tree.AddProtocol(protoPG, tvb, 0, -1)
	pi.SetProtocol("PGSQL")
	if st.ssl && !client && tvb.Len() == 1 {
		if tvb.U8(0) == 'S' {
			SetTCPAppHandle(pi, tlsHandle)
			pi.SetInfo("SSL accepted")
		} else {
			pi.SetInfo("SSL refused")
		}
		return 1
	}
	var infos []string
	// Startup (untyped) message: length, code.
	if client && tvb.Len() >= 8 && !pi.Visited && !st.started[0] || client && tvb.Len() >= 8 && pgIsStartup(tvb) {
		l := int(tvb.U32(0))
		code := tvb.U32(4)
		if l == 8 && code == 80877103 {
			pt.AddText(tvb, 0, 8, "SSL request")
			pt.AddValue(hfPGType, tvb, 0, 0, d.StringValue("SSL request"))
			if !pi.Visited {
				st.ssl = true
			}
			pi.SetInfo(">S")
			return tvb.Len()
		}
		if code == 196608 && l <= tvb.Len() {
			pt.AddValue(hfPGType, tvb, 0, 0, d.StringValue("Startup message"))
			pt.AddUint(hfPGLen, tvb, 0, 4)
			pt.AddUint(hfPGVersion, tvb, 4, 2)
			var user string
			for p := 8; p < l-1; {
				k, n1 := tvb.Stringz(p, l-p)
				if k == "" {
					break
				}
				v, n2 := tvb.Stringz(p+n1, l-p-n1)
				if k == "user" {
					pt.AddString(hfPGUser, tvb, p+n1, len(v))
					user = v
				} else if k == "database" {
					pt.AddString(hfPGDB, tvb, p+n1, len(v))
				}
				p += n1 + n2
			}
			if !pi.Visited {
				st.started[0] = true
			}
			pi.SetInfo(">?")
			_ = user
			return tvb.Len()
		}
	}
	n := TCPDissectPDUs(tvb, pi, pt, 5, func(t *d.Tvb, off int) int { return 1 + int(t.U32(off+1)) }, func(t *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
		typ := t.U8(0)
		names := pgBack
		if client {
			names = pgFront
		}
		mt := tree.AddText(t, 0, t.Len(), "Type: %s", orDefault(names[typ], string(typ)))
		mt.AddValue(hfPGType, t, 0, 1, d.StringValue(orDefault(names[typ], string(typ))))
		mt.AddUint(hfPGLen, t, 1, 4)
		body := t.Sub(5, -1)
		info := string(typ)
		switch {
		case client && typ == 'Q':
			_, q := mt.AddString(hfPGQuery, body, 0, body.Len()-1)
			info = "Query: " + q
		case client && typ == 'P':
			_, n1 := body.Stringz(0, body.Len())
			q, _ := body.Stringz(n1, body.Len()-n1)
			mt.AddValue(hfPGQuery, body, n1, len(q), d.StringValue(q))
			info = "Parse: " + q
		case client && typ == 'p':
			mt.AddString(hfPGPass, body, 0, body.Len()-1)
			info = "Password message"
		case !client && typ == 'R':
			_, a := mt.AddUint(hfPGAuth, body, 0, 4)
			info = "Authentication request " + map[uint64]string{0: "(Success)", 3: "(Plaintext password)", 5: "(MD5 password)", 10: "(SASL)"}[a]
		case !client && typ == 'S':
			k, n1 := body.Stringz(0, body.Len())
			v, _ := body.Stringz(n1, body.Len()-n1)
			mt.AddValue(hfPGParam, body, 0, len(k), d.StringValue(k))
			mt.AddValue(hfPGValue, body, n1, len(v), d.StringValue(v))
			info = "Parameter status " + k + "=" + v
		case !client && typ == 'C':
			_, tg := mt.AddString(hfPGTag, body, 0, body.Len()-1)
			info = "Command completion: " + tg
		case !client && typ == 'Z':
			mt.AddString(hfPGStatus, body, 0, 1)
			info = "Ready for query"
		case !client && (typ == 'E' || typ == 'N'):
			var msg string
			for p := 0; p < body.Len() && body.U8(p) != 0; {
				code := body.U8(p)
				s, n1 := body.Stringz(p+1, body.Len()-p-1)
				switch code {
				case 'S':
					mt.AddValue(hfPGSev, body, p+1, len(s), d.StringValue(s))
				case 'M':
					mt.AddValue(hfPGMsg, body, p+1, len(s), d.StringValue(s))
					msg = s
				}
				p += 1 + n1
			}
			info = map[byte]string{'E': "Error", 'N': "Notice"}[typ] + ": " + msg
		default:
			info = orDefault(names[typ], info)
		}
		infos = append(infos, string(typ))
		return t.Len()
	})
	if len(infos) > 0 {
		prefix := "<"
		if client {
			prefix = ">"
		}
		pi.SetInfo(prefix + strings.Join(infos, "/"))
	}
	return n
}

func pgIsStartup(tvb *d.Tvb) bool {
	if tvb.Len() < 8 {
		return false
	}
	code := tvb.U32(4)
	return code == 196608 || code == 80877103
}

// ---------------- MySQL ----------------

var (
	mysqlCmds = map[uint64]string{1: "Quit", 2: "Use Database", 3: "Query", 4: "Show Fields", 5: "Create DB", 6: "Drop DB", 7: "Refresh", 8: "Shutdown",
		9: "Statistics", 10: "Process List", 14: "Ping", 22: "Prepare Statement", 23: "Execute Statement", 25: "Close Statement"}
	protoMySQL   = d.RegisterProto("MySQL Protocol", "MySQL", "mysql")
	hfMySQLLen   = protoMySQL.Field("mysql.packet_length", "Packet Length", d.FtUint24)
	hfMySQLNum   = protoMySQL.Field("mysql.packet_number", "Packet Number", d.FtUint8)
	hfMySQLProto = protoMySQL.Field("mysql.protocol", "Protocol", d.FtUint8)
	hfMySQLVer   = protoMySQL.Field("mysql.version", "Version", d.FtString)
	hfMySQLThr   = protoMySQL.Field("mysql.thread_id", "Thread ID", d.FtUint32)
	hfMySQLUser  = protoMySQL.Field("mysql.user", "Username", d.FtString)
	hfMySQLSchem = protoMySQL.Field("mysql.schema", "Schema", d.FtString)
	hfMySQLCmd   = protoMySQL.Field("mysql.command", "Command", d.FtUint8, d.WithVS(mysqlCmds))
	hfMySQLQuery = protoMySQL.Field("mysql.query", "Statement", d.FtString)
	hfMySQLErr   = protoMySQL.Field("mysql.error_code", "Error Code", d.FtUint16)
	hfMySQLMsg   = protoMySQL.Field("mysql.error.message", "Error message", d.FtString)
	hfMySQLRows  = protoMySQL.Field("mysql.affected_rows", "Affected Rows", d.FtUint64)
	mysqlHandle  = d.RegisterHandle("mysql", d.NewHandle(protoMySQL, dissectMySQL))
)

type mysqlState struct {
	phase      int // 0 greeting expected, 1 login, 2 commands
	loginFrame uint32
}

func init() { TCPPortTable.Add(3306, mysqlHandle) }

func dissectMySQL(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	client := pi.DstPort == 3306
	var st *mysqlState
	if pi.Conv != nil {
		st, _ = pi.Conv.Data(protoMySQL).(*mysqlState)
		if st == nil {
			st = &mysqlState{}
			if !pi.Visited {
				pi.Conv.SetData(protoMySQL, st)
			}
		}
	} else {
		st = &mysqlState{}
	}
	mt := tree.AddProtocol(protoMySQL, tvb, 0, -1)
	pi.SetProtocol("MySQL")
	var infos []string
	n := TCPDissectPDUs(tvb, pi, mt, 4, func(t *d.Tvb, off int) int { return 4 + int(t.U24LE(off)) }, func(t *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
		pt := tree.AddText(t, 0, t.Len(), "MySQL packet")
		pt.AddUintLE(hfMySQLLen, t, 0, 3)
		_, seq := pt.AddUint(hfMySQLNum, t, 3, 1)
		body := t.Sub(4, -1)
		if body.Len() == 0 {
			return t.Len()
		}
		first := body.U8(0)
		switch {
		case !client && first == 10 && seq == 0:
			pt.AddUint(hfMySQLProto, body, 0, 1)
			v, n1 := body.Stringz(1, body.Len()-1)
			pt.AddValue(hfMySQLVer, body, 1, len(v), d.StringValue(v))
			pt.AddUintLE(hfMySQLThr, body, 1+n1, 4)
			infos = append(infos, "Server Greeting  proto=10 version="+v)
			if !pi.Visited {
				st.phase = 1
			}
		case client && seq == 1 && (pi.Num == st.loginFrame || (!pi.Visited && st.phase == 1)):
			// login: caps(4) maxpacket(4) charset(1) filler(23) user\0
			if body.Len() > 32 {
				u, _ := body.Stringz(32, body.Len()-32)
				pt.AddValue(hfMySQLUser, body, 32, len(u), d.StringValue(u))
				infos = append(infos, "Login Request user="+u)
			} else {
				infos = append(infos, "Login Request")
			}
			if !pi.Visited {
				st.phase, st.loginFrame = 2, pi.Num
			}
		case client && seq == 0:
			pt.AddUint(hfMySQLCmd, body, 0, 1)
			switch first {
			case 3, 22:
				_, q := pt.AddString(hfMySQLQuery, body, 1, body.Len()-1)
				infos = append(infos, "Request "+mysqlCmds[uint64(first)])
				_ = q
			case 2:
				pt.AddString(hfMySQLSchem, body, 1, body.Len()-1)
				infos = append(infos, "Use Database")
			default:
				infos = append(infos, "Request "+orDefault(mysqlCmds[uint64(first)], fmt.Sprint(first)))
			}
		case !client && first == 0xff && body.Len() >= 3:
			_, code := pt.AddUintLE(hfMySQLErr, body, 1, 2)
			off := 3
			if body.Len() > 9 && body.U8(3) == '#' {
				off = 9
			}
			_, m := pt.AddString(hfMySQLMsg, body, off, body.Len()-off)
			infos = append(infos, fmt.Sprintf("Error %d %s", code, m))
		case !client && first == 0 && seq > 0:
			infos = append(infos, "OK")
		case !client && first == 0xfe && body.Len() < 9:
			infos = append(infos, "EOF")
		default:
			if !client {
				infos = append(infos, "Response")
			}
		}
		return t.Len()
	})
	if len(infos) > 0 {
		pi.SetInfo(strings.Join(infos, " | "))
	}
	return n
}

// ---------------- MQTT ----------------

var (
	mqttTypes = map[uint64]string{1: "Connect Command", 2: "Connect Ack", 3: "Publish Message", 4: "Publish Ack", 5: "Publish Received", 6: "Publish Release",
		7: "Publish Complete", 8: "Subscribe Request", 9: "Subscribe Ack", 10: "Unsubscribe Request", 11: "Unsubscribe Ack", 12: "Ping Request",
		13: "Ping Response", 14: "Disconnect Req", 15: "Authentication Exchange"}
	protoMQTT   = d.RegisterProto("MQ Telemetry Transport Protocol", "MQTT", "mqtt")
	hfMQTTHdr   = protoMQTT.Field("mqtt.hdrflags", "Header Flags", d.FtUint8, d.WithBase(d.BaseHex))
	hfMQTTType  = protoMQTT.Field("mqtt.msgtype", "Message Type", d.FtUint8, d.WithMask(0xf0), d.WithParentBits(8), d.WithVS(mqttTypes))
	hfMQTTQoS   = protoMQTT.Field("mqtt.qos", "QoS Level", d.FtUint8, d.WithMask(0x06), d.WithParentBits(8))
	hfMQTTRet   = protoMQTT.Field("mqtt.retain", "Retain", d.FtBool, d.WithMask(0x01), d.WithParentBits(8))
	hfMQTTLen   = protoMQTT.Field("mqtt.len", "Msg Len", d.FtUint32)
	hfMQTTProto = protoMQTT.Field("mqtt.protoname", "Protocol Name", d.FtString)
	hfMQTTVer   = protoMQTT.Field("mqtt.ver", "Version", d.FtUint8)
	hfMQTTFlags = protoMQTT.Field("mqtt.conflags", "Connect Flags", d.FtUint8, d.WithBase(d.BaseHex))
	hfMQTTKA    = protoMQTT.Field("mqtt.kalive", "Keep Alive", d.FtUint16)
	hfMQTTCID   = protoMQTT.Field("mqtt.clientid", "Client ID", d.FtString)
	hfMQTTUser  = protoMQTT.Field("mqtt.username", "User Name", d.FtString)
	hfMQTTPass  = protoMQTT.Field("mqtt.passwd", "Password", d.FtString)
	hfMQTTTopic = protoMQTT.Field("mqtt.topic", "Topic", d.FtString)
	hfMQTTMsg   = protoMQTT.Field("mqtt.msg", "Message", d.FtBytes)
	hfMQTTMsgID = protoMQTT.Field("mqtt.msgid", "Message Identifier", d.FtUint16)
	hfMQTTRC    = protoMQTT.Field("mqtt.conack.val", "Return Code", d.FtUint8)
	mqttHandle  = d.RegisterHandle("mqtt", d.NewHandle(protoMQTT, dissectMQTT))
)

func init() { TCPPortTable.Add(1883, mqttHandle) }

func mqttLen(t *d.Tvb, off int) (int, int) {
	mul, v, n := 1, 0, 0
	for i := 0; i < 4; i++ {
		if !t.Has(off+1+i, 1) {
			return -1, 0
		}
		b := int(t.U8(off + 1 + i))
		v += (b & 0x7f) * mul
		mul *= 128
		n++
		if b&0x80 == 0 {
			return v, n
		}
	}
	return -1, 0
}

func dissectMQTT(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	mt := tree.AddProtocol(protoMQTT, tvb, 0, -1)
	pi.SetProtocol("MQTT")
	var infos []string
	n := TCPDissectPDUs(tvb, pi, mt, 2, func(t *d.Tvb, off int) int {
		l, n := mqttLen(t, off)
		if l < 0 {
			if n == 0 && t.Remaining(off) < 5 {
				return t.Remaining(off) + 1
			}
			return -1
		}
		return 1 + n + l
	}, func(t *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
		h := t.U8(0)
		typ := uint64(h >> 4)
		pt := tree.AddText(t, 0, t.Len(), "%s", orDefault(mqttTypes[typ], "MQTT"))
		hn, _ := pt.AddUint(hfMQTTHdr, t, 0, 1)
		hn.AddBits(hfMQTTType, t, 0, 1, uint64(h))
		if typ == 3 {
			hn.AddBits(hfMQTTQoS, t, 0, 1, uint64(h))
			hn.AddBits(hfMQTTRet, t, 0, 1, uint64(h))
		}
		l, ln := mqttLen(t, 0)
		pt.AddUintValue(hfMQTTLen, t, 1, ln, uint64(l))
		p := 1 + ln
		str := func(f *d.FieldDef) string {
			sl := int(t.U16(p))
			_, s := pt.AddString(f, t, p+2, sl)
			p += 2 + sl
			return s
		}
		info := orDefault(mqttTypes[typ], "MQTT")
		switch typ {
		case 1:
			str(hfMQTTProto)
			pt.AddUint(hfMQTTVer, t, p, 1)
			_, fl := pt.AddUint(hfMQTTFlags, t, p+1, 1)
			pt.AddUint(hfMQTTKA, t, p+2, 2)
			p += 4
			cid := str(hfMQTTCID)
			if fl&0x04 != 0 { // will
				str(hfMQTTTopic)
				sl := int(t.U16(p))
				p += 2 + sl
			}
			if fl&0x80 != 0 {
				str(hfMQTTUser)
			}
			if fl&0x40 != 0 {
				str(hfMQTTPass)
			}
			_ = cid
		case 2:
			pt.AddUint(hfMQTTRC, t, p+1, 1)
		case 3:
			topic := str(hfMQTTTopic)
			if (h>>1)&3 > 0 {
				pt.AddUint(hfMQTTMsgID, t, p, 2)
				p += 2
			}
			if p < t.Len() {
				pt.AddBytes(hfMQTTMsg, t, p, t.Len()-p)
			}
			info += fmt.Sprintf(" [%s]", topic)
		case 8, 10:
			pt.AddUint(hfMQTTMsgID, t, p, 2)
			p += 2
			var topics []string
			for p+2 <= t.Len() {
				topics = append(topics, str(hfMQTTTopic))
				if typ == 8 {
					p++
				}
			}
			info += " [" + strings.Join(topics, ", ") + "]"
		case 4, 5, 6, 7, 9, 11:
			pt.AddUint(hfMQTTMsgID, t, p, 2)
		}
		infos = append(infos, info)
		return t.Len()
	})
	if len(infos) > 0 {
		pi.SetInfo(strings.Join(infos, ", "))
	}
	return n
}
