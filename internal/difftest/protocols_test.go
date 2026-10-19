package difftest

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/poseydon/lazysniffer/internal/keylog"
	g "github.com/poseydon/lazysniffer/internal/testutil/pktgen"
)

func TestServices(t *testing.T) {
	compare(t, write(t, g.SampleServices()), "", []string{
		"udp.srcport", "udp.dstport",
		"dhcp.type", "dhcp.id", "dhcp.hw.mac_addr", "dhcp.option.dhcp", "dhcp.option.hostname", "dhcp.option.requested_ip_address", "dhcp.cookie",
		"ntp.flags", "ntp.flags.mode", "ntp.flags.vn", "ntp.stratum", "ntp.ppoll",
		"syslog.facility", "syslog.level", "syslog.msg",
		"stun.type", "stun.length", "stun.id", "stun.att.type", "stun.att.length", "stun.att.ipv4", "stun.att.port", "stun.cookie",
		"wg.type", "wg.sender",
		"isakmp.ispi", "isakmp.rspi", "isakmp.exchangetype", "isakmp.nextpayload", "isakmp.messageid", "isakmp.length", "isakmp.version",
		"esp.spi", "esp.sequence",
		"openvpn.opcode", "openvpn.keyid", "openvpn.sessionid",
		"ssh.protocol", "ssh.message_code", "ssh.padding_length", "ssh.packet_length", "ssh.kex_algorithms", "ssh.kex.hassh", "ssh.kex.hassh_algorithms", "ssh.cookie",
		"tcp.stream", "tcp.len",
	})
}

func TestTextProtocols(t *testing.T) {
	compare(t, write(t, g.SampleTextProtocols()), "", []string{
		"tcp.stream", "tcp.len",
		"ftp.request.command", "ftp.request.arg", "ftp.response.code", "ftp.response.arg", "ftp.passive.port", "ftp-data.setup-frame", "ftp-data.command", "ftp-data.len",
		"pop.request.command", "pop.request.parameter", "pop.response.indicator", "pop.response.description",
		"imap.request.command", "imap.request.parameter", "imap.line", "imap.response", "imap.request",
		"smtp.req.command", "smtp.req.parameter", "smtp.response.code", "smtp.rsp.parameter", "smtp.data.fragment",
		"telnet.data",
		"socks.version", "socks.command", "socks.remote_name", "socks.port", "socks.dst", "socks.results",
	})
}

func TestDatabases(t *testing.T) {
	compare(t, write(t, g.SampleDatabases()), "", []string{
		"tcp.stream", "tcp.len",
		"resp.string", "resp.bulk_string.value", "resp.bulk_string.length", "resp.array.length",
		"pgsql.type", "pgsql.length", "pgsql.query", "pgsql.user", "pgsql.database", "pgsql.authtype", "pgsql.version_major",
		"mysql.packet_length", "mysql.packet_number", "mysql.version", "mysql.command", "mysql.query", "mysql.user", "mysql.thread_id",
		"mqtt.msgtype", "mqtt.len", "mqtt.protoname", "mqtt.ver", "mqtt.kalive", "mqtt.clientid", "mqtt.topic", "mqtt.msg", "mqtt.conflags",
		"snmp.version", "snmp.community", "snmp.request_id", "snmp.name", "snmp.error_status", "snmp.error_index",
		"lldp.tlv.type", "lldp.tlv.len", "lldp.chassis.id.mac", "lldp.tlv.system.name", "lldp.time_to_live", "lldp.port.id",
	})
}

func TestHTTP2Plain(t *testing.T) {
	compare(t, write(t, g.SampleHTTP2(8083)), "", []string{
		"tcp.stream", "tcp.len", "http2.magic", "http2.length", "http2.type", "http2.flags", "http2.streamid", "http2.header.name", "http2.header.value",
		"http2.headers.method", "http2.headers.path", "http2.headers.authority", "http2.headers.scheme", "http2.headers.status",
		"http2.headers.content_type", "http2.headers.user_agent", "http2.headers.content_encoding", "http2.settings.id", "http2.settings.max_concurrent_streams",
		"http2.request_in", "http2.response_in", "http2.window_update.window_size_increment", "http2.flags.end_stream", "http2.flags.eh",
		"http2.request.full_uri", "http2.body.reassembled.data",
	})
}

func TestQUICInitial(t *testing.T) {
	ch := g.QUICClientHello(t, "quic.example.test")
	f := g.DefaultFlow()
	f.B.Port = 443
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	scid := []byte{0x01, 0x02, 0x03, 0x04}
	half := len(ch) / 2
	p1 := g.QUICInitial(t, 1, dcid, scid, 0, 0, ch[:half], true)
	p2 := g.QUICInitial(t, 1, dcid, scid, 1, uint64(half), ch[half:], true)
	pk := []g.Packet{{TS: 1e9, Data: g.UDP(f, p1)}, {TS: 2e9, Data: g.UDP(f, p2)}}
	compare(t, write(t, pk), "", []string{
		"udp.srcport", "udp.dstport", "quic.header_form", "quic.long.packet_type", "quic.version", "quic.dcid", "quic.scid", "quic.dcil", "quic.scil",
		"quic.token_length", "quic.length", "quic.packet_number", "quic.frame_type", "quic.crypto.offset", "quic.crypto.length",
		"tls.handshake.type", "tls.handshake.extensions_server_name", "tls.handshake.ja4", "tls.handshake.extensions_alpn_str", "tls.handshake.ciphersuite",
		"quic.tp.type", "quic.tp.len", "quic.padding_length",
	})
}

func TestDecryptedTLS(t *testing.T) {
	cert := g.SelfSigned(t, "example.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	for name, ver := range map[string]uint16{"1.2": tls.VersionTLS12, "1.3": tls.VersionTLS13} {
		srv := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}, MinVersion: ver, MaxVersion: ver}
		cli := &tls.Config{ServerName: "example.test", InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}, MinVersion: ver, MaxVersion: ver}
		writes, kl := g.TLSExchange(t, srv, cli, []byte("GET /pic.jpg HTTP/1.1\r\nHost: media.example\r\nUser-Agent: x\r\n\r\n"),
			append([]byte("HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nContent-Length: 20000\r\n\r\n"), make([]byte, 20000)...))
		path := filepath.Join(t.TempDir(), "keys.log")
		os.WriteFile(path, kl, 0o600)
		keylog.Default.SetFiles(path)
		f := g.DefaultFlow()
		f.B.Port = 443
		pk := g.TLSCapture(f, writes, 1400)
		t.Run(name, func(t *testing.T) {
			t.Setenv("DIFFTEST_KEYLOG", path)
			compare(t, write(t, pk), "", []string{
				"tls.handshake.type", "tls.handshake.extensions_alpn_str", "tls.record.content_type", "tls.record.length",
				"http.request.method", "http.request.uri", "http.host", "http.user_agent", "http.response.code", "http.content_type", "http.content_length",
				"http.request.full_uri", "http.response_in", "http.request_in", "tls.app_data", "tls.handshake.certificate_length",
			})
		})
		keylog.Default.SetFiles()
	}
}

func TestSIPAndRTP(t *testing.T) {
	f := g.DefaultFlow()
	var pk []g.Packet
	invite := "INVITE sip:bob@10.0.0.2 SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\r\nFrom: <sip:alice@10.0.0.1>;tag=a1\r\nTo: <sip:bob@10.0.0.2>\r\nCall-ID: call-1@10.0.0.1\r\nCSeq: 1 INVITE\r\nContact: <sip:alice@10.0.0.1:5060>\r\nContent-Type: application/sdp\r\nContent-Length: "
	sdp := "v=0\r\no=alice 1 1 IN IP4 10.0.0.1\r\ns=call\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 20000 RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\n"
	msg := invite + itoa(len(sdp)) + "\r\n\r\n" + sdp
	ok := "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\r\nFrom: <sip:alice@10.0.0.1>;tag=a1\r\nTo: <sip:bob@10.0.0.2>;tag=b1\r\nCall-ID: call-1@10.0.0.1\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
	pk = append(pk, g.UDPPacket(f, 5060, 5060, []byte(msg)), g.UDPPacket(f.Rev(), 5060, 5060, []byte(ok)))
	g2 := f
	for i := 0; i < 5; i++ {
		rtp := make([]byte, 12+160)
		rtp[0], rtp[1] = 0x80, 0
		rtp[3] = byte(i)
		rtp[7] = byte(160 * i)
		rtp[11] = 0x11
		pk = append(pk, g.UDPPacket(g2, 20000, 20000, rtp))
	}
	for i := range pk {
		pk[i].TS = int64(i+1) * 20e6
	}
	compare(t, write(t, pk), "", []string{
		"udp.srcport", "udp.dstport", "sip.Method", "sip.Request-Line", "sip.r-uri", "sip.Status-Code", "sip.Status-Line", "sip.Call-ID", "sip.From", "sip.To",
		"sip.CSeq", "sip.CSeq.method", "sip.Content-Type", "sip.Content-Length", "sip.from.user", "sip.to.user",
		"sdp.version", "sdp.media", "sdp.media.port", "sdp.connection_info", "sdp.connection_info.address", "sdp.owner.username",
		"rtp.version", "rtp.p_type", "rtp.seq", "rtp.timestamp", "rtp.ssrc", "rtp.marker", "rtp.setup-frame", "rtp.payload",
	})
}

func itoa(n int) string {
	return string([]byte(func() []byte {
		if n == 0 {
			return []byte("0")
		}
		var b []byte
		for n > 0 {
			b = append([]byte{byte('0' + n%10)}, b...)
			n /= 10
		}
		return b
	}()))
}

func TestQUICConnection(t *testing.T) {
	f := g.DefaultFlow()
	f.B.Port = 443
	q := g.NewQUICConn(t, f, "quic.example.test", "h3")
	q.SendStream(true, 0, []byte("hello quic stream"), true)
	q.SendStream(false, 0, []byte("response bytes"), false)
	q.SendStream(false, 0, []byte(" and more"), true)
	kf := filepath.Join(t.TempDir(), "keys.log")
	os.WriteFile(kf, q.Keylog.Bytes(), 0o600)
	file := write(t, q.Packets)
	fields := []string{"udp.srcport", "udp.dstport", "quic.header_form", "quic.long.packet_type", "quic.version", "quic.dcid", "quic.scid", "quic.packet_number", "quic.frame_type",
		"quic.crypto.offset", "quic.crypto.length", "quic.stream.stream_id", "quic.stream.offset", "quic.stream.length", "quic.stream.fin", "quic.stream_data",
		"tls.handshake.type", "tls.handshake.extensions_server_name", "tls.handshake.extensions_alpn_str", "tls.handshake.ja4", "quic.ack.largest_acknowledged",
		"quic.padding_length", "quic.spin_bit", "quic.key_phase"}
	t.Run("keys", func(t *testing.T) {
		keylog.Default.SetFiles(kf)
		defer keylog.Default.SetFiles()
		t.Setenv("DIFFTEST_KEYLOG", kf)
		compare(t, file, "", fields)
		compareColumns(t, file)
	})
	t.Run("no-keys", func(t *testing.T) {
		compare(t, file, "", fields)
		compareColumns(t, file)
	})
}

func TestHTTP3(t *testing.T) {
	f := g.DefaultFlow()
	f.B.Port = 443
	q := g.NewQUICConn(t, f, "h3.example", "h3")
	q.HTTP3Exchange("/pic.jpg", "image/jpeg", make([]byte, 600))
	kf := filepath.Join(t.TempDir(), "keys.log")
	os.WriteFile(kf, q.Keylog.Bytes(), 0o600)
	keylog.Default.SetFiles(kf)
	defer keylog.Default.SetFiles()
	t.Setenv("DIFFTEST_KEYLOG", kf)
	file := write(t, q.Packets)
	compare(t, file, "", []string{"quic.stream.stream_id", "quic.stream.fin", "quic.stream.offset", "http3.frame_type", "http3.frame_length", "http3.stream_uni_type",
		"http3.headers.method", "http3.headers.path", "http3.headers.authority", "http3.headers.scheme", "http3.headers.status", "http3.headers.content_type",
		"http3.header.header.name", "http3.headers.header.value", "http3.headers.count", "http3.request.full_uri", "http3.settings.id", "http3.settings.value",
		"http3.settings.qpack.max_table_capacity", "http3.settings.qpack.blocked_streams", "http3.data"})
	compareColumns(t, file)
}
