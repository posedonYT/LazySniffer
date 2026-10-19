package pktgen

import (
	"bytes"
	"encoding/binary"
	"strconv"
)

func UDPPacket(f Flow, sport, dport uint16, payload []byte) Packet {
	f.A.Port, f.B.Port = sport, dport
	return Packet{TS: 1e9, Data: UDP(f, payload)}
}

func nameList(s string) []byte {
	b := make([]byte, 4, 4+len(s))
	binary.BigEndian.PutUint32(b, uint32(len(s)))
	return append(b, s...)
}

func sshKexInit(kex string) []byte {
	var p bytes.Buffer
	p.WriteByte(20)
	p.Write(make([]byte, 16))
	for _, l := range []string{kex, "ssh-ed25519", "aes128-ctr", "aes128-ctr", "hmac-sha2-256", "hmac-sha2-256", "none", "none", "", ""} {
		p.Write(nameList(l))
	}
	p.WriteByte(0)
	p.Write(make([]byte, 4))
	pad := 8 - (p.Len()+5)%8
	if pad < 4 {
		pad += 8
	}
	out := make([]byte, 5)
	binary.BigEndian.PutUint32(out, uint32(p.Len()+1+pad))
	out[4] = byte(pad)
	out = append(out, p.Bytes()...)
	return append(out, make([]byte, pad)...)
}

// SampleServices has one packet or flow of DHCP, NTP, syslog, STUN, WireGuard, IKE, ESP, OpenVPN and SSH.
func SampleServices() []Packet {
	f := DefaultFlow()
	// DHCP discover
	dh := make([]byte, 240)
	dh[0], dh[1], dh[2] = 1, 1, 6
	binary.BigEndian.PutUint32(dh[4:], 0xdeadbeef)
	copy(dh[28:], []byte{0xaa, 0xbb, 0xcc, 0, 0, 1})
	binary.BigEndian.PutUint32(dh[236:], 0x63825363)
	dh = append(dh, 53, 1, 1, 12, 4, 'h', 'o', 's', 't', 50, 4, 10, 0, 0, 77, 255)
	// NTP client
	ntp := make([]byte, 48)
	ntp[0] = 0x23
	// syslog
	sys := []byte("<34>Oct 11 22:14:15 host su: 'su root' failed")
	// STUN binding request + response with XOR-MAPPED-ADDRESS
	stun := []byte{0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	stunResp := append([]byte{1, 1, 0, 12, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		0, 0x20, 0, 8, 0, 1, 0x21^0x12, 0x12^0x34, 0xc0^0x21, 0xa8^0x12, 1^0xa4, 2^0x42)
	// WireGuard initiation
	wg := make([]byte, 148)
	wg[0] = 1
	// IKEv2 IKE_SA_INIT
	ike := make([]byte, 28)
	copy(ike, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	ike[17], ike[18], ike[19] = 0x20, 34, 8
	binary.BigEndian.PutUint32(ike[24:], 28)
	// ESP
	esp := append([]byte{0, 0, 0x12, 0x34, 0, 0, 0, 1}, make([]byte, 32)...)
	// OpenVPN hard reset client v2
	ov := append([]byte{7 << 3}, make([]byte, 8)...)
	ov = append(ov, 0, 0, 0, 0, 0)

	tcp := NewTCPConv(func() Flow { x := f; x.B.Port = 22; return x }(), 2e9)
	tcp.Send(0, []byte("SSH-2.0-OpenSSH_9.6\r\n"))
	tcp.Send(1, []byte("SSH-2.0-dropbear\r\n"))
	tcp.Send(0, sshKexInit("curve25519-sha256,diffie-hellman-group14-sha256"))

	pkts := []Packet{
		UDPPacket(f, 68, 67, dh), UDPPacket(f, 40000, 123, ntp), UDPPacket(f, 40000, 514, sys),
		UDPPacket(f, 40000, 3478, stun), UDPPacket(f, 3478, 40000, stunResp), UDPPacket(f, 40000, 51820, wg),
		UDPPacket(f, 500, 500, ike), UDPPacket(f, 40000, 4500, esp), UDPPacket(f, 40000, 1194, ov),
	}
	for i := range pkts {
		pkts[i].TS = int64(i+1) * 1e6
	}
	pkts = append(pkts, tcp.Pkts...)
	return pkts
}

// SampleTextProtocols has FTP (with a data connection), POP3, IMAP, SMTP, Telnet and SOCKS5 sessions.
func SampleTextProtocols() []Packet {
	f := DefaultFlow()
	var pkts []Packet
	conv := func(port uint16, sport uint16, ts int64, fn func(c *TCPConv)) {
		x := f
		x.B.Port, x.A.Port = port, sport
		c := NewTCPConv(x, ts)
		fn(c)
		c.Close()
		pkts = append(pkts, c.Pkts...)
	}
	conv(21, 40001, 1e9, func(c *TCPConv) {
		c.Send(1, []byte("220 Welcome\r\n"))
		c.Send(0, []byte("USER anonymous\r\n"))
		c.Send(1, []byte("331 Password required\r\n"))
		c.Send(0, []byte("PASS secret\r\n"))
		c.Send(1, []byte("230 Logged in\r\n"))
		c.Send(0, []byte("PASV\r\n"))
		c.Send(1, []byte("227 Entering Passive Mode (10,0,0,2,200,10)\r\n"))
		c.Send(0, []byte("RETR a.txt\r\n"))
	})
	conv(51210, 40002, 2e9, func(c *TCPConv) { c.Send(1, []byte("file contents here")) })
	conv(110, 40003, 3e9, func(c *TCPConv) {
		c.Send(1, []byte("+OK POP3 ready\r\n"))
		c.Send(0, []byte("USER bob\r\n"))
		c.Send(1, []byte("+OK\r\n"))
	})
	conv(143, 40004, 4e9, func(c *TCPConv) {
		c.Send(1, []byte("* OK IMAP ready\r\n"))
		c.Send(0, []byte("a1 LOGIN bob pw\r\n"))
		c.Send(1, []byte("a1 OK done\r\n"))
	})
	conv(25, 40005, 5e9, func(c *TCPConv) {
		c.Send(1, []byte("220 mail ESMTP\r\n"))
		c.Send(0, []byte("EHLO me\r\nMAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\nDATA\r\n"))
		c.Send(1, []byte("354 go ahead\r\n"))
		c.Send(0, []byte("Subject: hi\r\n\r\nbody\r\n.\r\n"))
	})
	conv(23, 40006, 6e9, func(c *TCPConv) {
		c.Send(1, []byte{255, 253, 1, 255, 251, 3})
		c.Send(0, []byte("ls\r\n"))
	})
	conv(1080, 40007, 7e9, func(c *TCPConv) {
		c.Send(0, []byte{5, 1, 0})
		c.Send(1, []byte{5, 0})
		c.Send(0, []byte{5, 1, 0, 3, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 1, 0xbb})
	})
	return pkts
}

// SampleDatabases has Redis, PostgreSQL, MySQL, MQTT, SNMP and LLDP traffic.
func SampleDatabases() []Packet {
	f := DefaultFlow()
	var pkts []Packet
	conv := func(port, sport uint16, ts int64, fn func(c *TCPConv)) {
		x := f
		x.B.Port, x.A.Port = port, sport
		c := NewTCPConv(x, ts)
		fn(c)
		pkts = append(pkts, c.Pkts...)
	}
	conv(6379, 40010, 1e9, func(c *TCPConv) {
		c.Send(0, []byte("*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n"))
		c.Send(1, []byte("+OK\r\n"))
	})
	var startup bytes.Buffer
	startup.Write([]byte{0, 0, 0, 0, 0, 3, 0, 0})
	startup.WriteString("user\x00alice\x00database\x00shop\x00\x00")
	sb := startup.Bytes()
	binary.BigEndian.PutUint32(sb, uint32(len(sb)))
	q := append([]byte{'Q', 0, 0, 0, 0}, "SELECT 1\x00"...)
	binary.BigEndian.PutUint32(q[1:], uint32(len(q)-1))
	conv(5432, 40011, 2e9, func(c *TCPConv) {
		c.Send(0, sb)
		c.Send(1, []byte{'R', 0, 0, 0, 8, 0, 0, 0, 0})
		c.Send(0, q)
	})
	greet := append([]byte{0, 0, 0, 0}, 10)
	greet = append(greet, "8.0.36\x00"...)
	greet = append(greet, 1, 0, 0, 0)
	greet = append(greet, make([]byte, 20)...)
	greet[0] = byte(len(greet) - 4)
	query := append([]byte{0, 0, 0, 0, 3}, "select now()"...)
	query[0] = byte(len(query) - 4)
	conv(3306, 40012, 3e9, func(c *TCPConv) {
		c.Send(1, greet)
		c.Send(0, query[:0])
	})
	conv(3306, 40013, 3.5e9, func(c *TCPConv) {
		c.Send(1, greet)
		login := append([]byte{0, 0, 0, 1}, make([]byte, 32)...)
		login[4], login[5] = 0x05, 0x02 // capabilities: CLIENT_PROTOCOL_41
		login = append(login, "root\x00"...)
		login[0] = byte(len(login) - 4)
		c.Send(0, login)
		c.Send(0, query)
	})
	conn := append([]byte{0x10, 0, 0, 4}, "MQTT"...)
	conn = append(conn, 4, 0x02, 0, 60, 0, 3, 'c', 'i', 'd')
	conn[1] = byte(len(conn) - 2)
	pub := []byte{0x30, 0, 0, 5}
	pub = append(pub, "a/bhello"...)
	pub[1] = byte(len(pub) - 2)
	pub[3] = 3
	pub[2] = 0
	pub = append(pub[:4], "a/b"...)
	pub = append(pub, "hello"...)
	pub[1] = byte(len(pub) - 2)
	conv(1883, 40014, 4e9, func(c *TCPConv) {
		c.Send(0, conn)
		c.Send(0, pub)
	})
	snmp := []byte{0x30, 0x29, 2, 1, 0, 4, 6, 'p', 'u', 'b', 'l', 'i', 'c', 0xa0, 0x1c, 2, 4, 0, 0, 0, 1, 2, 1, 0, 2, 1, 0, 0x30, 0x0e, 0x30, 0x0c, 6, 8, 0x2b, 6, 1, 2, 1, 1, 1, 0, 5, 0}
	pkts = append(pkts, UDPPacket(f, 40020, 161, snmp))
	pkts[len(pkts)-1].TS = 9e9
	lldp := []byte{0x02, 0x07, 4, 0xaa, 0xbb, 0xcc, 0, 0, 1, 0x04, 0x04, 5, 'g', 'i', '0', 0x06, 0x02, 0, 120, 0x0a, 0x03, 's', 'w', '1', 0, 0}
	pkts = append(pkts, Packet{TS: 10e9, Data: Ether([6]byte{1, 0x80, 0xc2, 0, 0, 0xe}, [6]byte{2, 0, 0, 0, 0, 9}, 0x88cc, lldp)})
	return pkts
}

// SampleVoIP is a SIP call (INVITE…BYE) with 50 RTP packets, three of them lost and one delayed.
func SampleVoIP() []Packet {
	f := DefaultFlow()
	sdp := func(ip string, port int) string {
		return "v=0\r\no=u 1 1 IN IP4 " + ip + "\r\ns=c\r\nc=IN IP4 " + ip + "\r\nt=0 0\r\nm=audio " + strconv.Itoa(port) + " RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
	}
	sip := func(first string, extra string, body string) []byte {
		h := first + "\r\nVia: SIP/2.0/UDP 10.0.0.1:5060\r\nFrom: <sip:alice@10.0.0.1>;tag=1\r\nTo: <sip:bob@10.0.0.2>\r\nCall-ID: abc@10.0.0.1\r\n" + extra
		if body != "" {
			h += "Content-Type: application/sdp\r\n"
		}
		return []byte(h + "Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body)
	}
	var pk []Packet
	ts := int64(1e9)
	add := func(p Packet) { ts += 10e6; p.TS = ts; pk = append(pk, p) }
	add(UDPPacket(f, 5060, 5060, sip("INVITE sip:bob@10.0.0.2 SIP/2.0", "CSeq: 1 INVITE\r\n", sdp("10.0.0.1", 20000))))
	add(UDPPacket(f.Rev(), 5060, 5060, sip("SIP/2.0 180 Ringing", "CSeq: 1 INVITE\r\n", "")))
	add(UDPPacket(f.Rev(), 5060, 5060, sip("SIP/2.0 200 OK", "CSeq: 1 INVITE\r\n", sdp("10.0.0.2", 30000))))
	add(UDPPacket(f, 5060, 5060, sip("ACK sip:bob@10.0.0.2 SIP/2.0", "CSeq: 1 ACK\r\n", "")))
	seq := uint16(100)
	rtpTS := uint32(160000)
	for i := 0; i < 50; i++ {
		if i >= 10 && i < 13 {
			seq++
			rtpTS += 160
			ts += 20e6
			continue // three packets lost
		}
		p := make([]byte, 12+160)
		p[0], p[1] = 0x80, 0
		binary.BigEndian.PutUint16(p[2:], seq)
		binary.BigEndian.PutUint32(p[4:], rtpTS)
		binary.BigEndian.PutUint32(p[8:], 0x11223344)
		ts += 20e6
		if i == 30 {
			ts += 15e6 // network delay: jitter
		}
		pk = append(pk, Packet{TS: ts, Data: UDPPacket(f, 20000, 30000, p).Data})
		seq++
		rtpTS += 160
	}
	ts += 100e6
	add(UDPPacket(f, 5060, 5060, sip("BYE sip:bob@10.0.0.2 SIP/2.0", "CSeq: 2 BYE\r\n", "")))
	add(UDPPacket(f.Rev(), 5060, 5060, sip("SIP/2.0 200 OK", "CSeq: 2 BYE\r\n", "")))
	return pk
}

func wlanRadiotap() []byte {
	// version 0, pad 0, length 14, present: flags | rate | channel | dbm_antsignal
	b := []byte{0, 0, 14, 0, 0x2e, 0, 0, 0}
	b = append(b, 0x00)       // flags
	b = append(b, 12)         // rate 6 Mb/s
	b = append(b, 0x6c, 0x09) // 2412 MHz
	b = append(b, 0xa0, 0x00) // channel flags
	b = append(b, 0xc4)       // -60 dBm
	return b[:15]
}

func wlanMgmt(subtype byte, da, sa, bssid [6]byte, seq uint16, body []byte) []byte {
	f := []byte{subtype << 4, 0, 0x3a, 0x01}
	f = append(f, da[:]...)
	f = append(f, sa[:]...)
	f = append(f, bssid[:]...)
	f = append(f, byte(seq<<4), byte(seq>>4))
	return append(f, body...)
}

func wlanTag(id byte, data ...byte) []byte { return append([]byte{id, byte(len(data))}, data...) }

// SampleWLAN has radiotap-wrapped 802.11 beacons, probe requests, authentication, control and data frames.
func SampleWLAN() []Packet {
	ap := [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	sta := [6]byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	bc := [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	rt := wlanRadiotap()
	rt[2] = byte(len(rt))
	var pk []Packet
	add := func(b []byte) {
		pk = append(pk, Packet{TS: int64(len(pk)+1) * 1e6, Data: append(append([]byte(nil), rt...), b...)})
	}
	// Beacon
	body := make([]byte, 12)
	binary.LittleEndian.PutUint64(body, 123456789)
	binary.LittleEndian.PutUint16(body[8:], 100)
	binary.LittleEndian.PutUint16(body[10:], 0x0431)
	body = append(body, wlanTag(0, []byte("lazynet")...)...)
	body = append(body, wlanTag(1, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24)...)
	body = append(body, wlanTag(3, 6)...)
	add(wlanMgmt(8, bc, ap, ap, 1234, body))
	// Probe request (wildcard SSID)
	add(wlanMgmt(4, bc, sta, bc, 77, append(wlanTag(0), wlanTag(1, 0x82, 0x84)...)))
	// Authentication open system seq 1
	add(wlanMgmt(11, ap, sta, ap, 78, []byte{0, 0, 1, 0, 0, 0}))
	// Deauthentication reason 3
	add(wlanMgmt(12, sta, ap, ap, 79, []byte{3, 0}))
	// Acknowledgement and RTS control frames
	add(append([]byte{0xd4, 0x00, 0x00, 0x00}, sta[:]...))
	add(append(append([]byte{0xb4, 0x00, 0x9c, 0x00}, ap[:]...), sta[:]...))
	// QoS data frame to DS carrying LLC/SNAP IPv4 (not protected)
	llc := []byte{0xaa, 0xaa, 0x03, 0, 0, 0, 0x08, 0x00}
	ip := IPv4(DefaultFlow().A.IP, DefaultFlow().B.IP, 17, 5, 0, false, 64, []byte{0x13, 0x88, 0x13, 0x89, 0, 9, 0, 0, 'x'})
	data := []byte{0x88, 0x01, 0x30, 0x00}
	data = append(data, ap[:]...)  // addr1 = BSSID (to DS)
	data = append(data, sta[:]...) // addr2 = SA
	data = append(data, ap[:]...)  // addr3 = DA
	data = append(data, 0x50, 0x01, 0x00, 0x00)
	data = append(append(data, llc...), ip...)
	add(data)
	return pk
}
