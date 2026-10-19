package proto

import (
	"fmt"
	"net/netip"
	"strings"

	d "github.com/poseydon/lazysniffer/internal/dissect"
)

var (
	dhcpMsgTypes = map[uint64]string{1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"}
	dhcpOps      = map[uint64]string{1: "Boot Request", 2: "Boot Reply"}

	protoDHCP     = d.RegisterProto("Dynamic Host Configuration Protocol", "DHCP", "dhcp")
	hfDHCPOp      = protoDHCP.Field("dhcp.type", "Message type", d.FtUint8, d.WithVS(dhcpOps))
	hfDHCPHW      = protoDHCP.Field("dhcp.hw.type", "Hardware type", d.FtUint8, d.WithBase(d.BaseHex))
	hfDHCPHWLen   = protoDHCP.Field("dhcp.hw.len", "Hardware address length", d.FtUint8)
	hfDHCPHops    = protoDHCP.Field("dhcp.hops", "Hops", d.FtUint8)
	hfDHCPID      = protoDHCP.Field("dhcp.id", "Transaction ID", d.FtUint32, d.WithBase(d.BaseHex))
	hfDHCPSecs    = protoDHCP.Field("dhcp.secs", "Seconds elapsed", d.FtUint16)
	hfDHCPFlags   = protoDHCP.Field("dhcp.flags", "Bootp flags", d.FtUint16, d.WithBase(d.BaseHex))
	hfDHCPBcast   = protoDHCP.Field("dhcp.flags.bc", "Broadcast flag", d.FtBool, d.WithMask(0x8000), d.WithParentBits(16))
	hfDHCPCiaddr  = protoDHCP.Field("dhcp.ip.client", "Client IP address", d.FtIPv4)
	hfDHCPYiaddr  = protoDHCP.Field("dhcp.ip.your", "Your (client) IP address", d.FtIPv4)
	hfDHCPSiaddr  = protoDHCP.Field("dhcp.ip.server", "Next server IP address", d.FtIPv4)
	hfDHCPGiaddr  = protoDHCP.Field("dhcp.ip.relay", "Relay agent IP address", d.FtIPv4)
	hfDHCPMAC     = protoDHCP.Field("dhcp.hw.mac_addr", "Client MAC address", d.FtEther)
	hfDHCPServer  = protoDHCP.Field("dhcp.server", "Server host name", d.FtString)
	hfDHCPFile    = protoDHCP.Field("dhcp.file", "Boot file name", d.FtString)
	hfDHCPCookie  = protoDHCP.Field("dhcp.cookie", "Magic cookie", d.FtIPv4)
	hfDHCPOption  = protoDHCP.Field("dhcp.option", "Option", d.FtNone)
	hfDHCPOptCode = protoDHCP.Field("dhcp.option.type", "Option", d.FtUint8)
	hfDHCPOptLen  = protoDHCP.Field("dhcp.option.length", "Length", d.FtUint8)
	hfDHCPMsgType = protoDHCP.Field("dhcp.option.dhcp", "DHCP", d.FtUint8, d.WithVS(dhcpMsgTypes))
	hfDHCPMask    = protoDHCP.Field("dhcp.option.subnet_mask", "Subnet Mask", d.FtIPv4)
	hfDHCPRouter  = protoDHCP.Field("dhcp.option.router", "Router", d.FtIPv4)
	hfDHCPDNS     = protoDHCP.Field("dhcp.option.domain_name_server", "Domain Name Server", d.FtIPv4)
	hfDHCPHost    = protoDHCP.Field("dhcp.option.hostname", "Host Name", d.FtString)
	hfDHCPDomain  = protoDHCP.Field("dhcp.option.domain_name", "Domain Name", d.FtString)
	hfDHCPReqIP   = protoDHCP.Field("dhcp.option.requested_ip_address", "Requested IP Address", d.FtIPv4)
	hfDHCPLease   = protoDHCP.Field("dhcp.option.ip_address_lease_time", "IP Address Lease Time", d.FtUint32)
	hfDHCPSrvID   = protoDHCP.Field("dhcp.option.dhcp_server_id", "DHCP Server Identifier", d.FtIPv4)
	hfDHCPVendor  = protoDHCP.Field("dhcp.option.vendor_class_id", "Vendor class identifier", d.FtString)
	hfDHCPClient  = protoDHCP.Field("dhcp.option.client_id", "Client identifier", d.FtBytes)
	hfDHCPParams  = protoDHCP.Field("dhcp.option.request_list_item", "Parameter Request List Item", d.FtUint8)
	hfDHCPMessage = protoDHCP.Field("dhcp.option.message", "Message", d.FtString)
	hfDHCPNTP     = protoDHCP.Field("dhcp.option.ntp_server", "NTP Server", d.FtIPv4)
	hfDHCPData    = protoDHCP.Field("dhcp.option.value", "Value", d.FtBytes)
	dhcpHandle    = d.RegisterHandle("dhcp", d.NewHandle(protoDHCP, dissectDHCP))

	dhcpOptNames = map[uint8]string{1: "Subnet Mask", 3: "Router", 6: "Domain Name Server", 12: "Host Name", 15: "Domain Name",
		28: "Broadcast Address", 42: "NTP Servers", 43: "Vendor-Specific Information", 50: "Requested IP Address",
		51: "IP Address Lease Time", 53: "DHCP Message Type", 54: "DHCP Server Identifier", 55: "Parameter Request List",
		56: "Message", 57: "Maximum DHCP Message Size", 58: "Renewal Time Value", 59: "Rebinding Time Value",
		60: "Vendor class identifier", 61: "Client identifier", 66: "TFTP Server Name", 67: "Bootfile name", 82: "Relay Agent Information",
		119: "Domain Search", 121: "Classless Static Route", 252: "Web Proxy Auto-Discovery", 255: "End", 0: "Pad"}
)

func init() {
	UDPPortTable.Add(67, dhcpHandle)
	UDPPortTable.Add(68, dhcpHandle)
}

func dissectDHCP(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	if tvb.Len() < 240 {
		return 0
	}
	dt := tree.AddProtocol(protoDHCP, tvb, 0, -1)
	pi.SetProtocol("DHCP")
	_, op := dt.AddUint(hfDHCPOp, tvb, 0, 1)
	dt.AddUint(hfDHCPHW, tvb, 1, 1)
	_, hl := dt.AddUint(hfDHCPHWLen, tvb, 2, 1)
	dt.AddUint(hfDHCPHops, tvb, 3, 1)
	_, xid := dt.AddUint(hfDHCPID, tvb, 4, 4)
	dt.AddUint(hfDHCPSecs, tvb, 8, 2)
	fn, _ := dt.AddUint(hfDHCPFlags, tvb, 10, 2)
	fn.AddBits(hfDHCPBcast, tvb, 10, 2, uint64(tvb.U16(10)))
	dt.AddIPv4(hfDHCPCiaddr, tvb, 12)
	dt.AddIPv4(hfDHCPYiaddr, tvb, 16)
	dt.AddIPv4(hfDHCPSiaddr, tvb, 20)
	dt.AddIPv4(hfDHCPGiaddr, tvb, 24)
	if hl == 6 {
		dt.AddBytes(hfDHCPMAC, tvb, 28, 6)
	}
	if s, n := tvb.Stringz(44, 64); n > 1 {
		dt.AddString(hfDHCPServer, tvb, 44, 64)
		_ = s
	}
	if s, n := tvb.Stringz(108, 128); n > 1 {
		dt.AddString(hfDHCPFile, tvb, 108, 128)
		_ = s
	}
	dt.AddIPv4(hfDHCPCookie, tvb, 236)
	msg := ""
	for off := 240; off < tvb.Len(); {
		code := tvb.U8(off)
		if code == 0 {
			off++
			continue
		}
		if code == 255 {
			dt.AddText(tvb, off, 1, "Option: (255) End")
			break
		}
		l := int(tvb.U8(off + 1))
		on := dt.AddText(tvb, off, 2+l, "Option: (%d) %s", code, orDefault(dhcpOptNames[code], "Unknown"))
		on.AddUint(hfDHCPOptCode, tvb, off, 1)
		on.AddUint(hfDHCPOptLen, tvb, off+1, 1)
		v := off + 2
		switch code {
		case 53:
			_, t := on.AddUint(hfDHCPMsgType, tvb, v, 1)
			msg = dhcpMsgTypes[t]
			on.SetText("Option: (53) DHCP Message Type (%s)", msg)
		case 1:
			on.AddIPv4(hfDHCPMask, tvb, v)
		case 3, 6, 42, 54, 50:
			f := map[uint8]*d.FieldDef{3: hfDHCPRouter, 6: hfDHCPDNS, 42: hfDHCPNTP, 54: hfDHCPSrvID, 50: hfDHCPReqIP}[code]
			for i := 0; i+4 <= l; i += 4 {
				on.AddIPv4(f, tvb, v+i)
			}
		case 12:
			on.AddString(hfDHCPHost, tvb, v, l)
		case 15:
			on.AddString(hfDHCPDomain, tvb, v, l)
		case 51:
			on.AddUint(hfDHCPLease, tvb, v, 4)
		case 56:
			on.AddString(hfDHCPMessage, tvb, v, l)
		case 60:
			on.AddString(hfDHCPVendor, tvb, v, l)
		case 61:
			on.AddBytes(hfDHCPClient, tvb, v, l)
		case 55:
			for i := 0; i < l; i++ {
				on.AddUint(hfDHCPParams, tvb, v+i, 1)
			}
		default:
			if l > 0 {
				on.AddBytes(hfDHCPData, tvb, v, l)
			}
		}
		off += 2 + l
	}
	if msg == "" {
		msg = orDefault(dhcpOps[op], "BOOTP")
	}
	pi.SetInfo(fmt.Sprintf("DHCP %s - Transaction ID 0x%x", msg, xid))
	return tvb.Len()
}

// ---- NTP ----

var (
	ntpModes = map[uint64]string{0: "reserved", 1: "symmetric active", 2: "symmetric passive", 3: "client", 4: "server", 5: "broadcast", 6: "control", 7: "private"}

	protoNTP   = d.RegisterProto("Network Time Protocol", "NTP", "ntp")
	hfNTPFlags = protoNTP.Field("ntp.flags", "Flags", d.FtUint8, d.WithBase(d.BaseHex))
	hfNTPLI    = protoNTP.Field("ntp.flags.li", "Leap Indicator", d.FtUint8, d.WithMask(0xc0), d.WithParentBits(8))
	hfNTPVN    = protoNTP.Field("ntp.flags.vn", "Version number", d.FtUint8, d.WithMask(0x38), d.WithParentBits(8))
	hfNTPMode  = protoNTP.Field("ntp.flags.mode", "Mode", d.FtUint8, d.WithMask(0x07), d.WithParentBits(8), d.WithVS(ntpModes))
	hfNTPStrat = protoNTP.Field("ntp.stratum", "Peer Clock Stratum", d.FtUint8)
	hfNTPPoll  = protoNTP.Field("ntp.ppoll", "Peer Polling Interval", d.FtUint8)
	hfNTPPrec  = protoNTP.Field("ntp.precision", "Peer Clock Precision", d.FtInt8)
	hfNTPDelay = protoNTP.Field("ntp.rootdelay", "Root Delay", d.FtUint32)
	hfNTPDisp  = protoNTP.Field("ntp.rootdispersion", "Root Dispersion", d.FtUint32)
	hfNTPRefID = protoNTP.Field("ntp.refid", "Reference ID", d.FtBytes)
	hfNTPRef   = protoNTP.Field("ntp.reftime", "Reference Timestamp", d.FtAbsTime)
	hfNTPOrig  = protoNTP.Field("ntp.org", "Origin Timestamp", d.FtAbsTime)
	hfNTPRec   = protoNTP.Field("ntp.rec", "Receive Timestamp", d.FtAbsTime)
	hfNTPXmt   = protoNTP.Field("ntp.xmt", "Transmit Timestamp", d.FtAbsTime)
	ntpHandle  = d.RegisterHandle("ntp", d.NewHandle(protoNTP, dissectNTP))
)

func init() { UDPPortTable.Add(123, ntpHandle) }

func ntpTime(t *d.Tvb, off int) (int64, bool) {
	sec, frac := uint64(t.U32(off)), uint64(t.U32(off+4))
	if sec == 0 && frac == 0 {
		return 0, false
	}
	// NTP era 0 starts 1900-01-01; the Unix epoch is 2208988800 s later.
	return (int64(sec)-2208988800)*1e9 + int64(frac*1e9>>32), true
}

func dissectNTP(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	if tvb.Len() < 48 {
		return 0
	}
	nt := tree.AddProtocol(protoNTP, tvb, 0, -1)
	pi.SetProtocol("NTP")
	fn, _ := nt.AddUint(hfNTPFlags, tvb, 0, 1)
	b := uint64(tvb.U8(0))
	fn.AddBits(hfNTPLI, tvb, 0, 1, b)
	fn.AddBits(hfNTPVN, tvb, 0, 1, b)
	fn.AddBits(hfNTPMode, tvb, 0, 1, b)
	nt.AddUint(hfNTPStrat, tvb, 1, 1)
	nt.AddUint(hfNTPPoll, tvb, 2, 1)
	nt.AddValue(hfNTPPrec, tvb, 3, 1, d.IntValue(d.FtInt8, int64(int8(tvb.U8(3)))))
	nt.AddUint(hfNTPDelay, tvb, 4, 4)
	nt.AddUint(hfNTPDisp, tvb, 8, 4)
	nt.AddBytes(hfNTPRefID, tvb, 12, 4)
	for i, f := range []*d.FieldDef{hfNTPRef, hfNTPOrig, hfNTPRec, hfNTPXmt} {
		if ns, ok := ntpTime(tvb, 16+8*i); ok {
			nt.AddValue(f, tvb, 16+8*i, 8, d.TimeValue(ns))
		}
	}
	mode := b & 7
	pi.SetInfo(fmt.Sprintf("NTP Version %d, %s", (b>>3)&7, ntpModes[mode]))
	return tvb.Len()
}

// ---- Syslog ----

var (
	syslogSev = []string{"Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug"}
	syslogFac = []string{"kernel", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv", "ftp",
		"ntp", "security", "console", "clock", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"}

	protoSyslog  = d.RegisterProto("Syslog message", "Syslog", "syslog")
	hfSysPri     = protoSyslog.Field("syslog.pri", "Priority", d.FtUint8)
	hfSysFac     = protoSyslog.Field("syslog.facility", "Facility", d.FtUint8, d.WithVS(vsFromSlice(syslogFac)))
	hfSysLevel   = protoSyslog.Field("syslog.level", "Level", d.FtUint8, d.WithVS(vsFromSlice(syslogSev)))
	hfSysMsg     = protoSyslog.Field("syslog.msg", "Message", d.FtString)
	hfSysVer     = protoSyslog.Field("syslog.version", "Syslog version", d.FtUint8)
	hfSysHost    = protoSyslog.Field("syslog.hostname", "Hostname", d.FtString)
	hfSysApp     = protoSyslog.Field("syslog.appname", "Appname", d.FtString)
	hfSysTS      = protoSyslog.Field("syslog.timestamp_rfc3164", "Timestamp", d.FtString)
	hfSysProc    = protoSyslog.Field("syslog.procid", "Process ID", d.FtString)
	syslogHandle = d.RegisterHandle("syslog", d.NewHandle(protoSyslog, dissectSyslog))
)

var syslogFacShort = []string{"KERN", "USER", "MAIL", "DAEMON", "AUTH", "SYSLOG", "LPR", "NEWS", "UUCP", "CRON", "AUTHPRIV", "FTP", "NTP", "LOGAUDIT", "LOGALERT", "CLOCK",
	"LOCAL0", "LOCAL1", "LOCAL2", "LOCAL3", "LOCAL4", "LOCAL5", "LOCAL6", "LOCAL7"}
var syslogSevShort = []string{"EMERG", "ALERT", "CRIT", "ERR", "WARNING", "NOTICE", "INFO", "DEBUG"}

func vsFromSlice(s []string) map[uint64]string {
	m := make(map[uint64]string, len(s))
	for i, v := range s {
		m[uint64(i)] = v
	}
	return m
}

func init() {
	UDPPortTable.Add(514, syslogHandle)
	TCPPortTable.Add(514, syslogHandle)
}

func dissectSyslog(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	raw := string(tvb.Raw())
	if len(raw) < 3 || raw[0] != '<' {
		return 0
	}
	end := strings.IndexByte(raw, '>')
	if end < 2 || end > 5 {
		return 0
	}
	var pri int
	if _, err := fmt.Sscanf(raw[1:end], "%d", &pri); err != nil || pri > 191 {
		return 0
	}
	st := tree.AddProtocol(protoSyslog, tvb, 0, -1)
	pi.SetProtocol("Syslog")
	pn := st.AddText(tvb, 0, end+1, "Priority: %d", pri)
	pn.AddValue(hfSysPri, nil, 0, 0, d.UintValue(d.FtUint8, uint64(pri)))
	pn.AddValue(hfSysFac, tvb, 0, end+1, d.UintValue(d.FtUint8, uint64(pri>>3)))
	pn.AddValue(hfSysLevel, tvb, 0, end+1, d.UintValue(d.FtUint8, uint64(pri&7)))
	rest := raw[end+1:]
	msgOff := end + 1
	switch {
	case len(rest) > 0 && rest[0] >= '1' && rest[0] <= '9' && strings.HasPrefix(rest[1:], " "):
		// RFC 5424: VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
		f := strings.SplitN(rest, " ", 8)
		if len(f) >= 7 {
			st.AddValue(hfSysVer, tvb, msgOff, 1, d.StringValue(f[0]))
			st.AddValue(hfSysHost, tvb, msgOff, 0, d.StringValue(f[2]))
			st.AddValue(hfSysApp, tvb, msgOff, 0, d.StringValue(f[3]))
			msgOff = len(raw) - len(f[len(f)-1])
			if len(f) < 8 {
				msgOff = len(raw)
			}
		}
	case len(rest) >= 16 && rest[3] == ' ' && rest[6] == ' ' && rest[9] == ':' && rest[12] == ':':
		// RFC 3164: "Mmm dd hh:mm:ss host tag[pid]: msg"
		st.AddValue(hfSysTS, tvb, msgOff, 15, d.StringValue(rest[:15]))
		tail := rest[16:]
		if sp := strings.IndexByte(tail, ' '); sp > 0 {
			st.AddValue(hfSysHost, tvb, msgOff+16, sp, d.StringValue(tail[:sp]))
			after := tail[sp+1:]
			msgOff += 16 + sp + 1
			if c := strings.Index(after, ": "); c > 0 && !strings.ContainsAny(after[:c], " ") {
				tag := after[:c]
				if b := strings.IndexByte(tag, '['); b > 0 && strings.HasSuffix(tag, "]") {
					st.AddValue(hfSysProc, tvb, msgOff+b+1, len(tag)-b-2, d.StringValue(tag[b+1:len(tag)-1]))
					tag = tag[:b]
				}
				st.AddValue(hfSysApp, tvb, msgOff, len(tag), d.StringValue(tag))
				msgOff += c + 2
			}
		}
	}
	msg := raw[msgOff:]
	st.AddString(hfSysMsg, tvb, msgOff, len(msg))
	pi.SetInfo(fmt.Sprintf("%s.%s: %s", syslogFacShort[min(pri>>3, len(syslogFacShort)-1)], syslogSevShort[pri&7], strings.TrimSpace(raw[end+1:])))
	return tvb.Len()
}

var _ = netip.Addr{}
