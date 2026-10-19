package proto

import (
	"fmt"
	"strings"

	d "github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/pcapio"
)

var wlanTypeNames = map[uint64]string{0: "Management frame", 1: "Control frame", 2: "Data frame", 3: "Extension frame"}

// wlanSubtypes maps (type<<4|subtype) to Wireshark's names.
var wlanSubtypes = map[uint64]string{
	0x00: "Association Request", 0x01: "Association Response", 0x02: "Reassociation Request", 0x03: "Reassociation Response",
	0x04: "Probe Request", 0x05: "Probe Response", 0x06: "Timing Advertisement", 0x08: "Beacon", 0x09: "ATIM", 0x0a: "Disassociation",
	0x0b: "Authentication", 0x0c: "Deauthentication", 0x0d: "Action", 0x0e: "Action No Ack",
	0x14: "Beamforming Report Poll", 0x15: "VHT NDP Announcement", 0x17: "Control Wrapper", 0x18: "802.11 Block Ack Request", 0x19: "802.11 Block Ack",
	0x1a: "PS-Poll", 0x1b: "Request-to-send", 0x1c: "Clear-to-send", 0x1d: "Acknowledgement", 0x1e: "CF-End", 0x1f: "CF-End + CF-Ack",
	0x20: "Data", 0x21: "Data + CF-Ack", 0x22: "Data + CF-Poll", 0x23: "Data + CF-Ack + CF-Poll", 0x24: "Null function (No data)",
	0x25: "Null function + CF-Ack", 0x26: "Null function + CF-Poll", 0x27: "Null function + CF-Ack + CF-Poll",
	0x28: "QoS Data", 0x29: "QoS Data + CF-Ack", 0x2a: "QoS Data + CF-Poll", 0x2b: "QoS Data + CF-Ack + CF-Poll",
	0x2c: "QoS Null function (No data)", 0x2e: "QoS CF-Poll (No data)", 0x2f: "QoS CF-Ack + CF-Poll (No data)",
}

var wlanTags = map[uint64]string{0: "SSID parameter set", 1: "Supported Rates", 3: "DS Parameter set", 4: "CF Parameter set", 5: "Traffic Indication Map (TIM)",
	6: "IBSS Parameter set", 7: "Country Information", 11: "QBSS Load Element", 32: "Power Constraint", 33: "Power Capability", 36: "Supported Channels",
	42: "ERP Information", 45: "HT Capabilities", 48: "RSN Information", 50: "Extended Supported Rates", 61: "HT Information (802.11n D1.10)",
	70: "RM Enabled Capabilities", 127: "Extended Capabilities", 191: "VHT Capabilities", 192: "VHT Operation", 221: "Vendor Specific", 255: "Element ID Extension"}

var (
	protoRadiotap  = d.RegisterProto("802.11 radiotap", "Radiotap", "radiotap")
	hfRTVersion    = protoRadiotap.Field("radiotap.version", "Header revision", d.FtUint8)
	hfRTPad        = protoRadiotap.Field("radiotap.pad", "Header pad", d.FtUint8)
	hfRTLength     = protoRadiotap.Field("radiotap.length", "Header length", d.FtUint16)
	hfRTPresent    = protoRadiotap.Field("radiotap.present", "Present flags", d.FtUint32, d.WithBase(d.BaseHex))
	hfRTTSFT       = protoRadiotap.Field("radiotap.mactime", "MAC timestamp", d.FtUint64)
	hfRTFlags      = protoRadiotap.Field("radiotap.flags", "Flags", d.FtUint8, d.WithBase(d.BaseHex))
	hfRTFCS        = protoRadiotap.Field("radiotap.flags.fcs", "FCS at end of frame", d.FtBool, d.WithMask(0x10), d.WithParentBits(8))
	hfRTRate       = protoRadiotap.Field("radiotap.datarate", "Data Rate", d.FtFloat)
	hfRTFreq       = protoRadiotap.Field("radiotap.channel.freq", "Channel frequency", d.FtUint16)
	hfRTChFlags    = protoRadiotap.Field("radiotap.channel.flags", "Channel type", d.FtUint16, d.WithBase(d.BaseHex))
	hfRTSignal     = protoRadiotap.Field("radiotap.dbm_antsignal", "SSI Signal", d.FtInt8)
	hfRTNoise      = protoRadiotap.Field("radiotap.dbm_antnoise", "SSI Noise", d.FtInt8)
	hfRTAntenna    = protoRadiotap.Field("radiotap.antenna", "Antenna", d.FtUint8)
	hfRTRxFlags    = protoRadiotap.Field("radiotap.rxflags", "RX flags", d.FtUint16, d.WithBase(d.BaseHex))
	radiotapHandle = d.RegisterHandle("radiotap", d.NewHandle(protoRadiotap, dissectRadiotap))

	protoWLAN    = d.RegisterProto("IEEE 802.11 wireless LAN", "IEEE 802.11", "wlan")
	hfWLFC       = protoWLAN.Field("wlan.fc", "Frame Control Field", d.FtUint16, d.WithBase(d.BaseHex))
	hfWLVersion  = protoWLAN.Field("wlan.fc.version", "Version", d.FtUint8, d.WithMask(0x03), d.WithParentBits(8))
	hfWLType     = protoWLAN.Field("wlan.fc.type", "Type", d.FtUint8, d.WithMask(0x0c), d.WithParentBits(8), d.WithVS(wlanTypeNames))
	hfWLSubtype  = protoWLAN.Field("wlan.fc.subtype", "Subtype", d.FtUint8, d.WithMask(0xf0), d.WithParentBits(8))
	hfWLTS       = protoWLAN.Field("wlan.fc.type_subtype", "Type/Subtype", d.FtUint8, d.WithVS(wlanSubtypes))
	hfWLFlags    = protoWLAN.Field("wlan.flags", "Flags", d.FtUint8, d.WithBase(d.BaseHex))
	hfWLDS       = protoWLAN.Field("wlan.fc.ds", "DS status", d.FtUint8, d.WithMask(0x03), d.WithParentBits(8), d.WithBase(d.BaseHex))
	hfWLToDS     = protoWLAN.Field("wlan.fc.tods", "To DS", d.FtBool, d.WithMask(0x01), d.WithParentBits(8))
	hfWLFromDS   = protoWLAN.Field("wlan.fc.fromds", "From DS", d.FtBool, d.WithMask(0x02), d.WithParentBits(8))
	hfWLMoreFrag = protoWLAN.Field("wlan.fc.frag", "More Fragments", d.FtBool, d.WithMask(0x04), d.WithParentBits(8))
	hfWLRetry    = protoWLAN.Field("wlan.fc.retry", "Retry", d.FtBool, d.WithMask(0x08), d.WithParentBits(8))
	hfWLPwr      = protoWLAN.Field("wlan.fc.pwrmgt", "PWR MGT", d.FtBool, d.WithMask(0x10), d.WithParentBits(8))
	hfWLMoreData = protoWLAN.Field("wlan.fc.moredata", "More Data", d.FtBool, d.WithMask(0x20), d.WithParentBits(8))
	hfWLProt     = protoWLAN.Field("wlan.fc.protected", "Protected flag", d.FtBool, d.WithMask(0x40), d.WithParentBits(8))
	hfWLOrder    = protoWLAN.Field("wlan.fc.order", "+HTC/Order flag", d.FtBool, d.WithMask(0x80), d.WithParentBits(8))
	hfWLDur      = protoWLAN.Field("wlan.duration", "Duration", d.FtUint16)
	hfWLRA       = protoWLAN.Field("wlan.ra", "Receiver address", d.FtEther)
	hfWLTA       = protoWLAN.Field("wlan.ta", "Transmitter address", d.FtEther)
	hfWLDA       = protoWLAN.Field("wlan.da", "Destination address", d.FtEther)
	hfWLSA       = protoWLAN.Field("wlan.sa", "Source address", d.FtEther)
	hfWLBSSID    = protoWLAN.Field("wlan.bssid", "BSS Id", d.FtEther)
	hfWLAddr     = protoWLAN.Field("wlan.addr", "Source or Destination address", d.FtEther)
	hfWLFrag     = protoWLAN.Field("wlan.frag", "Fragment number", d.FtUint16, d.WithMask(0x000f), d.WithParentBits(16))
	hfWLSeq      = protoWLAN.Field("wlan.seq", "Sequence number", d.FtUint16, d.WithMask(0xfff0), d.WithParentBits(16))
	hfWLQoS      = protoWLAN.Field("wlan.qos", "Qos Control", d.FtUint16, d.WithBase(d.BaseHex))
	hfWLQoSPrio  = protoWLAN.Field("wlan.qos.priority", "Priority", d.FtUint16, d.WithMask(0x0007), d.WithParentBits(16))
	hfWLFixedTS  = protoWLAN.Field("wlan.fixed.timestamp", "Timestamp", d.FtUint64)
	hfWLBI       = protoWLAN.Field("wlan.fixed.beacon", "Beacon Interval", d.FtUint16)
	hfWLCap      = protoWLAN.Field("wlan.fixed.capabilities", "Capabilities Information", d.FtUint16, d.WithBase(d.BaseHex))
	hfWLAuthAlg  = protoWLAN.Field("wlan.fixed.auth.alg", "Authentication Algorithm", d.FtUint16, d.WithVS(map[uint64]string{0: "Open System", 1: "Shared key", 3: "SAE"}))
	hfWLAuthSeq  = protoWLAN.Field("wlan.fixed.auth_seq", "Authentication SEQ", d.FtUint16, d.WithBase(d.BaseHex))
	hfWLStatus   = protoWLAN.Field("wlan.fixed.status_code", "Status code", d.FtUint16, d.WithVS(map[uint64]string{0: "Successful"}))
	hfWLReason   = protoWLAN.Field("wlan.fixed.reason_code", "Reason code", d.FtUint16)
	hfWLAID      = protoWLAN.Field("wlan.fixed.aid", "Association ID", d.FtUint16)
	hfWLListen   = protoWLAN.Field("wlan.fixed.listen_ival", "Listen Interval", d.FtUint16)
	hfWLTagNum   = protoWLAN.Field("wlan.tag.number", "Tag Number", d.FtUint8, d.WithVS(wlanTags))
	hfWLTagLen   = protoWLAN.Field("wlan.tag.length", "Tag length", d.FtUint8)
	hfWLSSID     = protoWLAN.Field("wlan.ssid", "SSID", d.FtBytes)
	hfWLRates    = protoWLAN.Field("wlan.supported_rates", "Supported Rates", d.FtUint8)
	hfWLChannel  = protoWLAN.Field("wlan.ds.current_channel", "Current Channel", d.FtUint8)
	hfWLCountry  = protoWLAN.Field("wlan.country_info.code", "Country Code", d.FtString)
	hfWLRSNVer   = protoWLAN.Field("wlan.rsn.version", "RSN Version", d.FtUint16)
	hfWLRSNGroup = protoWLAN.Field("wlan.rsn.gcs.type", "Group Cipher Suite type", d.FtUint8)
	hfWLRSNPair  = protoWLAN.Field("wlan.rsn.pcs.type", "Pairwise Cipher Suite type", d.FtUint8)
	hfWLRSNAKM   = protoWLAN.Field("wlan.rsn.akms.type", "AKM Suite type", d.FtUint8)
	hfWLTagData  = protoWLAN.Field("wlan.tag.data", "Tag data", d.FtBytes)
	hfWLCCMP     = protoWLAN.Field("wlan.ccmp.extiv", "CCMP Ext. Initialization Vector", d.FtBytes)
	hfWLFCS      = protoWLAN.Field("wlan.fcs", "Frame check sequence", d.FtUint32, d.WithBase(d.BaseHex))
	hfWLProtData = protoWLAN.Field("wlan.protected_data", "Protected Data", d.FtBytes)
	wlanHandle   = d.RegisterHandle("wlan", d.NewHandle(protoWLAN, dissectWLAN))
)

func init() {
	EncapTable.Add(uint64(pcapio.LinkIEEE80211Radiotap), radiotapHandle)
	EncapTable.Add(uint64(pcapio.LinkIEEE80211), wlanHandle)
}

// radiotap field alignment and size by bit number.
var rtFields = map[int][2]int{0: {8, 8}, 1: {1, 1}, 2: {1, 1}, 3: {2, 4}, 4: {2, 2}, 5: {1, 1}, 6: {1, 1}, 7: {2, 2}, 8: {2, 2}, 9: {2, 2}, 10: {1, 1}, 11: {1, 1},
	12: {1, 1}, 13: {1, 1}, 14: {2, 2}, 15: {2, 2}, 19: {1, 3}, 20: {4, 8}, 21: {2, 12}, 22: {8, 12}, 23: {2, 12}, 24: {2, 6}}

func dissectRadiotap(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	if tvb.Len() < 8 {
		return 0
	}
	rt := tree.AddProtocol(protoRadiotap, tvb, 0, -1)
	rt.AddUint(hfRTVersion, tvb, 0, 1)
	rt.AddUint(hfRTPad, tvb, 1, 1)
	_, hl := rt.AddUintLE(hfRTLength, tvb, 2, 2)
	if int(hl) > tvb.Len() || hl < 8 {
		return 0
	}
	rt.SetLen(int(hl))
	_, present := rt.AddUintLE(hfRTPresent, tvb, 4, 4)
	// Extended present words.
	off := 8
	pres := []uint32{uint32(present)}
	for p := uint32(present); p&0x80000000 != 0 && off+4 <= int(hl); off += 4 {
		p = tvb.U32LE(off)
		pres = append(pres, p)
	}
	fcs := false
	for bit := 0; bit < 29; bit++ {
		if pres[0]&(1<<bit) == 0 {
			continue
		}
		sz, ok := rtFields[bit]
		if !ok {
			break
		}
		off = (off + sz[0] - 1) &^ (sz[0] - 1)
		if off+sz[1] > int(hl) {
			break
		}
		switch bit {
		case 0:
			rt.AddUintLE(hfRTTSFT, tvb, off, 8)
		case 1:
			rt.AddUint(hfRTFlags, tvb, off, 1)
			rt.AddBits(hfRTFCS, tvb, off, 1, uint64(tvb.U8(off)))
			fcs = tvb.U8(off)&0x10 != 0
		case 2:
			rt.AddValue(hfRTRate, tvb, off, 1, d.FloatValue(d.FtFloat, float64(tvb.U8(off))/2))
		case 3:
			rt.AddUintLE(hfRTFreq, tvb, off, 2)
			rt.AddUintLE(hfRTChFlags, tvb, off+2, 2)
		case 5:
			rt.AddValue(hfRTSignal, tvb, off, 1, d.IntValue(d.FtInt8, int64(int8(tvb.U8(off)))))
		case 6:
			rt.AddValue(hfRTNoise, tvb, off, 1, d.IntValue(d.FtInt8, int64(int8(tvb.U8(off)))))
		case 11:
			rt.AddUint(hfRTAntenna, tvb, off, 1)
		case 14:
			rt.AddUintLE(hfRTRxFlags, tvb, off, 2)
		}
		off += sz[1]
	}
	pi.Protocols = append(pi.Protocols, "radiotap")
	rest := tvb.Sub(int(hl), -1)
	if fcs && rest.Len() > 4 {
		body := rest.Sub(0, rest.Len()-4)
		dissectWLAN(body, pi, tree)
		tree.AddUint(hfWLFCS, rest, rest.Len()-4, 4)
	} else {
		dissectWLAN(rest, pi, tree)
	}
	return tvb.Len()
}

func wlanFlagString(f uint8) string {
	var b [8]byte
	names := "opmPRTMF" // order, protected, more data, pwr mgt, retry, more frag, from DS, to DS (bit 7..0)
	_ = names
	chars := []byte{'o', 'p', 'm', 'P', 'R', 'F', 'T'}
	_ = chars
	// Wireshark prints bit 7..0 as o p m P R F f t, with '.' for unset
	sym := [8]byte{'o', 'p', 'm', 'P', 'R', 'F', 'F', 'T'}
	for i := 0; i < 8; i++ {
		if f&(1<<(7-i)) != 0 {
			b[i] = sym[i]
		} else {
			b[i] = '.'
		}
	}
	// "to DS"/"from DS" are shown through the DS status bits: t = bit0, f = bit1
	if f&1 != 0 {
		b[7] = 't'
	}
	if f&2 != 0 {
		b[6] = 'f'
	}
	return string(b[:])
}

func dissectWLAN(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	if tvb.Len() < 10 {
		return 0
	}
	wt := tree.AddProtocol(protoWLAN, tvb, 0, -1)
	pi.SetProtocol("802.11")
	fc0 := tvb.U8(0)
	typ, sub := uint64(fc0>>2)&3, uint64(fc0>>4)
	ts := typ<<4 | sub
	name := orDefault(wlanSubtypes[ts], fmt.Sprintf("Unknown (0x%02x)", ts))
	fn, _ := wt.AddUintLE(hfWLFC, tvb, 0, 2)
	fn.AddBits(hfWLVersion, tvb, 0, 1, uint64(fc0))
	fn.AddBits(hfWLType, tvb, 0, 1, uint64(fc0))
	fn.AddBits(hfWLSubtype, tvb, 0, 1, uint64(fc0))
	wt.AddValue(hfWLTS, tvb, 0, 1, d.UintValue(d.FtUint8, ts)).SetHidden()
	fl, _ := wt.AddUint(hfWLFlags, tvb, 1, 1)
	_ = fl
	fl2 := tvb.U8(1)
	fb := uint64(fl2)
	wt.AddBits(hfWLDS, tvb, 1, 1, fb)
	wt.AddBits(hfWLToDS, tvb, 1, 1, fb)
	wt.AddBits(hfWLFromDS, tvb, 1, 1, fb)
	wt.AddBits(hfWLMoreFrag, tvb, 1, 1, fb)
	wt.AddBits(hfWLRetry, tvb, 1, 1, fb)
	wt.AddBits(hfWLPwr, tvb, 1, 1, fb)
	wt.AddBits(hfWLMoreData, tvb, 1, 1, fb)
	wt.AddBits(hfWLProt, tvb, 1, 1, fb)
	wt.AddBits(hfWLOrder, tvb, 1, 1, fb)
	wt.AddUintLE(hfWLDur, tvb, 2, 2)
	toDS, fromDS := fl2&1 != 0, fl2&2 != 0
	flags := wlanFlagString(fl2) + "C"
	off := 4
	info := name
	var bssid, sa, da []byte
	hdr := func(n int) bool { return tvb.Has(off, n) }
	switch typ {
	case 1: // control
		if !hdr(6) {
			return tvb.Len()
		}
		wt.AddBytes(hfWLRA, tvb, off, 6)
		off += 6
		switch ts {
		case 0x1b, 0x18, 0x19, 0x1a, 0x1e, 0x1f:
			if hdr(6) {
				wt.AddBytes(hfWLTA, tvb, off, 6)
				off += 6
			}
		}
		pi.SetInfo(fmt.Sprintf("%s, Flags=%s", name, flags))
		return tvb.Len()
	case 0, 2:
		if !hdr(20) {
			return tvb.Len()
		}
		wt.AddBytes(hfWLRA, tvb, 4, 6)
		wt.AddBytes(hfWLTA, tvb, 10, 6)
		type addr struct {
			f   *d.FieldDef
			off int
		}
		var addrs []addr
		off = 24
		switch {
		case typ == 0 || (!toDS && !fromDS):
			addrs = []addr{{hfWLDA, 4}, {hfWLSA, 10}, {hfWLBSSID, 16}}
		case !toDS && fromDS:
			addrs = []addr{{hfWLDA, 4}, {hfWLBSSID, 10}, {hfWLSA, 16}}
		case toDS && !fromDS:
			addrs = []addr{{hfWLBSSID, 4}, {hfWLSA, 10}, {hfWLDA, 16}}
		default:
			if !tvb.Has(24, 6) {
				return tvb.Len()
			}
			addrs = []addr{{hfWLDA, 16}, {hfWLSA, 24}}
			off = 30
		}
		for _, ad := range addrs {
			_, b := wt.AddBytes(ad.f, tvb, ad.off, 6)
			wt.AddValue(hfWLAddr, tvb, ad.off, 6, d.BytesValue(d.FtEther, b)).SetHidden()
			switch ad.f {
			case hfWLBSSID:
				bssid = b
			case hfWLSA:
				sa = b
			case hfWLDA:
				da = b
			}
		}
		sc := tvb.U16LE(22)
		wt.AddUintValue(hfWLFrag, tvb, 22, 2, uint64(sc&0xf))
		wt.AddUintValue(hfWLSeq, tvb, 22, 2, uint64(sc>>4))
		info = fmt.Sprintf("%s, SN=%d, FN=%d, Flags=%s", name, sc>>4, sc&0xf, flags)
		_, _, _ = bssid, sa, da
	default:
		pi.SetInfo(name)
		return tvb.Len()
	}
	protected := fl2&0x40 != 0
	if typ == 2 && sub&8 != 0 { // QoS
		if hdr(2) {
			q := tvb.U16LE(off)
			qn, _ := wt.AddUintLE(hfWLQoS, tvb, off, 2)
			qn.AddBits(hfWLQoSPrio, tvb, off, 2, uint64(q))
			off += 2
		}
	}
	if fl2&0x80 != 0 && sub&8 != 0 {
		off += 4 // HT control
	}
	if typ == 0 {
		off = 24
		info += dissectWLANMgmt(tvb, off, int(sub), wt, pi)
		pi.SetInfo(info)
		return tvb.Len()
	}
	if sub&4 != 0 { // null function: no body
		pi.SetInfo(info)
		return tvb.Len()
	}
	if protected {
		if hdr(8) {
			wt.AddBytes(hfWLCCMP, tvb, off, 8)
			off += 8
		}
		wt.AddBytes(hfWLProtData, tvb, off, tvb.Remaining(off))
		pi.SetProtocol("802.11")
		pi.SetInfo(info)
		return tvb.Len()
	}
	// LLC/SNAP
	if tvb.Has(off, 8) && tvb.U8(off) == 0xaa && tvb.U8(off+1) == 0xaa {
		et := uint64(tvb.U16(off + 6))
		pi.SetInfo(info)
		body := tvb.Sub(off+8, -1)
		if _, ok := EtherTypeTable.Try(et, body, pi, tree); !ok {
			pi.Call(DataHandle, body, tree)
		}
		return tvb.Len()
	}
	pi.SetInfo(info)
	if tvb.Remaining(off) > 0 {
		pi.Call(DataHandle, tvb.Sub(off, -1), tree)
	}
	return tvb.Len()
}

func dissectWLANMgmt(tvb *d.Tvb, off, sub int, wt *d.Node, pi *d.PacketInfo) string {
	extra := ""
	switch sub {
	case 8, 5: // Beacon, Probe Response
		if !tvb.Has(off, 12) {
			return extra
		}
		wt.AddUintLE(hfWLFixedTS, tvb, off, 8)
		wt.AddUintLE(hfWLBI, tvb, off+8, 2)
		wt.AddUintLE(hfWLCap, tvb, off+10, 2)
		off += 12
		extra = fmt.Sprintf(", BI=%d", tvb.U16LE(off-4))
	case 4: // Probe Request: only tags
	case 0, 2: // Association/Reassociation Request
		wt.AddUintLE(hfWLCap, tvb, off, 2)
		wt.AddUintLE(hfWLListen, tvb, off+2, 2)
		off += 4
		if sub == 2 {
			off += 6
		}
	case 1, 3: // Association/Reassociation Response
		wt.AddUintLE(hfWLCap, tvb, off, 2)
		wt.AddUintLE(hfWLStatus, tvb, off+2, 2)
		wt.AddUintLE(hfWLAID, tvb, off+4, 2)
		off += 6
	case 11: // Authentication
		wt.AddUintLE(hfWLAuthAlg, tvb, off, 2)
		wt.AddUintLE(hfWLAuthSeq, tvb, off+2, 2)
		wt.AddUintLE(hfWLStatus, tvb, off+4, 2)
		return extra
	case 10, 12:
		wt.AddUintLE(hfWLReason, tvb, off, 2)
		return extra
	default:
		return extra
	}
	var ssid string
	for tvb.Has(off, 2) {
		tag, l := uint64(tvb.U8(off)), int(tvb.U8(off+1))
		if !tvb.Has(off+2, l) {
			break
		}
		tn := wt.AddText(tvb, off, 2+l, "Tag: %s", orDefault(wlanTags[tag], fmt.Sprintf("Tag %d", tag)))
		tn.AddUint(hfWLTagNum, tvb, off, 1)
		tn.AddUint(hfWLTagLen, tvb, off+1, 1)
		switch tag {
		case 0:
			_, b := tn.AddBytes(hfWLSSID, tvb, off+2, l)
			ssid = string(b)
			tn.SetText("Tag: SSID parameter set: %s", ssid)
		case 1, 50:
			for i := 0; i < l; i++ {
				r := tvb.U8(off + 2 + i)
				tn.AddUint(hfWLRates, tvb, off+2+i, 1)
				_ = r
			}
		case 3:
			if l >= 1 {
				tn.AddUint(hfWLChannel, tvb, off+2, 1)
			}
		case 7:
			if l >= 2 {
				tn.AddString(hfWLCountry, tvb, off+2, 2)
			}
		case 48:
			dissectRSN(tvb.Sub(off+2, l), tn)
		default:
			if l > 0 {
				tn.AddBytes(hfWLTagData, tvb, off+2, l)
			}
		}
		off += 2 + l
	}
	if ssid != "" || sub == 8 || sub == 4 || sub == 5 {
		s := ssid
		extra += fmt.Sprintf(", SSID=%q", s)
		if s == "" {
			extra = strings.Replace(extra, `SSID=""`, "SSID=Wildcard (Broadcast)", 1)
		}
	}
	return extra
}

func dissectRSN(t *d.Tvb, n *d.Node) {
	if t.Len() < 8 {
		return
	}
	n.AddUintLE(hfWLRSNVer, t, 0, 2)
	n.AddUint(hfWLRSNGroup, t, 5, 1)
	off := 6
	if !t.Has(off, 2) {
		return
	}
	pc := int(t.U16LE(off))
	off += 2
	for i := 0; i < pc && t.Has(off, 4); i++ {
		n.AddUint(hfWLRSNPair, t, off+3, 1)
		off += 4
	}
	if !t.Has(off, 2) {
		return
	}
	ac := int(t.U16LE(off))
	off += 2
	for i := 0; i < ac && t.Has(off, 4); i++ {
		n.AddUint(hfWLRSNAKM, t, off+3, 1)
		off += 4
	}
}

// ---------------- EAPOL ----------------

var (
	protoEAPOL   = d.RegisterProto("802.1X Authentication", "EAPOL", "eapol")
	hfEAPOLVer   = protoEAPOL.Field("eapol.version", "Version", d.FtUint8)
	hfEAPOLType  = protoEAPOL.Field("eapol.type", "Type", d.FtUint8, d.WithVS(map[uint64]string{0: "EAP Packet", 1: "Start", 2: "Logoff", 3: "Key", 4: "Encapsulated ASF Alert"}))
	hfEAPOLLen   = protoEAPOL.Field("eapol.len", "Length", d.FtUint16)
	hfEAPOLDesc  = protoEAPOL.Field("eapol.keydes.type", "Key Descriptor Type", d.FtUint8, d.WithVS(map[uint64]string{1: "RC4 Descriptor", 2: "EAPOL RSN Key", 254: "EAPOL WPA Key"}))
	hfEAPOLInfo  = protoEAPOL.Field("wlan.rsn.keydes.key_info", "Key Information", d.FtUint16, d.WithBase(d.BaseHex))
	hfEAPOLKLen  = protoEAPOL.Field("eapol.keydes.key_len", "Key Length", d.FtUint16)
	hfEAPOLRC    = protoEAPOL.Field("eapol.keydes.replay_counter", "Replay Counter", d.FtUint64)
	hfEAPOLNonce = protoEAPOL.Field("eapol.keydes.nonce", "WPA Key Nonce", d.FtBytes)
	hfEAPOLMIC   = protoEAPOL.Field("eapol.keydes.mic", "WPA Key MIC", d.FtBytes)
	hfEAPOLDLen  = protoEAPOL.Field("eapol.keydes.data_len", "WPA Key Data Length", d.FtUint16)
	hfEAPOLData  = protoEAPOL.Field("eapol.keydes.data", "WPA Key Data", d.FtBytes)
	eapolHandle  = d.RegisterHandle("eapol", d.NewHandle(protoEAPOL, dissectEAPOL))
)

func init() { EtherTypeTable.Add(0x888e, eapolHandle) }

func dissectEAPOL(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	if tvb.Len() < 4 {
		return 0
	}
	et := tree.AddProtocol(protoEAPOL, tvb, 0, -1)
	pi.SetProtocol("EAPOL")
	et.AddUint(hfEAPOLVer, tvb, 0, 1)
	_, typ := et.AddUint(hfEAPOLType, tvb, 1, 1)
	et.AddUint(hfEAPOLLen, tvb, 2, 2)
	if typ != 3 || tvb.Len() < 95 {
		pi.SetInfo(map[uint64]string{0: "EAP Packet", 1: "Start", 2: "Logoff"}[typ])
		return tvb.Len()
	}
	et.AddUint(hfEAPOLDesc, tvb, 4, 1)
	_, info := et.AddUint(hfEAPOLInfo, tvb, 5, 2)
	et.AddUint(hfEAPOLKLen, tvb, 7, 2)
	et.AddUint(hfEAPOLRC, tvb, 9, 8)
	et.AddBytes(hfEAPOLNonce, tvb, 17, 32)
	et.AddBytes(hfEAPOLMIC, tvb, 77, 16)
	_, dl := et.AddUint(hfEAPOLDLen, tvb, 93, 2)
	if dl > 0 && tvb.Has(95, int(dl)) {
		et.AddBytes(hfEAPOLData, tvb, 95, int(dl))
	}
	// 4-way handshake message number from the key information bits.
	msg := 0
	ack, mic, secure, install := info&0x80 != 0, info&0x100 != 0, info&0x200 != 0, info&0x40 != 0
	switch {
	case ack && !mic:
		msg = 1
	case !ack && mic && !secure:
		msg = 2
	case ack && mic && install:
		msg = 3
	case !ack && mic && secure:
		msg = 4
	}
	pi.SetInfo(fmt.Sprintf("Key (Message %d of 4)", msg))
	return tvb.Len()
}
