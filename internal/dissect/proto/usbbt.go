package proto

import (
	"fmt"

	d "github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/pcapio"
)

// ---------------- USB (Linux usbmon) ----------------

var (
	usbURBTypes  = map[uint64]string{'S': "URB_SUBMIT", 'C': "URB_COMPLETE", 'E': "URB_ERROR"}
	usbTransfers = map[uint64]string{0: "URB_ISOCHRONOUS", 1: "URB_INTERRUPT", 2: "URB_CONTROL", 3: "URB_BULK"}
	usbRequests  = map[uint64]string{0: "GET STATUS", 1: "CLEAR FEATURE", 3: "SET FEATURE", 5: "SET ADDRESS", 6: "GET DESCRIPTOR", 7: "SET DESCRIPTOR",
		8: "GET CONFIGURATION", 9: "SET CONFIGURATION", 10: "GET INTERFACE", 11: "SET INTERFACE", 12: "SYNCH FRAME"}

	protoUSB     = d.RegisterProto("USB", "USB", "usb")
	hfUSBURBID   = protoUSB.Field("usb.urb_id", "URB id", d.FtUint64, d.WithBase(d.BaseHex))
	hfUSBURBType = protoUSB.Field("usb.urb_type", "URB type", d.FtChar, d.WithVS(usbURBTypes))
	hfUSBXfer    = protoUSB.Field("usb.transfer_type", "URB transfer type", d.FtUint8, d.WithBase(d.BaseHex), d.WithVS(usbTransfers))
	hfUSBEP      = protoUSB.Field("usb.endpoint_address", "Endpoint", d.FtUint8, d.WithBase(d.BaseHex))
	hfUSBDir     = protoUSB.Field("usb.endpoint_address.direction", "Direction", d.FtUint8, d.WithMask(0x80), d.WithParentBits(8), d.WithVS(map[uint64]string{0: "OUT", 1: "IN"}))
	hfUSBEPNum   = protoUSB.Field("usb.endpoint_address.number", "Endpoint number", d.FtUint8, d.WithMask(0x0f), d.WithParentBits(8))
	hfUSBDev     = protoUSB.Field("usb.device_address", "Device", d.FtUint8)
	hfUSBBus     = protoUSB.Field("usb.bus_id", "URB bus id", d.FtUint16)
	hfUSBSetup   = protoUSB.Field("usb.setup_flag", "Device setup request", d.FtChar)
	hfUSBDataFl  = protoUSB.Field("usb.data_flag", "Data", d.FtUint8)
	hfUSBStatus  = protoUSB.Field("usb.urb_status", "URB status", d.FtInt32)
	hfUSBLen     = protoUSB.Field("usb.urb_len", "URB length [bytes]", d.FtUint32)
	hfUSBDLen    = protoUSB.Field("usb.data_len", "Application Data length [bytes]", d.FtUint32)
	hfUSBReqT    = protoUSB.Field("usb.bmRequestType", "bmRequestType", d.FtUint8, d.WithBase(d.BaseHex))
	hfUSBReq     = protoUSB.Field("usb.setup.bRequest", "bRequest", d.FtUint8, d.WithVS(usbRequests))
	hfUSBValue   = protoUSB.Field("usb.setup.wValue", "wValue", d.FtUint16, d.WithBase(d.BaseHex))
	hfUSBIndex   = protoUSB.Field("usb.setup.wIndex", "wIndex", d.FtUint16, d.WithBase(d.BaseHex))
	hfUSBWLen    = protoUSB.Field("usb.setup.wLength", "wLength", d.FtUint16)
	hfUSBCapData = protoUSB.Field("usb.capdata", "Leftover Capture Data", d.FtBytes)
	usbHandle    = d.RegisterHandle("usb", d.NewHandle(protoUSB, dissectUSBLinux))
)

func init() {
	EncapTable.Add(uint64(pcapio.LinkUSBLinux), d.NewHandle(protoUSB, func(t *d.Tvb, pi *d.PacketInfo, tree *d.Node) int { return dissectUSBmon(t, pi, tree, false) }))
	EncapTable.Add(uint64(pcapio.LinkUSBLinuxMMapped), d.NewHandle(protoUSB, func(t *d.Tvb, pi *d.PacketInfo, tree *d.Node) int { return dissectUSBmon(t, pi, tree, true) }))
}

func dissectUSBLinux(t *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	return dissectUSBmon(t, pi, tree, false)
}

func dissectUSBmon(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node, mmapped bool) int {
	hl := 48
	if mmapped {
		hl = 64
	}
	if tvb.Len() < 48 {
		return 0
	}
	ut := tree.AddProtocol(protoUSB, tvb, 0, -1)
	pi.SetProtocol("USB")
	// usbmon little-endian layout (host order on the capturing machine).
	ut.AddUintLE(hfUSBURBID, tvb, 0, 8)
	_, typ := ut.AddUint(hfUSBURBType, tvb, 8, 1)
	_, xfer := ut.AddUint(hfUSBXfer, tvb, 9, 1)
	ep := tvb.U8(10)
	epn := ut.AddUint
	_ = epn
	ut.AddUint(hfUSBEP, tvb, 10, 1)
	ut.AddBits(hfUSBDir, tvb, 10, 1, uint64(ep))
	ut.AddBits(hfUSBEPNum, tvb, 10, 1, uint64(ep))
	_, dev := ut.AddUint(hfUSBDev, tvb, 11, 1)
	_, bus := ut.AddUintLE(hfUSBBus, tvb, 12, 2)
	_, setup := ut.AddUint(hfUSBSetup, tvb, 14, 1)
	ut.AddUint(hfUSBDataFl, tvb, 15, 1)
	status := int32(tvb.U32LE(28))
	ut.AddValue(hfUSBStatus, tvb, 28, 4, d.IntValue(d.FtInt32, int64(status)))
	_, ulen := ut.AddUintLE(hfUSBLen, tvb, 32, 4)
	_, dlen := ut.AddUintLE(hfUSBDLen, tvb, 36, 4)
	off := 40
	if setup == 0 && tvb.Has(40, 8) {
		ut.AddUint(hfUSBReqT, tvb, 40, 1)
		ut.AddUint(hfUSBReq, tvb, 41, 1)
		ut.AddUintLE(hfUSBValue, tvb, 42, 2)
		ut.AddUintLE(hfUSBIndex, tvb, 44, 2)
		ut.AddUintLE(hfUSBWLen, tvb, 46, 2)
	}
	off = hl
	if tvb.Remaining(off) > 0 {
		ut.AddBytes(hfUSBCapData, tvb, off, tvb.Remaining(off))
	}
	dir := "OUT"
	if ep&0x80 != 0 {
		dir = "IN"
	}
	pi.SetInfo(fmt.Sprintf("%s %s %d.%d.%d len=%d/%d", usbURBTypes[typ], dir, bus, dev, ep&0x0f, dlen, ulen))
	_ = xfer
	return tvb.Len()
}

// ---------------- Bluetooth HCI (H4) ----------------

var (
	hciPackets  = map[uint64]string{1: "HCI Command", 2: "HCI ACL Data", 3: "HCI SCO Data", 4: "HCI Event"}
	hciOGF      = map[uint64]string{1: "Link Control", 2: "Link Policy", 3: "Controller & Baseband", 4: "Informational", 5: "Status", 6: "Testing", 8: "LE Controller"}
	hciCommands = map[uint64]string{0x0401: "Inquiry", 0x0405: "Create Connection", 0x0406: "Disconnect", 0x040b: "Link Key Request Reply", 0x0c01: "Set Event Mask",
		0x0c03: "Reset", 0x0c13: "Write Local Name", 0x0c14: "Read Local Name", 0x0c1a: "Write Scan Enable", 0x0c24: "Write Class of Device",
		0x1001: "Read Local Version Information", 0x1009: "Read BD_ADDR", 0x2001: "LE Set Event Mask", 0x2005: "LE Set Random Address",
		0x2006: "LE Set Advertising Parameters", 0x2008: "LE Set Advertising Data", 0x200a: "LE Set Advertise Enable", 0x200b: "LE Set Scan Parameters",
		0x200c: "LE Set Scan Enable", 0x200d: "LE Create Connection"}
	hciEvents = map[uint64]string{0x01: "Inquiry Complete", 0x02: "Inquiry Result", 0x03: "Connect Complete", 0x04: "Connect Request", 0x05: "Disconnect Complete",
		0x08: "Encryption Change", 0x0e: "Command Complete", 0x0f: "Command Status", 0x13: "Number of Completed Packets", 0x3e: "LE Meta"}
	attOpcodes = map[uint64]string{0x01: "Error Response", 0x02: "Exchange MTU Request", 0x03: "Exchange MTU Response", 0x04: "Find Information Request",
		0x05: "Find Information Response", 0x08: "Read By Type Request", 0x09: "Read By Type Response", 0x0a: "Read Request", 0x0b: "Read Response",
		0x10: "Read By Group Type Request", 0x11: "Read By Group Type Response", 0x12: "Write Request", 0x13: "Write Response", 0x1b: "Handle Value Notification",
		0x1d: "Handle Value Indication", 0x1e: "Handle Value Confirmation", 0x52: "Write Command"}

	protoHCI    = d.RegisterProto("Bluetooth HCI H4", "HCI_H4", "hci_h4")
	hfHCIType   = protoHCI.Field("hci_h4.type", "HCI Packet Type", d.FtUint8, d.WithBase(d.BaseHex), d.WithVS(hciPackets))
	hfHCIDir    = protoHCI.Field("hci_h4.direction", "Direction", d.FtUint8, d.WithVS(map[uint64]string{0: "Sent", 1: "Rcvd"}))
	hfHCIOpcode = protoHCI.Field("bthci_cmd.opcode", "Command Opcode", d.FtUint16, d.WithBase(d.BaseHex), d.WithVS(hciCommands))
	hfHCIOGF    = protoHCI.Field("bthci_cmd.opcode.ogf", "Opcode Group Field", d.FtUint16, d.WithMask(0xfc00), d.WithParentBits(16), d.WithVS(hciOGF))
	hfHCIOCF    = protoHCI.Field("bthci_cmd.opcode.ocf", "Opcode Command Field", d.FtUint16, d.WithMask(0x03ff), d.WithParentBits(16), d.WithBase(d.BaseHex))
	hfHCICmdLen = protoHCI.Field("bthci_cmd.param_length", "Parameter Total Length", d.FtUint8)
	hfHCIEvCode = protoHCI.Field("bthci_evt.code", "Event Code", d.FtUint8, d.WithBase(d.BaseHex), d.WithVS(hciEvents))
	hfHCIEvLen  = protoHCI.Field("bthci_evt.param_length", "Parameter Total Length", d.FtUint8)
	hfHCIEvData = protoHCI.Field("bthci_evt.data", "Event Parameters", d.FtBytes)
	hfHCIParams = protoHCI.Field("bthci_cmd.params", "Command Parameters", d.FtBytes)
	hfHCIACLH   = protoHCI.Field("bthci_acl.chandle", "Connection Handle", d.FtUint16, d.WithMask(0x0fff), d.WithParentBits(16), d.WithBase(d.BaseHex))
	hfHCIACLPB  = protoHCI.Field("bthci_acl.pb_flag", "PB Flag", d.FtUint16, d.WithMask(0x3000), d.WithParentBits(16))
	hfHCIACLLen = protoHCI.Field("bthci_acl.length", "Data Total Length", d.FtUint16)
	hfL2Len     = protoHCI.Field("btl2cap.length", "Length", d.FtUint16)
	hfL2CID     = protoHCI.Field("btl2cap.cid", "CID", d.FtUint16, d.WithBase(d.BaseHex), d.WithVS(map[uint64]string{1: "L2CAP Signaling Channel", 4: "Attribute Protocol", 5: "LE L2CAP Signaling Channel", 6: "Security Manager Protocol"}))
	hfATTOp     = protoHCI.Field("btatt.opcode", "Opcode", d.FtUint8, d.WithBase(d.BaseHex), d.WithVS(attOpcodes))
	hfATTHandle = protoHCI.Field("btatt.handle", "Handle", d.FtUint16, d.WithBase(d.BaseHex))
	hfATTValue  = protoHCI.Field("btatt.value", "Value", d.FtBytes)
	hciHandle   = d.RegisterHandle("hci_h4", d.NewHandle(protoHCI, dissectHCI))
	hciPhdr     = d.RegisterHandle("hci_h4_phdr", d.NewHandle(protoHCI, dissectHCIPhdr))
)

func init() {
	EncapTable.Add(uint64(pcapio.LinkBluetoothH4), hciHandle)
	EncapTable.Add(uint64(pcapio.LinkBluetoothH4Phdr), hciPhdr)
}

func dissectHCIPhdr(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	if tvb.Len() < 5 {
		return 0
	}
	ht := tree.AddProtocol(protoHCI, tvb, 0, 4)
	ht.AddUint(hfHCIDir, tvb, 0, 4)
	return dissectHCI(tvb.Sub(4, -1), pi, tree)
}

func dissectHCI(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	if tvb.Len() < 1 {
		return 0
	}
	ht := tree.AddProtocol(protoHCI, tvb, 0, 1)
	_, typ := ht.AddUint(hfHCIType, tvb, 0, 1)
	pi.SetProtocol(map[uint64]string{1: "HCI_CMD", 2: "HCI_ACL", 3: "HCI_SCO", 4: "HCI_EVT"}[typ])
	if pi.Protocol() == "" {
		pi.SetProtocol("HCI_H4")
	}
	switch typ {
	case 1:
		if !tvb.Has(1, 3) {
			return tvb.Len()
		}
		ct := tree.AddProtocol(protoHCI, tvb, 1, -1)
		opc := uint64(tvb.U16LE(1))
		on, _ := ct.AddUintLE(hfHCIOpcode, tvb, 1, 2)
		on.AddBits(hfHCIOGF, tvb, 1, 2, opc)
		on.AddBits(hfHCIOCF, tvb, 1, 2, opc)
		_, l := ct.AddUint(hfHCICmdLen, tvb, 3, 1)
		if l > 0 && tvb.Has(4, int(l)) {
			ct.AddBytes(hfHCIParams, tvb, 4, int(l))
		}
		pi.SetInfo("Sent " + orDefault(hciCommands[opc], fmt.Sprintf("Unknown (0x%04x)", opc)))
	case 4:
		if !tvb.Has(1, 2) {
			return tvb.Len()
		}
		et := tree.AddProtocol(protoHCI, tvb, 1, -1)
		_, code := et.AddUint(hfHCIEvCode, tvb, 1, 1)
		_, l := et.AddUint(hfHCIEvLen, tvb, 2, 1)
		if l > 0 && tvb.Has(3, int(l)) {
			et.AddBytes(hfHCIEvData, tvb, 3, int(l))
		}
		pi.SetInfo("Rcvd " + orDefault(hciEvents[code], fmt.Sprintf("Unknown (0x%02x)", code)))
	case 2:
		if !tvb.Has(1, 4) {
			return tvb.Len()
		}
		at := tree.AddProtocol(protoHCI, tvb, 1, -1)
		h := uint64(tvb.U16LE(1))
		at.AddBits(hfHCIACLH, tvb, 1, 2, h)
		at.AddBits(hfHCIACLPB, tvb, 1, 2, h)
		at.AddUintLE(hfHCIACLLen, tvb, 3, 2)
		info := "Sent ACL Data"
		if tvb.Has(5, 4) {
			l2 := tree.AddProtocol(protoHCI, tvb, 5, -1)
			l2.AddUintLE(hfL2Len, tvb, 5, 2)
			_, cid := l2.AddUintLE(hfL2CID, tvb, 7, 2)
			info = fmt.Sprintf("L2CAP CID=0x%04x", cid)
			if cid == 4 && tvb.Has(9, 1) {
				op := uint64(tvb.U8(9))
				l2.AddUint(hfATTOp, tvb, 9, 1)
				if tvb.Has(10, 2) && (op == 0x0a || op == 0x12 || op == 0x52 || op == 0x1b || op == 0x1d) {
					l2.AddUintLE(hfATTHandle, tvb, 10, 2)
					if tvb.Remaining(12) > 0 {
						l2.AddBytes(hfATTValue, tvb, 12, tvb.Remaining(12))
					}
				}
				info = "Sent " + orDefault(attOpcodes[op], fmt.Sprintf("ATT 0x%02x", op))
				pi.SetProtocol("ATT")
			}
		}
		pi.SetInfo(info)
	default:
		pi.SetInfo(hciPackets[typ])
	}
	return tvb.Len()
}
