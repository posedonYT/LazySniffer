package difftest

import (
	"encoding/binary"
	"testing"

	"github.com/poseydon/lazysniffer/internal/pcapio"
	g "github.com/poseydon/lazysniffer/internal/testutil/pktgen"
)

func TestUSB(t *testing.T) {
	urb := func(typ byte, xfer byte, ep byte, setup bool, data []byte) []byte {
		h := make([]byte, 64)
		binary.LittleEndian.PutUint64(h[0:], 0xffff8a0012345678)
		h[8], h[9], h[10], h[11] = typ, xfer, ep, 5
		binary.LittleEndian.PutUint16(h[12:], 1)
		if setup {
			h[14] = 0
			copy(h[40:], []byte{0x80, 6, 0, 1, 0, 0, 18, 0}) // GET DESCRIPTOR device
		} else {
			h[14] = '-'
		}
		h[15] = 0
		binary.LittleEndian.PutUint32(h[32:], uint32(len(data)))
		binary.LittleEndian.PutUint32(h[36:], uint32(len(data)))
		return append(h, data...)
	}
	pk := []g.Packet{
		{TS: 1e6, Data: urb('S', 2, 0x80, true, nil)},
		{TS: 2e6, Data: urb('C', 2, 0x80, false, []byte{18, 1, 0, 2, 0, 0, 0, 64, 0x86, 0x80, 0x01, 0x00, 0, 1, 1, 2, 0, 1})},
		{TS: 3e6, Data: urb('S', 3, 0x02, false, []byte{1, 2, 3, 4})},
	}
	compare(t, g.WritePcapngLink(t, pcapio.LinkUSBLinuxMMapped, pk), "", []string{
		"usb.urb_id", "usb.urb_type", "usb.transfer_type", "usb.endpoint_address", "usb.endpoint_address.direction", "usb.endpoint_address.number",
		"usb.device_address", "usb.bus_id", "usb.urb_status", "usb.urb_len", "usb.data_len", "usb.bmRequestType", "usb.setup.bRequest", "usb.setup.wLength",
	})
}

func TestBluetooth(t *testing.T) {
	pk := []g.Packet{
		{TS: 1e6, Data: []byte{0x01, 0x03, 0x0c, 0x00}},                   // Reset
		{TS: 2e6, Data: []byte{0x04, 0x0e, 0x04, 0x01, 0x03, 0x0c, 0x00}}, // Command Complete
		{TS: 3e6, Data: []byte{0x01, 0x0b, 0x20, 0x07, 0x01, 0x10, 0x00, 0x10, 0x00, 0x00, 0x00}},
		{TS: 4e6, Data: []byte{0x02, 0x40, 0x20, 0x0b, 0x00, 0x07, 0x00, 0x04, 0x00, 0x12, 0x2a, 0x00, 0x01, 0x02, 0x03}}, // ACL L2CAP ATT write
	}
	compare(t, g.WritePcapngLink(t, pcapio.LinkBluetoothH4, pk), "", []string{
		"hci_h4.type", "bthci_cmd.opcode", "bthci_cmd.opcode.ogf", "bthci_cmd.opcode.ocf", "bthci_cmd.param_length", "bthci_evt.code", "bthci_evt.param_length",
		"bthci_acl.chandle", "bthci_acl.pb_flag", "bthci_acl.length", "btl2cap.length", "btl2cap.cid", "btatt.opcode", "btatt.handle", "btatt.value",
	})
}
