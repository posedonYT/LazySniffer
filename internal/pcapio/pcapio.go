// Package pcapio reads and writes capture files (pcap, pcapng) and gives
// random access to packet bytes through a memory mapping.
package pcapio

import (
	"errors"
	"fmt"
)

// LinkType is a LINKTYPE_* value as stored in capture files.
type LinkType uint16

// LINKTYPE_* values, see https://www.tcpdump.org/linktypes.html.
const (
	LinkNull              LinkType = 0
	LinkEthernet          LinkType = 1
	LinkPPP               LinkType = 9
	LinkPPPEther          LinkType = 51
	LinkRaw               LinkType = 101
	LinkIEEE80211         LinkType = 105
	LinkLoop              LinkType = 108
	LinkLinuxSLL          LinkType = 113
	LinkIEEE80211Radiotap LinkType = 127
	LinkBluetoothH4       LinkType = 187
	LinkUSBLinux          LinkType = 189
	LinkBluetoothH4Phdr   LinkType = 201
	LinkUSBLinuxMMapped   LinkType = 220
	LinkIPv4              LinkType = 228
	LinkIPv6              LinkType = 229
	LinkNetlink           LinkType = 253
	LinkPKTAP             LinkType = 258
	LinkLinuxSLL2         LinkType = 276
)

var linkTypeNames = map[LinkType]string{
	LinkNull:              "NULL",
	LinkEthernet:          "Ethernet",
	LinkPPP:               "PPP",
	LinkPPPEther:          "PPPoE",
	LinkRaw:               "Raw IP",
	LinkIEEE80211:         "IEEE 802.11",
	LinkLoop:              "OpenBSD loopback",
	LinkLinuxSLL:          "Linux cooked v1",
	LinkIEEE80211Radiotap: "IEEE 802.11 plus radiotap",
	LinkBluetoothH4:       "Bluetooth HCI H4",
	LinkUSBLinux:          "USB Linux",
	LinkBluetoothH4Phdr:   "Bluetooth HCI H4 with pseudo-header",
	LinkUSBLinuxMMapped:   "USB Linux mmapped",
	LinkIPv4:              "Raw IPv4",
	LinkIPv6:              "Raw IPv6",
	LinkNetlink:           "Linux Netlink",
	LinkPKTAP:             "Apple PKTAP",
	LinkLinuxSLL2:         "Linux cooked v2",
}

func (l LinkType) String() string {
	if s, ok := linkTypeNames[l]; ok {
		return s
	}
	return fmt.Sprintf("LINKTYPE %d", uint16(l))
}

// Format identifies the on-disk container format.
type Format uint8

const (
	FormatPcap Format = iota + 1
	FormatPcapNs
	FormatPcapng
)

func (f Format) String() string {
	switch f {
	case FormatPcap:
		return "Wireshark/tcpdump/... - pcap"
	case FormatPcapNs:
		return "Wireshark/tcpdump/... - nanosecond pcap"
	case FormatPcapng:
		return "Wireshark/... - pcapng"
	}
	return "unknown"
}

// Interface describes one capture interface (a pcapng IDB, or the single
// implicit interface of a pcap file).
type Interface struct {
	LinkType    LinkType
	SnapLen     uint32
	Name        string
	Description string
	Filter      string
	OS          string
	Hardware    string
	FCSLen      int8 // -1 when unknown
	TSResol     uint8
	TSOffset    int64
}

// Record is one packet as found in a capture file. Data lives in the file at
// DataOff and is read through File.Data.
type Record struct {
	DataOff  int64
	CapLen   uint32
	OrigLen  uint32
	TS       int64 // nanoseconds since the Unix epoch
	Iface    uint32
	Flags    uint32 // pcapng epb_flags
	Comments []string
	PacketID uint64
	Queue    uint32
}

// Direction values encoded in the low two bits of epb_flags.
const (
	DirUnknown  = 0
	DirInbound  = 1
	DirOutbound = 2
)

// SecretsType is a pcapng Decryption Secrets Block type.
type SecretsType uint32

const (
	SecretsTLSKeyLog       SecretsType = 0x544c534b // "TLSK"
	SecretsWireGuardKeyLog SecretsType = 0x57474b4c // "WGKL"
	SecretsZigBeeNWK       SecretsType = 0x5a4e574b
	SecretsZigBeeAPS       SecretsType = 0x5a415053
	SecretsOPCUA           SecretsType = 0x55414b4c
)

// Secrets is the payload of a Decryption Secrets Block.
type Secrets struct {
	Type SecretsType
	Data []byte
}

// NameRecord maps an address to names (pcapng NRB).
type NameRecord struct {
	Addr  []byte // 4 or 16 bytes
	Names []string
}

// SectionInfo is the metadata of a pcapng section header (or synthesized for pcap).
type SectionInfo struct {
	Hardware    string
	OS          string
	Application string
	Comments    []string
}

var (
	ErrUnknownFormat = errors.New("unknown capture file format")
	ErrTruncated     = errors.New("capture file appears to be cut short")
)

// FormatError reports a corrupt capture file at a given offset.
type FormatError struct {
	Off int64
	Msg string
}

func (e *FormatError) Error() string {
	return fmt.Sprintf("capture file is damaged at offset %d: %s", e.Off, e.Msg)
}
