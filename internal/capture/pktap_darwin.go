//go:build darwin

package capture

import "github.com/gopacket/gopacket/pcap"

func setWantPktap(in *pcap.InactiveHandle) error { return in.SetWantPktap(true) }

// PKTAPSupported reports whether per-packet process info can be captured.
const PKTAPSupported = true
