//go:build !darwin

package capture

import (
	"errors"

	"github.com/gopacket/gopacket/pcap"
)

func setWantPktap(*pcap.InactiveHandle) error { return errors.New("PKTAP is only available on macOS") }

// PKTAPSupported reports whether per-packet process info can be captured.
const PKTAPSupported = false
