package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/poseydon/lazysniffer/internal/capture"
)

func dumpcapCmd() *cobra.Command {
	return &cobra.Command{
		Use:                "dumpcap [dumpcap options]",
		Short:              "Capture packets to a pcapng file (the capture helper)",
		Long:               "Captures from interfaces with libpcap and writes pcapng, like Wireshark's dumpcap.\nOptions: -i iface (repeatable) -f filter -s snaplen -B MB -p -I -k -w file -c count -a duration:SEC|filesize:KB -b filesize:KB|files:N|duration:SEC -r replay.pcap --speed N",
		DisableFlagParsing: true,
		Run: func(cmd *cobra.Command, args []string) {
			os.Exit(capture.RunDumpcap(args))
		},
	}
}

func doctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check capture permissions and optional tools",
		Run: func(cmd *cobra.Command, args []string) {
			for _, c := range capture.Doctor() {
				mark := "✓"
				if !c.OK {
					mark = "✗"
				}
				fmt.Printf("%s %-24s %s\n", mark, c.Name, c.Info)
				if c.Fix != "" {
					fmt.Printf("  → %s\n", c.Fix)
				}
			}
		},
	}
}

func setupCmd() *cobra.Command {
	var uninstall bool
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Allow capturing without sudo (run once with sudo)",
		Long: `macOS: creates the access_bpf group, adds you to it and installs a launch
daemon that grants the group access to /dev/bpf* at boot (like Wireshark's
ChmodBPF). Linux: installs lazysniffer-dumpcap with cap_net_raw and
cap_net_admin. Run: sudo lazysniffer setup`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return capture.Setup(os.Stdout, uninstall)
		},
	}
	cmd.Flags().BoolVar(&uninstall, "uninstall", false, "remove what setup installed")
	return cmd
}
