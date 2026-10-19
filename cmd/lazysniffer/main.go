// Command lazysniffer is a terminal network protocol analyzer.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/poseydon/lazysniffer/internal/capture"
	"github.com/poseydon/lazysniffer/internal/config"
	"github.com/poseydon/lazysniffer/internal/deep"
	_ "github.com/poseydon/lazysniffer/internal/dissect/proto"
	"github.com/poseydon/lazysniffer/internal/version"
)

func main() {
	// Installed as lazysniffer-dumpcap (possibly with capture privileges),
	// the binary only runs the capture helper.
	if filepath.Base(os.Args[0]) == "lazysniffer-dumpcap" {
		os.Exit(capture.RunDumpcap(os.Args[1:]))
	}
	root := &cobra.Command{
		Use:   "lazysniffer [file]",
		Short: "A terminal UI for network packet capture and analysis",
		Long: `lazysniffer is a terminal network protocol analyzer in the spirit of
lazygit: capture live traffic or open a capture file, filter it with
Wireshark display filters and dig into every protocol layer.`,
		Args:          cobra.MaximumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.String(),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := ""
			if len(args) == 1 {
				path = args[0]
			}
			return runTUI(path, tuiFlags)
		},
	}
	root.Flags().StringVarP(&tuiFlags.filter, "display-filter", "Y", "", "apply a display filter on open")
	root.Flags().StringSliceVarP(&tuiFlags.ifaces, "interface", "i", nil, "start capturing on these interfaces (- for stdin)")
	root.Flags().StringVarP(&tuiFlags.captureFilter, "capture-filter", "f", "", "capture filter (BPF syntax)")
	root.Flags().StringVar(&tuiFlags.ssh, "ssh", "", "capture remotely: user@host[:iface]")
	root.PersistentFlags().StringSliceVar(&tuiFlags.lua, "lua", nil, "load a Lua dissector plugin (also ~/.config/lazysniffer/plugins/*.lua)")
	root.PersistentFlags().StringVar(&config.Profile, "profile", "", "configuration profile (Edit → Configuration Profiles)")
	root.PersistentFlags().BoolVar(&deep.Disabled, "no-deep", false, "do not use Wireshark (sharkd) for fields and protocols lazysniffer lacks")
	root.PersistentFlags().StringVar(&tuiFlags.keylog, "keylog", "", "TLS key log file (SSLKEYLOGFILE format) used to decrypt TLS and QUIC")
	root.AddCommand(readCmd(), statCmd(), runCmd(), infoCmd(), mergeCmd(), editCmd(), reorderCmd(), text2pcapCmd(), versionCmd(), fieldsCmd(), dftestCmd(), dumpcapCmd(), doctorCmd(), setupCmd())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "lazysniffer:", err)
		os.Exit(1)
	}
}

type uiFlags struct {
	filter        string
	ifaces        []string
	captureFilter string
	ssh           string
	keylog        string
	lua           []string
}

var tuiFlags uiFlags

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("lazysniffer", version.String())
		},
	}
}
