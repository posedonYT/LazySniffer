package main

import (
	"fmt"
	"os"

	tea "charm.land/bubbletea/v2"
	"github.com/spf13/cobra"

	"github.com/poseydon/lazysniffer/internal/capture"
	"github.com/poseydon/lazysniffer/internal/config"
	"github.com/poseydon/lazysniffer/internal/keylog"
	"github.com/poseydon/lazysniffer/internal/ui"
)

func runCmd() *cobra.Command {
	var iface, captureFilter, display, keys string
	var keep bool
	cmd := &cobra.Command{
		Use:   "run [flags] -- command [args…]",
		Short: "Capture while a command runs and decrypt its TLS traffic",
		Long: `Starts a capture on the default interface, runs the command with
SSLKEYLOGFILE set (curl, Firefox, Chrome, Python requests, Go, … write
their TLS keys there) and opens the capture with TLS decrypted when the
command exits.

  lazysniffer run -- curl -s https://example.com
  lazysniffer run --keep -- open -n -a "Google Chrome" --args https://rutube.ru`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				fmt.Fprintf(os.Stderr, "lazysniffer: %v (using defaults)\n", err)
			}
			if iface == "" {
				iface = capture.DefaultInterface()
			}
			if iface == "" {
				return fmt.Errorf("cannot find the default interface; pass -i")
			}
			if keys == "" {
				f, err := os.CreateTemp("", "lazysniffer-keys-*.log")
				if err != nil {
					return err
				}
				f.Close()
				keys = f.Name()
				defer os.Remove(keys)
			}
			setupKeylog(cfg, keys)
			if display == "" {
				display = ""
			}
			app := ui.New(cfg, ui.Options{Filter: display, Ifaces: []string{iface}, CaptureFilter: captureFilter,
				Exec: args, KeylogFile: keys, KeepOpen: keep})
			_, err = tea.NewProgram(app).Run()
			return err
		},
	}
	cmd.Flags().StringVarP(&iface, "interface", "i", "", "interface to capture on (default: the default route)")
	cmd.Flags().StringVarP(&captureFilter, "capture-filter", "f", "", "capture filter (BPF syntax)")
	cmd.Flags().StringVarP(&display, "display-filter", "Y", "", "display filter")
	cmd.Flags().StringVar(&keys, "keylog-file", "", "write TLS keys here (default: a temporary file)")
	cmd.Flags().BoolVar(&keep, "keep", false, "keep capturing after the command exits (for GUI apps)")
	cmd.Flags().SetInterspersed(false)
	_ = keylog.Default
	return cmd
}
