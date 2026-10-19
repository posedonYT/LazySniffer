package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/poseydon/lazysniffer/internal/keylog"
	"github.com/poseydon/lazysniffer/internal/pcapio"
	"github.com/poseydon/lazysniffer/internal/pcaptools"
)

func formatOf(path, flag string) pcapio.Format {
	switch strings.ToLower(flag) {
	case "pcap":
		return pcapio.FormatPcap
	case "pcapng":
		return pcapio.FormatPcapng
	}
	if strings.HasSuffix(strings.ToLower(path), ".pcap") {
		return pcapio.FormatPcap
	}
	return pcapio.FormatPcapng
}

func writeFile(path string, pkts []pcaptools.Packet, o pcaptools.WriteOptions) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return pcaptools.Write(f, pkts, o)
}

func infoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info <file>…",
		Short: "Print capture file properties (like capinfos)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, p := range args {
				in, err := pcaptools.Summarize(p)
				if err != nil {
					return err
				}
				fmt.Printf("File name:           %s\n", in.Path)
				fmt.Printf("File type:           %s\n", in.Format)
				fmt.Printf("File encapsulation:  %s\n", strings.Join(in.Encap, ", "))
				fmt.Printf("File size:           %d bytes\n", in.Size)
				fmt.Printf("Number of packets:   %d\n", in.Packets)
				fmt.Printf("Data size:           %d bytes\n", in.DataBytes)
				if in.Packets > 0 {
					fmt.Printf("First packet time:   %s\n", time.Unix(0, in.First).UTC().Format("2006-01-02 15:04:05.000000"))
					fmt.Printf("Last packet time:    %s\n", time.Unix(0, in.Last).UTC().Format("2006-01-02 15:04:05.000000"))
					fmt.Printf("Capture duration:    %.6f seconds\n", in.Duration())
					if d := in.Duration(); d > 0 {
						fmt.Printf("Average packet rate: %.2f packets/s\n", float64(in.Packets)/d)
						fmt.Printf("Average data rate:   %.0f bits/s\n", float64(in.DataBytes)*8/d)
					}
				}
				fmt.Printf("SHA256:              %s\n", in.SHA256)
				for _, c := range in.Comments {
					fmt.Printf("Capture comment:     %s\n", c)
				}
			}
			return nil
		},
	}
}

func mergeCmd() *cobra.Command {
	var out, format string
	var appendMode bool
	cmd := &cobra.Command{
		Use:   "merge -o <out> <file>…",
		Short: "Merge capture files chronologically (like mergecap)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if out == "" {
				return fmt.Errorf("-o output file required")
			}
			pk, secrets, err := pcaptools.Merge(args, appendMode)
			if err != nil {
				return err
			}
			return writeFile(out, pk, pcaptools.WriteOptions{Format: formatOf(out, format), Secrets: secrets})
		},
	}
	cmd.Flags().StringVarP(&out, "output", "o", "", "output file")
	cmd.Flags().StringVarP(&format, "format", "F", "", "pcap or pcapng (default: by extension)")
	cmd.Flags().BoolVarP(&appendMode, "append", "a", false, "append files instead of merging by time")
	return cmd
}

func editCmd() *cobra.Command {
	var out, format, keep, del, secrets string
	var snap, dedup, splitN int
	var shift float64
	var splitSec float64
	var strip bool
	cmd := &cobra.Command{
		Use:   "edit <in> <out>",
		Short: "Select, trim, de-duplicate, shift or split packets (like editcap)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			pk, f, err := pcaptools.Read(args[0])
			if err != nil {
				return err
			}
			defer f.Close()
			o := pcaptools.EditOptions{SnapLen: snap, Dedup: dedup, TimeShift: int64(shift * 1e9), StripComm: strip}
			if o.Keep, err = pcaptools.ParseRanges(keep); err != nil {
				return err
			}
			if o.Delete, err = pcaptools.ParseRanges(del); err != nil {
				return err
			}
			pk = pcaptools.Edit(pk, o)
			wo := pcaptools.WriteOptions{Format: formatOf(args[1], format), Secrets: f.Secrets}
			if secrets != "" {
				// --inject-secrets tls,<keylog file>
				kind, path, ok := strings.Cut(secrets, ",")
				if !ok || kind != "tls" {
					return fmt.Errorf("--inject-secrets: use tls,<keylog file>")
				}
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				s := keylog.New()
				s.AddData(data)
				wo.Secrets = append(wo.Secrets, pcapio.Secrets{Type: pcapio.SecretsTLSKeyLog, Data: s.Export()})
			}
			if splitN > 0 || splitSec > 0 {
				ext := filepath.Ext(args[1])
				base := strings.TrimSuffix(args[1], ext)
				for i, chunk := range pcaptools.Split(pk, splitN, time.Duration(splitSec*float64(time.Second))) {
					if err := writeFile(fmt.Sprintf("%s_%05d%s", base, i+1, ext), chunk, wo); err != nil {
						return err
					}
				}
				return nil
			}
			return writeFile(args[1], pk, wo)
		},
	}
	_ = out
	cmd.Flags().StringVarP(&keep, "keep", "r", "", "keep only these packets, e.g. 1-100,250")
	cmd.Flags().StringVarP(&del, "delete", "R", "", "drop these packets")
	cmd.Flags().IntVarP(&snap, "snaplen", "s", 0, "truncate packets to this many bytes")
	cmd.Flags().IntVarP(&dedup, "dedup", "d", 0, "remove duplicates seen within this many packets")
	cmd.Flags().Float64VarP(&shift, "time-shift", "t", 0, "shift timestamps by this many seconds")
	cmd.Flags().IntVarP(&splitN, "split-packets", "c", 0, "write a new file every N packets")
	cmd.Flags().Float64VarP(&splitSec, "split-seconds", "i", 0, "write a new file every N seconds")
	cmd.Flags().StringVarP(&format, "format", "F", "", "pcap or pcapng")
	cmd.Flags().StringVar(&secrets, "inject-secrets", "", "embed TLS keys: tls,<keylog file>")
	cmd.Flags().BoolVar(&strip, "strip-comments", false, "remove packet comments")
	return cmd
}

func reorderCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reorder <in> <out>",
		Short: "Sort packets by timestamp (like reordercap)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			pk, f, err := pcaptools.Read(args[0])
			if err != nil {
				return err
			}
			defer f.Close()
			return writeFile(args[1], pcaptools.Reorder(pk), pcaptools.WriteOptions{Format: formatOf(args[1], ""), Secrets: f.Secrets})
		},
	}
}

func text2pcapCmd() *cobra.Command {
	var link int
	cmd := &cobra.Command{
		Use:   "text2pcap <hexdump|-> <out>",
		Short: "Convert a hex dump to a capture file (like text2pcap)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			in := os.Stdin
			if args[0] != "-" {
				f, err := os.Open(args[0])
				if err != nil {
					return err
				}
				defer f.Close()
				in = f
			}
			pk, err := pcaptools.Text2Pcap(in, pcapio.LinkType(link), time.Now())
			if err != nil {
				return err
			}
			return writeFile(args[1], pk, pcaptools.WriteOptions{Format: formatOf(args[1], "")})
		},
	}
	cmd.Flags().IntVarP(&link, "link-type", "l", 1, "link-layer type number (1 = Ethernet, 101 = raw IP)")
	return cmd
}
