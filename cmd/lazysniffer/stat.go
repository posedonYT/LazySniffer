package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/poseydon/lazysniffer/internal/dfilter"
	"github.com/poseydon/lazysniffer/internal/engine"
	"github.com/poseydon/lazysniffer/internal/stats"
	"github.com/poseydon/lazysniffer/internal/store"
)

func statCmd() *cobra.Command {
	var filter, kind string
	cmd := &cobra.Command{
		Use:   "stat <conv|endpoints|phs|len> <file>",
		Short: "Print statistics of a capture file (like tshark -z)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := store.Open(args[1])
			if err != nil {
				return err
			}
			defer c.Close()
			ctx := context.Background()
			if err := c.Load(ctx, nil); err != nil {
				return err
			}
			var frames []uint32
			if filter != "" {
				f, err := dfilter.Compile(filter)
				if err != nil {
					return err
				}
				if frames, err = engine.Filter(ctx, c, f, 1, uint32(c.Count()), nil); err != nil {
					return err
				}
			}
			k := stats.TCP
			for _, kk := range stats.Kinds {
				if strings.EqualFold(kk.String(), kind) {
					k = kk
				}
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			defer tw.Flush()
			switch args[0] {
			case "conv":
				cs, err := stats.Conversations(ctx, c, frames, k)
				if err != nil {
					return err
				}
				fmt.Fprintln(tw, "Address A\tAddress B\tPackets\tBytes\tA→B pkts\tA→B bytes\tB→A pkts\tB→A bytes\tStart\tDuration")
				for _, cv := range cs {
					a, b := cv.A.String(), cv.B.String()
					if k == stats.TCP || k == stats.UDP {
						a, b = fmt.Sprintf("%s:%d", a, cv.PortA), fmt.Sprintf("%s:%d", b, cv.PortB)
					}
					fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%.6f\t%.4f\n", a, b, cv.Packets(), cv.Bytes(), cv.PktsAB, cv.BytesAB, cv.PktsBA, cv.BytesBA, float64(cv.FirstTS)/1e9, cv.Duration())
				}
			case "endpoints":
				es, err := stats.Endpoints(ctx, c, frames, k)
				if err != nil {
					return err
				}
				fmt.Fprintln(tw, "Address\tPort\tPackets\tBytes\tTx pkts\tTx bytes\tRx pkts\tRx bytes")
				for _, e := range es {
					fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n", e.Addr, e.Port, e.Packets(), e.Bytes(), e.TxP, e.TxB, e.RxP, e.RxB)
				}
			case "phs":
				root, err := stats.Hierarchy(ctx, c, frames)
				if err != nil {
					return err
				}
				var walk func(n *stats.PHS, depth int)
				fmt.Fprintln(tw, "Protocol\tPackets\t% packets\tBytes\t% bytes\tEnd packets\tEnd bytes")
				walk = func(n *stats.PHS, depth int) {
					fmt.Fprintf(tw, "%s%s\t%d\t%.2f\t%d\t%.2f\t%d\t%d\n", strings.Repeat("  ", depth), n.Name, n.Packets,
						100*float64(n.Packets)/float64(max(root.Packets, 1)), n.Bytes, 100*float64(n.Bytes)/float64(max(root.Bytes, 1)), n.EndP, n.EndB)
					for _, ch := range n.Children {
						walk(ch, depth+1)
					}
				}
				walk(root, 0)
			case "len":
				bins, err := stats.Lengths(ctx, c, frames)
				if err != nil {
					return err
				}
				fmt.Fprintln(tw, "Length\tCount")
				for _, b := range bins {
					fmt.Fprintf(tw, "%s\t%d\n", b.Label, b.Count)
				}
			default:
				return fmt.Errorf("unknown statistic %q (conv, endpoints, phs, len)", args[0])
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&filter, "display-filter", "Y", "", "only count packets matching this display filter")
	cmd.Flags().StringVarP(&kind, "type", "t", "tcp", "layer for conv/endpoints: eth, ipv4, ipv6, tcp, udp")
	return cmd
}
