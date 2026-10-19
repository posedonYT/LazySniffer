package main

import (
	"bufio"
	"context"
	"fmt"
	"github.com/poseydon/lazysniffer/internal/config"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/poseydon/lazysniffer/internal/columns"
	"github.com/poseydon/lazysniffer/internal/dfilter"
	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/engine"
	"github.com/poseydon/lazysniffer/internal/export"
	"github.com/poseydon/lazysniffer/internal/store"
)

func readCmd() *cobra.Command {
	var (
		verbose bool
		count   int
		fields  []string
		hex     bool
		filter  string
		format  string
	)
	cmd := &cobra.Command{
		Use:   "read <file>",
		Short: "Print packets of a capture file (like tshark -r)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if cfg, _ := config.Load(); cfg != nil {
				setupKeylog(cfg, tuiFlags.keylog)
			}
			c, err := store.Open(args[0])
			if err != nil {
				return err
			}
			defer c.Close()
			if err := c.Load(context.Background(), nil); err != nil {
				return err
			}
			w := bufio.NewWriter(os.Stdout)
			defer w.Flush()
			var fdefs []*dissect.FieldDef
			for _, name := range fields {
				f := dissect.LookupField(name)
				if f == nil {
					return fmt.Errorf("unknown field %q", name)
				}
				fdefs = append(fdefs, f)
			}
			flt, err := dfilter.Compile(filter)
			if err != nil {
				return err
			}
			frames, err := engine.Filter(context.Background(), c, flt, 1, uint32(c.Count()), nil)
			if err != nil {
				return err
			}
			if count > 0 && count < len(frames) {
				frames = frames[:count]
			}
			if format != "" {
				fm, ok := map[string]export.DissectFormat{"text": export.DissectText, "details": export.DissectDetails, "csv": export.DissectCSV,
					"json": export.DissectJSON, "psml": export.DissectPSML, "pdml": export.DissectPDML}[format]
				if !ok {
					return fmt.Errorf("unknown format %q (text, details, csv, json, psml, pdml)", format)
				}
				w.Flush()
				return export.WriteDissections(context.Background(), os.Stdout, c, frames, fm)
			}
			rows := columns.NewBuilder(c, visibleDefaults())
			full := c.Session().NewWorker(dissect.Options{Full: true, Columns: true})
			for i, num := range frames {
				prev := uint32(0)
				if i > 0 {
					prev = frames[i-1]
				}
				switch {
				case len(fdefs) > 0:
					pi := full.Dissect(c.Input(num))
					var cells []string
					for _, f := range fdefs {
						var vals []string
						for _, v := range pi.Tree.Values(f) {
							vals = append(vals, f.FilterString(v.V))
						}
						cells = append(cells, strings.Join(vals, ","))
					}
					fmt.Fprintln(w, strings.Join(cells, "\t"))
				case verbose:
					pi := full.Dissect(c.Input(num))
					export.WriteTree(w, &pi.Tree.Root)
					if hex {
						export.WriteHex(w, pi.Sources[0].Data)
					}
					fmt.Fprintln(w)
				default:
					r := rows.Row(num, prev)
					fmt.Fprintln(w, strings.Join(r.Cells, "  "))
				}
			}
			if c.Truncated() {
				fmt.Fprintln(os.Stderr, "lazysniffer: the capture file appears to have been cut short in the middle of a packet")
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&verbose, "verbose", "V", false, "print the full protocol tree")
	cmd.Flags().BoolVarP(&hex, "hex", "x", false, "print packet bytes (with -V)")
	cmd.Flags().IntVarP(&count, "count", "c", 0, "stop after this many packets")
	cmd.Flags().StringVarP(&filter, "display-filter", "Y", "", "only print packets matching this display filter")
	cmd.Flags().StringSliceVarP(&fields, "field", "e", nil, "print these fields (tab separated)")
	cmd.Flags().StringVarP(&format, "format", "T", "", "output format: text, details, csv, json, psml, pdml")
	return cmd
}

func visibleDefaults() []columns.Column {
	var out []columns.Column
	for _, c := range columns.Defaults() {
		if !c.Hide {
			out = append(out, c)
		}
	}
	return out
}

func fieldsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "fields [prefix]",
		Short: "List known display filter fields (like tshark -G fields)",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			prefix := ""
			if len(args) == 1 {
				prefix = args[0]
			}
			w := bufio.NewWriter(os.Stdout)
			defer w.Flush()
			for _, f := range dissect.FieldsWithPrefix(prefix) {
				kind := "F"
				if f.Type == dissect.FtProtocol {
					kind = "P"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", kind, f.Name, f.Abbrev, f.Type)
			}
		},
	}
}

func dftestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "dftest <filter>",
		Short: "Check a display filter and show the fields it uses",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			text := strings.Join(args, " ")
			f, err := dfilter.Compile(text)
			if err != nil {
				if fe, ok := err.(*dfilter.Error); ok && fe.Len >= 0 {
					fmt.Println(text)
					fmt.Println(strings.Repeat(" ", fe.Pos) + "^" + strings.Repeat("~", max(fe.Len-1, 0)))
				}
				return err
			}
			fmt.Println("Filter:", text)
			fmt.Println("Fields:")
			for _, fd := range f.Fields {
				fmt.Printf("  %-40s %s\n", fd.Abbrev, fd.Type)
			}
			for _, w := range f.Warnings {
				fmt.Println("Warning:", w)
			}
			return nil
		},
	}
}
