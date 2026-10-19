//go:build ignore

// Command gen converts the IEEE OUI registry and the IANA service registry
// into the compact gzip files embedded by package resolve.
//
//	go run ./internal/resolve/gen -oui oui.csv -services services.csv
//
// Without flags it downloads both registries.
package main

import (
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

const (
	ouiURL      = "https://standards-oui.ieee.org/oui/oui.csv"
	servicesURL = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"
)

func open(path, url string) io.ReadCloser {
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			log.Fatal(err)
		}
		return f
	}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "lazysniffer-gen")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	return resp.Body
}

var dropWords = map[string]bool{"inc": true, "incorporated": true, "corp": true, "corporation": true,
	"co": true, "ltd": true, "limited": true, "llc": true, "gmbh": true, "ag": true, "sa": true, "srl": true,
	"bv": true, "plc": true, "the": true, "company": true, "kg": true, "oy": true, "ab": true, "as": true, "spa": true}

// shortName mimics Wireshark's manuf short names: words without legal
// suffixes, concatenated and cut to 8 characters ("Apple, Inc." → "Apple").
func shortName(full string) string {
	var words []string
	for _, w := range strings.FieldsFunc(full, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' }) {
		if dropWords[strings.ToLower(w)] {
			continue
		}
		words = append(words, w)
	}
	if len(words) == 0 {
		return ""
	}
	s := strings.Join(words, "")
	if r := []rune(s); len(r) > 8 {
		s = string(r[:8])
	}
	return s
}

func writeGz(path string, lines []string) {
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	zw.Write([]byte(strings.Join(lines, "\n") + "\n"))
	zw.Close()
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s: %d entries, %d bytes\n", path, len(lines), buf.Len())
}

func main() {
	ouiPath := flag.String("oui", "", "local oui.csv")
	svcPath := flag.String("services", "", "local service-names-port-numbers.csv")
	outDir := flag.String("out", "internal/resolve", "output directory")
	flag.Parse()

	r := csv.NewReader(open(*ouiPath, ouiURL))
	r.FieldsPerRecord = -1
	var lines []string
	seen := map[string]bool{}
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(rec) < 3 || rec[0] != "MA-L" {
			continue
		}
		prefix := strings.ToUpper(rec[1])
		if len(prefix) != 6 || seen[prefix] {
			continue
		}
		seen[prefix] = true
		full := strings.Join(strings.Fields(rec[2]), " ")
		short := shortName(full)
		if short == "" {
			continue
		}
		lines = append(lines, prefix+"\t"+short+"\t"+full)
	}
	sort.Strings(lines)
	writeGz(*outDir+"/oui.txt.gz", lines)

	r = csv.NewReader(open(*svcPath, servicesURL))
	r.FieldsPerRecord = -1
	lines = nil
	type key struct {
		port  int
		proto string
	}
	got := map[key]bool{}
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(rec) < 3 || rec[0] == "" || rec[0] == "Service Name" {
			continue
		}
		proto := rec[2]
		if proto != "tcp" && proto != "udp" && proto != "sctp" {
			continue
		}
		// Ranges like "6000-6063" are skipped; single ports only.
		port, err := strconv.Atoi(rec[1])
		if err != nil || port <= 0 || port > 65535 {
			continue
		}
		k := key{port, proto}
		if got[k] {
			continue
		}
		got[k] = true
		lines = append(lines, fmt.Sprintf("%d/%s\t%s", port, proto, rec[0]))
	}
	sort.Strings(lines)
	writeGz(*outDir+"/services.txt.gz", lines)
}
