package config

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ColorRule is a packet coloring rule (Wireshark colorfilters format).
type ColorRule struct {
	Name     string
	Filter   string
	BG, FG   string // "#rrggbb"
	Disabled bool
}

// DefaultColorRules mirrors Wireshark's stock rule set. Rules referencing
// protocols lazysniffer does not dissect yet simply never match.
const DefaultColorRules = `# lazysniffer coloring rules — Wireshark "colorfilters" format:
# @name@filter@[bg red,green,blue][fg red,green,blue] (16-bit components)
# A leading ! disables a rule.
@Bad TCP@tcp.analysis.flags && !tcp.analysis.window_update && !tcp.analysis.keep_alive && !tcp.analysis.keep_alive_ack@[4626,10023,11822][63479,34695,34695]
@HSRP State Change@hsrp.state != 8 && hsrp.state != 16@[4626,10023,11822][65535,64764,40092]
@Spanning Tree Topology  Change@stp.type == 0x80@[4626,10023,11822][65535,64764,40092]
@OSPF State Change@ospf.msg != 1@[4626,10023,11822][65535,64764,40092]
@ICMP errors@icmp.type in { 3..5 11 } || icmpv6.type in { 1..4 }@[4626,10023,11822][47031,63479,29812]
@ARP@arp@[64250,61680,55255][4626,10023,11822]
@ICMP@icmp || icmpv6@[64764,57568,65535][4626,10023,11822]
@TCP RST@tcp.flags.reset eq 1@[42148,0,0][65535,64764,40092]
@SCTP ABORT@sctp.chunk_type eq ABORT@[42148,0,0][65535,64764,40092]
@TTL low or unexpected@(ip.dst != 224.0.0.0/4 && ip.ttl < 5 && !pim && !ospf) || (ip.dst == 224.0.0.0/24 && ip.dst != 224.0.0.251 && ip.ttl != 1 && !(vrrp || carp))@[42148,0,0][60652,61680,60395]
@Checksum Errors@ip.checksum.status == 0 || tcp.checksum.status == 0 || udp.checksum.status == 0 || icmp.checksum.status == 0 || icmpv6.checksum.status == 0@[4626,10023,11822][63479,34695,34695]
@SMB@smb || nbss || nbns || netbios@[65278,65535,53456][4626,10023,11822]
@HTTP@http || tcp.port == 80 || http2@[58596,65535,51143][4626,10023,11822]
@DCERPC@dcerpc@[51199,38706,65535][4626,10023,11822]
@Routing@hsrp || eigrp || ospf || bgp || cdp || vrrp || carp || gvrp || igmp || ismp@[65534,62325,54808][4626,10023,11822]
@TCP SYN/FIN@tcp.flags & 0x02 || tcp.flags.fin == 1@[41026,41026,41026][4626,10023,11822]
@TCP@tcp@[59345,58980,65534][4626,10023,11822]
@UDP@udp@[56026,61166,65535][4626,10023,11822]
@Broadcast@eth[0] & 1@[65535,65535,65535][47802,48573,46774]
@System Event@systemd_journal || sysdig@[59110,59110,59110][11565,28527,39578]
`

// ParseColorRules parses the Wireshark colorfilters format.
func ParseColorRules(r io.Reader) ([]ColorRule, error) {
	var out []ColorRule
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		disabled := false
		if strings.HasPrefix(s, "!") {
			disabled, s = true, s[1:]
		}
		if !strings.HasPrefix(s, "@") {
			return nil, fmt.Errorf("line %d: expected @name@filter@[bg][fg]", line)
		}
		parts := strings.SplitN(s[1:], "@", 3)
		if len(parts) != 3 {
			return nil, fmt.Errorf("line %d: expected @name@filter@[bg][fg]", line)
		}
		var br, bg, bb, fr, fg, fb int
		if _, err := fmt.Sscanf(parts[2], "[%d,%d,%d][%d,%d,%d]", &br, &bg, &bb, &fr, &fg, &fb); err != nil {
			return nil, fmt.Errorf("line %d: bad colors %q", line, parts[2])
		}
		out = append(out, ColorRule{
			Name: parts[0], Filter: parts[1], Disabled: disabled,
			BG: hex16(br, bg, bb), FG: hex16(fr, fg, fb),
		})
	}
	return out, sc.Err()
}

func hex16(r, g, b int) string { return fmt.Sprintf("#%02x%02x%02x", r>>8, g>>8, b>>8) }

func unhex(s string) (int, int, int) {
	var r, g, b int
	fmt.Sscanf(strings.TrimPrefix(s, "#"), "%02x%02x%02x", &r, &g, &b)
	return r * 257, g * 257, b * 257
}

// FormatColorRules writes rules in the colorfilters format.
func FormatColorRules(w io.Writer, rules []ColorRule) error {
	for _, r := range rules {
		pre := ""
		if r.Disabled {
			pre = "!"
		}
		br, bg, bb := unhex(r.BG)
		fr, fg, fb := unhex(r.FG)
		if _, err := fmt.Fprintf(w, "%s@%s@%s@[%d,%d,%d][%d,%d,%d]\n", pre, r.Name, r.Filter, br, bg, bb, fr, fg, fb); err != nil {
			return err
		}
	}
	return nil
}

// LoadColorRules reads colorfilters from the config dir, or the defaults.
func LoadColorRules() ([]ColorRule, error) {
	f, err := os.Open(filepath.Join(Dir(), "colorfilters"))
	if err != nil {
		return ParseColorRules(strings.NewReader(DefaultColorRules))
	}
	defer f.Close()
	return ParseColorRules(f)
}
