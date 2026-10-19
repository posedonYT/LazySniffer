package export

import (
	"context"
	"encoding/base64"
	"sort"
	"strings"

	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/engine"
	"github.com/poseydon/lazysniffer/internal/store"
)

// Credential is a username/password seen on the wire.
type Credential struct {
	Frame    uint32
	Proto    string
	Username string
	Password string
	Note     string
}

type credEvent struct {
	frame  uint32
	stream int
	proto  string
	kind   string // user, pass, both, authplain, authlogin, ...
	a, b   string
}

var credFields = []string{
	"tcp.stream", "ftp.request.command", "ftp.request.arg", "pop.request.command", "pop.request.parameter",
	"imap.request.command", "imap.request.parameter", "imap.line", "smtp.req.command", "smtp.req.parameter",
	"http.authbasic", "http.request.full_uri", "urlencoded-form.key", "urlencoded-form.value",
	"mqtt.username", "mqtt.passwd", "mysql.user", "pgsql.user", "pgsql.password", "socks.username", "socks.password",
	"http.request.method",
}

// Credentials scans the capture for clear-text logins (Tools → Credentials).
func Credentials(ctx context.Context, c *store.Capture) ([]Credential, error) {
	want := make([]bool, dissect.NumFields())
	fd := map[string]*dissect.FieldDef{}
	for _, name := range credFields {
		if f := dissect.LookupField(name); f != nil {
			want[f.ID] = true
			fd[name] = f
		}
	}
	parts := make([][]credEvent, engine.Workers())
	err := engine.Each(ctx, c, dissect.Options{Want: want}, engine.AllFrames(c), func(w int, num uint32, pi *dissect.PacketInfo) {
		str := func(name string) []string {
			f := fd[name]
			if f == nil {
				return nil
			}
			var out []string
			for _, v := range pi.Tree.Values(f) {
				out = append(out, v.V.S)
			}
			return out
		}
		stream := -1
		if f := fd["tcp.stream"]; f != nil {
			if v, ok := pi.Tree.First(f); ok {
				stream = int(v.V.U)
			}
		}
		ev := func(proto, kind, a, b string) {
			parts[w] = append(parts[w], credEvent{num, stream, proto, kind, a, b})
		}
		cmds, args := str("ftp.request.command"), str("ftp.request.arg")
		for i, cmd := range cmds {
			if i < len(args) || cmd == "USER" || cmd == "PASS" {
				arg := ""
				if i < len(args) {
					arg = args[i]
				}
				switch cmd {
				case "USER":
					ev("FTP", "user", arg, "")
				case "PASS":
					ev("FTP", "pass", arg, "")
				}
			}
		}
		cmds, args = str("pop.request.command"), str("pop.request.parameter")
		for i, cmd := range cmds {
			arg := ""
			if i < len(args) {
				arg = args[i]
			}
			switch cmd {
			case "USER":
				ev("POP", "user", arg, "")
			case "PASS":
				ev("POP", "pass", arg, "")
			}
		}
		cmds, args = str("imap.request.command"), str("imap.request.parameter")
		for i, cmd := range cmds {
			if cmd == "LOGIN" && i < len(args) {
				f := strings.Fields(args[i])
				if len(f) >= 2 {
					ev("IMAP", "both", strings.Trim(f[0], `"`), strings.Trim(f[1], `"`))
				}
			}
		}
		cmds, args = str("smtp.req.command"), str("smtp.req.parameter")
		for i, cmd := range cmds {
			if cmd == "AUTH" && i < len(args) {
				f := strings.Fields(args[i])
				if len(f) == 2 && strings.EqualFold(f[0], "PLAIN") {
					if b, err := base64.StdEncoding.DecodeString(f[1]); err == nil {
						if p := strings.Split(string(b), "\x00"); len(p) == 3 {
							ev("SMTP", "both", p[1], p[2])
						}
					}
				}
			}
		}
		for _, b := range str("http.authbasic") {
			if u, p, ok := strings.Cut(b, ":"); ok {
				uri := ""
				if s := str("http.request.full_uri"); len(s) > 0 {
					uri = s[0]
				}
				parts[w] = append(parts[w], credEvent{num, stream, "HTTP", "both", u, p + "\x00" + uri})
			}
		}
		keys, vals := str("urlencoded-form.key"), str("urlencoded-form.value")
		var user, pass string
		for i, k := range keys {
			if i >= len(vals) {
				break
			}
			lk := strings.ToLower(k)
			switch {
			case strings.Contains(lk, "pass") || lk == "pwd" || lk == "pw":
				pass = vals[i]
			case strings.Contains(lk, "user") || strings.Contains(lk, "login") || lk == "email" || lk == "name":
				if user == "" {
					user = vals[i]
				}
			}
		}
		if pass != "" {
			uri := ""
			if s := str("http.request.full_uri"); len(s) > 0 {
				uri = s[0]
			}
			parts[w] = append(parts[w], credEvent{num, stream, "HTTP form", "both", user, pass + "\x00" + uri})
		}
		if u := str("mqtt.username"); len(u) > 0 {
			p := str("mqtt.passwd")
			pw := ""
			if len(p) > 0 {
				pw = p[0]
			}
			ev("MQTT", "both", u[0], pw)
		}
		if u := str("socks.username"); len(u) > 0 {
			p := str("socks.password")
			pw := ""
			if len(p) > 0 {
				pw = p[0]
			}
			ev("SOCKS", "both", u[0], pw)
		}
		if u, p := str("pgsql.user"), str("pgsql.password"); len(u) > 0 || len(p) > 0 {
			if len(u) > 0 {
				ev("PostgreSQL", "user", u[0], "")
			}
			if len(p) > 0 {
				ev("PostgreSQL", "pass", p[0], "")
			}
		}
	})
	if err != nil {
		return nil, err
	}
	var events []credEvent
	for _, p := range parts {
		events = append(events, p...)
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].frame < events[j].frame })
	var out []Credential
	pending := map[string]*Credential{} // proto|stream → waiting for PASS
	for _, e := range events {
		key := e.proto + "|" + string(rune(e.stream+1))
		switch e.kind {
		case "both":
			note := ""
			pw := e.b
			if i := strings.IndexByte(pw, 0); i >= 0 {
				pw, note = pw[:i], pw[i+1:]
			}
			out = append(out, Credential{Frame: e.frame, Proto: e.proto, Username: e.a, Password: pw, Note: note})
		case "user":
			cr := &Credential{Frame: e.frame, Proto: e.proto, Username: e.a}
			pending[key] = cr
		case "pass":
			if cr := pending[key]; cr != nil {
				cr.Password = e.a
				out = append(out, *cr)
				delete(pending, key)
			} else {
				out = append(out, Credential{Frame: e.frame, Proto: e.proto, Password: e.a})
			}
		}
	}
	for _, cr := range pending {
		out = append(out, *cr)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Frame < out[j].Frame })
	return out, nil
}
