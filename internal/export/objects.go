package export

import (
	"context"
	"fmt"
	"mime"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/poseydon/lazysniffer/internal/dfilter"
	"github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/engine"
	"github.com/poseydon/lazysniffer/internal/store"
)

// Object is a file transferred over HTTP, HTTP/2 or FTP-DATA.
type Object struct {
	Frame    uint32
	Index    int // n-th object of the frame
	Proto    string
	Host     string
	Type     string
	Filename string
	URI      string
	Size     int
	Dir      string // request or response
}

var dispositionName = regexp.MustCompile(`(?i)filename\*?=(?:UTF-8'')?"?([^";]+)"?`)

// findIn returns the string value of the first node with the abbreviation
// below n.
func findIn(n *dissect.Node, abbrev string) string {
	var out string
	found := false
	n.Walk(func(c *dissect.Node, _ int) bool {
		if !found && c.Field != nil && c.Field.Abbrev == abbrev {
			out, found = c.Value.S, true
		}
		return !found
	})
	return out
}

func ancestor(n *dissect.Node, abbrev string) *dissect.Node {
	for p := n.Parent; p != nil; p = p.Parent {
		if p.Field != nil && p.Field.Abbrev == abbrev {
			return p
		}
	}
	return nil
}

func objectName(uri, disposition, ctype string, frame uint32) string {
	if m := dispositionName.FindStringSubmatch(disposition); m != nil {
		if n := path.Base(strings.TrimSpace(m[1])); n != "." && n != "/" {
			return n
		}
	}
	name := ""
	if u, err := url.Parse(uri); err == nil {
		if p := u.Path; p != "" && !strings.HasSuffix(p, "/") {
			name = path.Base(p)
		}
		if un, err := url.PathUnescape(name); err == nil {
			name = un
		}
	}
	if name == "" {
		name = fmt.Sprintf("object-%d", frame)
		if exts, _ := mime.ExtensionsByType(ctype); len(exts) > 0 {
			name += exts[0]
		}
	}
	return name
}

// Objects lists the files carried in HTTP and HTTP/2 messages (decrypted
// TLS included).
func Objects(ctx context.Context, c *store.Capture) ([]Object, error) {
	flt, err := dfilter.Compile("http.file_data || http2.body.data || http3.body.data || ftp-data.data")
	if err != nil {
		return nil, err
	}
	frames, err := engine.Filter(ctx, c, flt, 1, uint32(c.Count()), nil)
	if err != nil {
		return nil, err
	}
	parts := make([][]Object, engine.Workers())
	err = engine.Each(ctx, c, dissect.Options{Full: true}, frames, func(w int, num uint32, pi *dissect.PacketInfo) {
		idx := 0
		pi.Tree.Root.Walk(func(n *dissect.Node, _ int) bool {
			if n.Field == nil {
				return true
			}
			switch n.Field.Abbrev {
			case "http.file_data":
				ht := ancestor(n, "http")
				if ht == nil {
					break
				}
				uri := findIn(ht, "http.request.full_uri")
				dir := "request"
				if findIn(ht, "http.response.phrase") != "" || findIn(ht, "http.response.version") != "" {
					dir = "response"
				}
				ct := findIn(ht, "http.content_type")
				host := ""
				if u, err := url.Parse(uri); err == nil {
					host = u.Host
				}
				parts[w] = append(parts[w], Object{Frame: num, Index: idx, Proto: "HTTP", Host: host, Type: strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]),
					Filename: objectName(uri, findIn(ht, "http.content_disposition"), ct, num), URI: uri, Size: len(n.Value.B), Dir: dir})
				idx++
			case "http2.body.data":
				p := n.Parent
				uri := findIn(p, "http2.body.uri")
				ct := findIn(p, "http2.body.type")
				host := ""
				if u, err := url.Parse(uri); err == nil {
					host = u.Host
				}
				parts[w] = append(parts[w], Object{Frame: num, Index: idx, Proto: "HTTP2", Host: host, Type: ct,
					Filename: objectName(uri, "", ct, num), URI: uri, Size: len(n.Value.B), Dir: findIn(p, "http2.body.direction")})
				idx++
			case "http3.body.data":
				p := n.Parent
				uri := findIn(p, "http3.body.uri")
				ct := findIn(p, "http3.body.type")
				host := ""
				if u, err := url.Parse(uri); err == nil {
					host = u.Host
				}
				parts[w] = append(parts[w], Object{Frame: num, Index: idx, Proto: "HTTP3", Host: host, Type: ct,
					Filename: objectName(uri, "", ct, num), URI: uri, Size: len(n.Value.B), Dir: findIn(p, "http3.body.direction")})
				idx++
			case "ftp-data.data":
				parts[w] = append(parts[w], Object{Frame: num, Index: idx, Proto: "FTP-DATA", Filename: fmt.Sprintf("ftp-data-%d", num), Size: len(n.Value.B), Dir: "response"})
				idx++
			}
			return true
		})
	})
	if err != nil {
		return nil, err
	}
	var out []Object
	for _, p := range parts {
		out = append(out, p...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Frame != out[j].Frame {
			return out[i].Frame < out[j].Frame
		}
		return out[i].Index < out[j].Index
	})
	return out, nil
}

// ObjectBytes returns the content of an object.
func ObjectBytes(c *store.Capture, o Object) ([]byte, error) {
	w := c.Session().NewWorker(dissect.Options{Full: true})
	pi := w.Dissect(c.Input(o.Frame))
	idx := 0
	var data []byte
	found := false
	pi.Tree.Root.Walk(func(n *dissect.Node, _ int) bool {
		if found || n.Field == nil {
			return !found
		}
		switch n.Field.Abbrev {
		case "http.file_data", "http2.body.data", "http3.body.data", "ftp-data.data":
			if idx == o.Index {
				data, found = append([]byte(nil), n.Value.B...), true
			}
			idx++
		}
		return !found
	})
	if !found {
		return nil, fmt.Errorf("object not found in frame %d", o.Frame)
	}
	return data, nil
}

// SaveObjects writes objects into dir with unique, sanitized names. It
// returns the number of files written.
func SaveObjects(c *store.Capture, objs []Object, dir string) (int, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}
	used := map[string]bool{}
	n := 0
	for _, o := range objs {
		data, err := ObjectBytes(c, o)
		if err != nil {
			return n, err
		}
		name := SafeName(o.Filename)
		if used[name] {
			name = fmt.Sprintf("%d-%s", o.Frame, name)
		}
		used[name] = true
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// SafeName makes a file name safe to create on disk.
func SafeName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || strings.ContainsRune(`/\:*?"<>|`, r) {
			return '_'
		}
		return r
	}, s)
	s = strings.TrimLeft(s, ".")
	if s == "" {
		s = "object"
	}
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}
