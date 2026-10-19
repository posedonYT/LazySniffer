// Package deep talks to Wireshark's sharkd (JSON-RPC over stdio) so that
// protocols, fields and statistics lazysniffer does not implement natively
// can still be dissected when Wireshark is installed.
package deep

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// Find returns the path of sharkd, or "" when Wireshark is not installed.
func Find() string {
	for _, p := range []string{"sharkd", "/opt/homebrew/bin/sharkd", "/usr/local/bin/sharkd", "/usr/bin/sharkd", "/Applications/Wireshark.app/Contents/MacOS/sharkd"} {
		if path, err := exec.LookPath(p); err == nil {
			return path
		}
	}
	return ""
}

// Disabled turns the deep engine off (tests, --no-deep).
var Disabled bool

// Available reports whether a deep engine can be started.
func Available() bool { return !Disabled && Find() != "" }

// Client is one sharkd process with a loaded capture file.
type Client struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	in     *bufio.Writer
	out    *bufio.Reader
	nextID int
	closed bool
	File   string
}

// Start launches sharkd.
func Start() (*Client, error) {
	path := Find()
	if path == "" || Disabled {
		return nil, errors.New("sharkd (Wireshark) is not installed")
	}
	cmd := exec.Command(path, "-")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	c := &Client{cmd: cmd, in: bufio.NewWriter(stdin), out: bufio.NewReaderSize(stdout, 1<<20)}
	return c, nil
}

// Close stops the process.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	c.cmd.Process.Kill()
	c.cmd.Wait()
}

type rpcReply struct {
	ID     int             `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// call sends a request and returns the raw result. sharkd also prints
// diagnostics to stdout, so lines that are not JSON replies are skipped.
func (c *Client) call(method string, params map[string]any) (json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("deep engine closed")
	}
	c.nextID++
	req := map[string]any{"jsonrpc": "2.0", "id": c.nextID, "method": method}
	if params != nil {
		req["params"] = params
	}
	b, _ := json.Marshal(req)
	c.in.Write(b)
	c.in.WriteByte('\n')
	if err := c.in.Flush(); err != nil {
		return nil, err
	}
	for {
		line, err := c.out.ReadBytes('\n')
		if err != nil {
			return nil, fmt.Errorf("sharkd: %w", err)
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var r rpcReply
		if json.Unmarshal(line, &r) != nil || r.ID != c.nextID {
			continue
		}
		if r.Error != nil {
			return nil, errors.New(strings.TrimSpace(r.Error.Message))
		}
		return r.Result, nil
	}
}

// Load opens a capture file in the engine.
func (c *Client) Load(file string) error {
	if _, err := c.call("load", map[string]any{"file": file}); err != nil {
		return err
	}
	c.File = file
	return nil
}

// Check validates a display filter with Wireshark's compiler.
func (c *Client) Check(filter string) error {
	_, err := c.call("check", map[string]any{"filter": filter})
	return err
}

// Frames returns the numbers of the frames matching filter.
func (c *Client) Frames(filter string) ([]uint32, error) {
	raw, err := c.call("frames", map[string]any{"filter": filter, "limit": 1 << 24})
	if err != nil {
		return nil, err
	}
	var rows []struct {
		Num uint32 `json:"num"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	out := make([]uint32, len(rows))
	for i, r := range rows {
		out[i] = r.Num
	}
	return out, nil
}

// Node is one item of the dissection tree.
type Node struct {
	Label     string  `json:"l"`
	Offsets   []int   `json:"h"`  // start, length
	Type      string  `json:"t"`  // "proto", "url", ...
	Filter    string  `json:"f"`  // "field == value"
	Field     string  `json:"fn"` // field name
	Children  []*Node `json:"n"`
	DS        int     `json:"ds"`
	Expert    int     `json:"e"`
	Sev       string  `json:"s"`
	Generated bool    `json:"g"`
	Hidden    bool    `json:"v"`
}

// Frame is a fully dissected packet.
type Frame struct {
	Tree  []*Node
	Bytes []byte
	// Sources are additional data sources (decrypted, reassembled…).
	Sources []Source
}

// Source is a named data source with its bytes.
type Source struct {
	Name  string
	Bytes []byte
}

// Frame dissects one frame completely.
func (c *Client) Frame(num uint32) (*Frame, error) {
	raw, err := c.call("frame", map[string]any{"frame": num, "proto": true, "bytes": true})
	if err != nil {
		return nil, err
	}
	var r struct {
		Tree  []*Node `json:"tree"`
		Bytes string  `json:"bytes"`
		Other []struct {
			Name  string `json:"name"`
			Bytes string `json:"bytes"`
		} `json:"data_sources"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	f := &Frame{Tree: r.Tree}
	f.Bytes, _ = base64.StdEncoding.DecodeString(r.Bytes)
	for _, o := range r.Other {
		b, _ := base64.StdEncoding.DecodeString(o.Bytes)
		f.Sources = append(f.Sources, Source{Name: o.Name, Bytes: b})
	}
	return f, nil
}

// Fields returns fields whose name starts with prefix (autocompletion).
func (c *Client) Fields(prefix string) ([]string, error) {
	raw, err := c.call("complete", map[string]any{"field": prefix})
	if err != nil {
		return nil, err
	}
	var r struct {
		Field []struct {
			F string `json:"f"`
		} `json:"field"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	out := make([]string, len(r.Field))
	for i, f := range r.Field {
		out[i] = f.F
	}
	return out, nil
}

// Tap runs a Wireshark statistics tap such as "conv:TCP", "endpt:IPv4",
// "srt:dns", "rtd:..." and returns the JSON result.
func (c *Client) Tap(spec string, filter string) (json.RawMessage, error) {
	p := map[string]any{"tap0": spec}
	if filter != "" {
		p["filter"] = filter
	}
	return c.call("tap", p)
}

// Follow returns the payload of a followed stream (kind "TCP", "UDP",
// "TLS", "HTTP", "HTTP2", …).
func (c *Client) Follow(kind, filter string) (json.RawMessage, error) {
	return c.call("follow", map[string]any{"follow": kind, "filter": filter})
}

// Walk visits the tree depth first.
func Walk(nodes []*Node, fn func(n *Node, depth int) bool) {
	var rec func(ns []*Node, d int)
	rec = func(ns []*Node, d int) {
		for _, n := range ns {
			if fn(n, d) {
				rec(n.Children, d+1)
			}
		}
	}
	rec(nodes, 0)
}
