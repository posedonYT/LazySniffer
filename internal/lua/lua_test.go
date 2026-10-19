package lua_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/poseydon/lazysniffer/internal/dfilter"
	"github.com/poseydon/lazysniffer/internal/dissect"
	_ "github.com/poseydon/lazysniffer/internal/dissect/proto"
	"github.com/poseydon/lazysniffer/internal/engine"
	"github.com/poseydon/lazysniffer/internal/lua"
	"github.com/poseydon/lazysniffer/internal/store"
	g "github.com/poseydon/lazysniffer/internal/testutil/pktgen"
)

const plugin = `
local foo = Proto("foo", "Foo Test Protocol")
local f_type = ProtoField.uint8("foo.type", "Type", base.DEC, {[1] = "Hello", [2] = "Data"})
local f_len  = ProtoField.uint16("foo.len", "Length", base.DEC)
local f_flag = ProtoField.uint8("foo.flags", "Flags", base.HEX, nil, 0x0f)
local f_msg  = ProtoField.string("foo.msg", "Message")
local f_ip   = ProtoField.ipv4("foo.addr", "Address")
foo.fields = { f_type, f_len, f_flag, f_msg, f_ip }

function foo.dissector(buffer, pinfo, tree)
  if buffer:len() < 8 then return 0 end
  pinfo.cols.protocol = "FOO"
  local t = tree:add(foo, buffer(), "Foo Protocol")
  t:add(f_type, buffer(0, 1))
  t:add(f_len, buffer(1, 2))
  t:add(f_flag, buffer(3, 1))
  t:add(f_ip, buffer(4, 4))
  local n = buffer(1, 2):uint()
  t:add(f_msg, buffer(8, n))
  pinfo.cols.info:set("Foo type " .. buffer(0, 1):uint() .. " len " .. n)
  return buffer:len()
end

DissectorTable.get("udp.port"):add(9999, foo)
`

func capture(t *testing.T) string {
	f := g.DefaultFlow()
	f.B.Port = 9999
	payload := append([]byte{1, 0, 5, 0x0a, 10, 1, 2, 3}, "hello"...)
	return g.WritePcapng(t, []g.Packet{{TS: 1e9, Data: g.UDP(f, payload)}})
}

func TestLuaPlugin(t *testing.T) {
	if err := lua.LoadString("foo.lua", plugin); err != nil {
		t.Fatal(err)
	}
	c, err := store.Open(capture(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Load(context.Background(), nil)
	for filter, want := range map[string]int{
		`foo`: 1, `foo.type == 1`: 1, `foo.type == "Hello"`: 1, `foo.len == 5`: 1, `foo.msg == "hello"`: 1, `foo.addr == 10.1.2.3`: 1, `foo.flags == 0x0a`: 1, `foo.type == 2`: 0,
	} {
		f, err := dfilter.Compile(filter)
		if err != nil {
			t.Fatalf("%s: %v", filter, err)
		}
		got, _ := engine.Filter(context.Background(), c, f, 1, 1, nil)
		if len(got) != want {
			t.Errorf("%s: %v", filter, got)
		}
	}
	w := c.Session().NewWorker(dissect.Options{Columns: true, Want: make([]bool, dissect.NumFields())})
	pi := w.Dissect(c.Input(1))
	if pi.Protocol() != "FOO" || pi.Info() != "Foo type 1 len 5" {
		t.Errorf("columns %q %q", pi.Protocol(), pi.Info())
	}
}

// TestAgainstTshark runs the same script in Wireshark's Lua.
func TestAgainstTshark(t *testing.T) {
	tshark := "/opt/homebrew/bin/tshark"
	if _, err := os.Stat(tshark); err != nil {
		t.Skip("tshark is not installed")
	}
	script := filepath.Join(t.TempDir(), "foo.lua")
	os.WriteFile(script, []byte(plugin), 0o644)
	out, err := exec.Command(tshark, "-r", capture(t), "-X", "lua_script:"+script, "-T", "fields", "-e", "foo.type", "-e", "foo.len", "-e", "foo.msg",
		"-e", "foo.addr", "-e", "foo.flags", "-e", "_ws.col.protocol", "-e", "_ws.col.info", "-Y", "foo").CombinedOutput()
	if err != nil {
		t.Skipf("tshark cannot run Lua here: %v\n%s", err, out)
	}
	got := strings.TrimSpace(string(out))
	want := "1\t5\thello\t10.1.2.3\t0x0a\tFOO\tFoo type 1 len 5"
	if got != want {
		t.Errorf("tshark says %q, expected %q", got, want)
	}
}
