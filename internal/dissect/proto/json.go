package proto

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	d "github.com/poseydon/lazysniffer/internal/dissect"
)

var (
	protoJSON     = d.RegisterProto("JavaScript Object Notation", "JSON", "json")
	hfJSONObject  = protoJSON.Field("json.object", "Object", d.FtNone)
	hfJSONArray   = protoJSON.Field("json.array", "Array", d.FtNone)
	hfJSONMember  = protoJSON.Field("json.member", "Member", d.FtNone)
	hfJSONKey     = protoJSON.Field("json.key", "Key", d.FtString)
	hfJSONString  = protoJSON.Field("json.value.string", "String value", d.FtString)
	hfJSONNumber  = protoJSON.Field("json.value.number", "Number value", d.FtDouble)
	hfJSONTrue    = protoJSON.Field("json.value.true", "True value", d.FtNone)
	hfJSONFalse   = protoJSON.Field("json.value.false", "False value", d.FtNone)
	hfJSONNull    = protoJSON.Field("json.value.null", "Null value", d.FtNone)
	hfJSONWithVal = protoJSON.Field("json.member_with_value", "Member with value", d.FtString)
	hfJSONPath    = protoJSON.Field("json.path", "Path", d.FtString)
	hfJSONPathVal = protoJSON.Field("json.path_with_value", "Path with value", d.FtString)
	jsonHandle    = d.RegisterHandle("json", d.NewHandle(protoJSON, dissectJSON))
)

func dissectJSON(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	raw := tvb.Raw()
	if !json.Valid(raw) {
		return 0
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	jt := tree.AddProtocol(protoJSON, tvb, 0, -1)
	jt.SetText("JavaScript Object Notation: %s", "application/json")
	jsonParse(dec, jt, "", 0)
	return tvb.Len()
}

// jsonParse walks the token stream so members keep their original order.
func jsonParse(dec *json.Decoder, parent *d.Node, path string, depth int) {
	tok, err := dec.Token()
	if err != nil || depth > 64 {
		return
	}
	jsonToken(dec, tok, parent, path, depth)
}

func jsonToken(dec *json.Decoder, tok json.Token, parent *d.Node, path string, depth int) {
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			on := parent.AddValue(hfJSONObject, nil, 0, 0, d.Value{})
			on.SetText("Object")
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return
				}
				k, _ := kt.(string)
				mp := path + "/" + k
				mn := on.AddValue(hfJSONMember, nil, 0, 0, d.Value{})
				mn.SetText("Member: %s", k)
				mn.AddValue(hfJSONKey, nil, 0, 0, d.StringValue(k))
				mn.AddValue(hfJSONPath, nil, 0, 0, d.StringValue(mp)).SetHidden()
				vt, err := dec.Token()
				if err != nil {
					return
				}
				if s := jsonScalar(vt); s != "" {
					v := strings.Trim(s, "\"")
					mn.AddValue(hfJSONWithVal, nil, 0, 0, d.StringValue(k+":"+v)).SetHidden()
					mn.AddValue(hfJSONPathVal, nil, 0, 0, d.StringValue(mp+":"+v)).SetHidden()
				}
				jsonToken(dec, vt, mn, mp, depth+1)
			}
			dec.Token() // }
		case '[':
			an := parent.AddValue(hfJSONArray, nil, 0, 0, d.Value{})
			n := 0
			for dec.More() {
				vt, err := dec.Token()
				if err != nil {
					return
				}
				jsonToken(dec, vt, an, fmt.Sprintf("%s/[%d]", path, n), depth+1)
				n++
			}
			dec.Token() // ]
			an.SetText("Array (%d elements)", n)
		}
	case string:
		parent.AddValue(hfJSONString, nil, 0, 0, d.StringValue(t)).SetText("String value: %s", t)
	case json.Number:
		f, _ := t.Float64()
		parent.AddValue(hfJSONNumber, nil, 0, 0, d.Value{F: f}).SetText("Number value: %s", t.String())
	case bool:
		if t {
			parent.AddValue(hfJSONTrue, nil, 0, 0, d.Value{}).SetText("True value")
		} else {
			parent.AddValue(hfJSONFalse, nil, 0, 0, d.Value{}).SetText("False value")
		}
	case nil:
		parent.AddValue(hfJSONNull, nil, 0, 0, d.Value{}).SetText("Null value")
	}
}

func jsonScalar(v any) string {
	switch x := v.(type) {
	case string:
		return strconv.Quote(x)
	case json.Number:
		return x.String()
	case bool:
		return strconv.FormatBool(x)
	case nil:
		return "null"
	}
	return ""
}
