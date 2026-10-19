package dissect

import "fmt"

// Severity of an expert info item, ordered from least to most severe.
type Severity uint8

const (
	SevComment Severity = iota + 1
	SevChat
	SevNote
	SevWarn
	SevError
)

func (s Severity) String() string {
	switch s {
	case SevComment:
		return "Comment"
	case SevChat:
		return "Chat"
	case SevNote:
		return "Note"
	case SevWarn:
		return "Warning"
	case SevError:
		return "Error"
	}
	return "None"
}

// Group classifies expert info items.
type Group uint8

const (
	GroupChecksum Group = iota + 1
	GroupSequence
	GroupResponseCode
	GroupRequestCode
	GroupUndecoded
	GroupReassemble
	GroupMalformed
	GroupDebug
	GroupProtocol
	GroupSecurity
	GroupComments
	GroupDecryption
	GroupAssumption
	GroupDeprecated
	GroupReceiveWindow
	GroupInterface
	GroupDissectorBug
)

var groupNames = map[Group]string{
	GroupChecksum: "Checksum", GroupSequence: "Sequence", GroupResponseCode: "Response",
	GroupRequestCode: "Request", GroupUndecoded: "Undecoded", GroupReassemble: "Reassemble",
	GroupMalformed: "Malformed", GroupDebug: "Debug", GroupProtocol: "Protocol",
	GroupSecurity: "Security", GroupComments: "Comment", GroupDecryption: "Decryption",
	GroupAssumption: "Assumption", GroupDeprecated: "Deprecated", GroupReceiveWindow: "Receive window",
	GroupInterface: "Interface", GroupDissectorBug: "Dissector bug",
}

func (g Group) String() string {
	if s, ok := groupNames[g]; ok {
		return s
	}
	return "Unknown"
}

// ExpertField is a registered expert info kind; it is also a filterable
// label field (e.g. tcp.analysis.retransmission).
type ExpertField struct {
	F        *FieldDef
	Group    Group
	Severity Severity
	Summary  string
}

// ExpertInfo is an expert item attached to a node.
type ExpertInfo struct {
	Def *ExpertField
	Msg string
}

// ExpertEntry is a frame-level record of an expert item (Expert Info view).
type ExpertEntry struct {
	Def   *ExpertField
	Msg   string
	Proto *Proto
}

var (
	wsProto        = RegisterProto("Wireshark internal", "_ws", "_ws")
	hfExpert       = wsProto.Field("_ws.expert", "Expert Info", FtNone)
	hfExpertMsg    = wsProto.Field("_ws.expert.message", "Message", FtString)
	hfExpertSev    = wsProto.Field("_ws.expert.severity", "Severity level", FtUint32, WithVS(sevVS), WithBase(BaseNone))
	hfExpertGroup  = wsProto.Field("_ws.expert.group", "Group", FtUint32, WithVS(groupVS()), WithBase(BaseNone))
	malformedProto = RegisterProto("Malformed Packet", "Malformed", "_ws.malformed")
	shortProto     = RegisterProto("Unreassembled Fragmented Packet", "Short", "_ws.short")
	bugProto       = RegisterProto("Dissector bug", "Bug", "_ws.dissector_bug")
	eiMalformed    = malformedProto.Expert("_ws.malformed.expert", GroupMalformed, SevError, "Malformed Packet (Exception occurred)")
	eiDissectorBug = bugProto.Expert("_ws.dissector_bug.expert", GroupDissectorBug, SevError, "Dissector bug")
	sevVS          = map[uint64]string{uint64(SevComment): "Comment", uint64(SevChat): "Chat", uint64(SevNote): "Note", uint64(SevWarn): "Warning", uint64(SevError): "Error"}
)

func groupVS() map[uint64]string {
	m := map[uint64]string{}
	for g, s := range groupNames {
		m[uint64(g)] = s
	}
	return m
}

// Expert registers an expert info kind for the protocol.
func (p *Proto) Expert(abbrev string, g Group, sev Severity, summary string) *ExpertField {
	f := p.Field(abbrev, summary, FtNone)
	return &ExpertField{F: f, Group: g, Severity: sev, Summary: summary}
}

// AddExpert attaches an expert item under n. An empty format uses the summary.
func (n *Node) AddExpert(e *ExpertField, format string, args ...any) *Node {
	msg := e.Summary
	if format != "" {
		msg = fmt.Sprintf(format, args...)
	}
	t := n.tree
	if pi := t.PI; pi != nil {
		pi.Experts = append(pi.Experts, ExpertEntry{Def: e, Msg: msg, Proto: e.F.Proto})
		if e.Severity > pi.MaxSeverity {
			pi.MaxSeverity = e.Severity
		}
	}
	ds, start, length := n.DS, int(n.Start), int(n.Length)
	if n.IsSink() {
		ds, start, length = 0, 0, 0
	}
	var tvb *Tvb
	if t.full && t.PI != nil && int(ds) < len(t.PI.Sources) {
		tvb = &Tvb{data: t.PI.Sources[ds].Data, reported: len(t.PI.Sources[ds].Data), ds: ds}
		if start+length > len(tvb.data) {
			start, length = 0, 0
		}
	}
	c := n.add(e.F, tvb, start, length, Value{T: FtNone}, NodeExpert|NodeGenerated)
	c.SetText("Expert Info (%s/%s): %s", e.Severity, e.Group, msg)
	if !c.IsSink() {
		c.Expert = &ExpertInfo{Def: e, Msg: msg}
	}
	sub := c
	sub.AddGenerated(hfExpertMsg, Value{S: msg}).SetText("%s", msg)
	sub.AddGenerated(hfExpertSev, Value{U: uint64(e.Severity)})
	sub.AddGenerated(hfExpertGroup, Value{U: uint64(e.Group)})
	if t.Wants(hfExpert) {
		t.Vals = append(t.Vals, FieldVal{F: hfExpert, V: Value{T: FtNone}, Layer: 1})
	}
	return c
}
