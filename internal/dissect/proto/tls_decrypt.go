package proto

import (
	"strings"

	"github.com/poseydon/lazysniffer/internal/decrypt"
	d "github.com/poseydon/lazysniffer/internal/dissect"
	"github.com/poseydon/lazysniffer/internal/keylog"
)

// tlsAppBuf holds decrypted application data waiting for more bytes.
type tlsAppBuf struct {
	pending []byte
	handle  *d.Handle
	chosen  bool
}

// tlsDec is the decryption state of one TLS connection (first pass).
type tlsDec struct {
	d13  [2]*decrypt.TLS13Dir
	ep13 [2]int
	d12  [2]*decrypt.TLS12Dir
	app  [2]tlsAppBuf
}

func init() {
	QUICKeyLookup = func(cr []byte, label string) []byte { return keylog.Default.Lookup(cr, label) }
	TLSDecryptHook = nil
}

func (s *tlsSession) dec() *tlsDec {
	t, _ := s.keys.(*tlsDec)
	if t == nil {
		t = &tlsDec{}
		s.keys = t
	}
	return t
}

var tls13Labels = [2][2]string{
	{"CLIENT_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0"},
	{"SERVER_HANDSHAKE_TRAFFIC_SECRET", "SERVER_TRAFFIC_SECRET_0"},
}

func (s *tlsSession) tls13Keys(dir, epoch int) *decrypt.TLS13Dir {
	sec := keylog.Default.Lookup(s.clientRandom, tls13Labels[dir][epoch])
	if sec == nil {
		return nil
	}
	k, err := decrypt.NewTLS13Dir(s.cipher, sec)
	if err != nil {
		return nil
	}
	return k
}

// decryptRecord decrypts one record body. It returns the plaintext and, for
// TLS 1.3, the inner content type (for TLS 1.2 the record type).
func (s *tlsSession) decryptRecord(dir int, typ byte, ver uint16, hdr, body []byte) (plain []byte, inner byte, ok bool) {
	if s.clientRandom == nil || s.cipher == 0 {
		return nil, 0, false
	}
	t := s.dec()
	if s.tls13() {
		if s.cipher < 0x1301 || s.cipher > 0x1303 || typ != 23 {
			return nil, 0, false
		}
		if t.d13[dir] == nil {
			t.d13[dir] = s.tls13Keys(dir, 0)
			t.ep13[dir] = 0
			if t.d13[dir] == nil {
				return nil, 0, false
			}
		}
		k := t.d13[dir]
		seq := k.Seq
		it, p, err := k.Open(hdr, body)
		if err != nil {
			k.Seq = seq
			// Another epoch: the application keys, or a key update.
			if t.ep13[dir] == 0 {
				if nk := s.tls13Keys(dir, 1); nk != nil {
					if it, p, err = nk.Open(hdr, body); err == nil {
						t.d13[dir], t.ep13[dir] = nk, 1
						return p, it, true
					}
				}
			} else if nk, e := k.Next(); e == nil {
				if it, p, err = nk.Open(hdr, body); err == nil {
					t.d13[dir] = nk
					return p, it, true
				}
			}
			return nil, 0, false
		}
		if t.ep13[dir] == 0 && it == 22 && hasFinished(p) {
			if nk := s.tls13Keys(dir, 1); nk != nil {
				t.d13[dir], t.ep13[dir] = nk, 1
			}
		}
		return p, it, true
	}
	// TLS 1.2 and older
	if !decrypt.TLS12Supported(s.cipher) || s.version < 0x0302 {
		return nil, 0, false
	}
	if t.d12[0] == nil {
		master := keylog.Default.Lookup(s.clientRandom, "CLIENT_RANDOM")
		if master == nil {
			return nil, 0, false
		}
		c, sv, err := decrypt.NewTLS12Keys(s.cipher, master, s.clientRandom, s.serverRandom)
		if err != nil {
			return nil, 0, false
		}
		t.d12[0], t.d12[1] = c, sv
	}
	p, err := t.d12[dir].Open(typ, ver, body)
	if err != nil {
		return nil, 0, false
	}
	return p, typ, true
}

func hasFinished(p []byte) bool {
	for off := 0; off+4 <= len(p); {
		if p[off] == 20 {
			return true
		}
		off += 4 + (int(p[off+1])<<16 | int(p[off+2])<<8 | int(p[off+3]))
	}
	return false
}

// tlsInnerPorts maps ports of TLS-wrapped services to the handle name of
// the protocol inside.
var tlsInnerPorts = map[uint32]string{853: "dns-tcp"}

func (s *tlsSession) chooseApp(pi *d.PacketInfo, data []byte) *d.Handle {
	switch {
	case len(data) >= 4 && string(data[:4]) == "PRI ":
		return FindHandleLazy("http2")
	case s.alpn == "h2":
		return FindHandleLazy("http2")
	case s.alpn == "http/1.1" || s.alpn == "http/1.0":
		return FindHandleLazy("http")
	}
	if n, ok := tlsInnerPorts[pi.DstPort]; ok {
		if h := d.FindHandle(n); h != nil {
			return h
		}
	}
	if n, ok := tlsInnerPorts[pi.SrcPort]; ok {
		if h := d.FindHandle(n); h != nil {
			return h
		}
	}
	if looksLikeHTTP(data) {
		return FindHandleLazy("http")
	}
	return nil
}

// tlsDissectAppData feeds decrypted application data to the protocol
// inside TLS, reassembling across records. It reports whether an
// application dissector produced output.
func tlsDissectAppData(plain []byte, info *tlsRecInfo, pi *d.PacketInfo, tree *d.Node, ctx *tlsFrameCtx, first bool) bool {
	sess := ctx.sess
	t := sess.dec()
	ab := &t.app[ctx.dir]
	var buf []byte
	if pi.Visited {
		buf = info.appBuf
		if buf == nil {
			buf = plain
		}
	} else {
		if len(ab.pending) > 0 {
			buf = append(append([]byte(nil), ab.pending...), plain...)
			info.appBuf = buf
			ab.pending = nil
		} else {
			buf = plain
		}
		if !ab.chosen {
			ab.handle = sess.chooseApp(pi, buf)
			if ab.handle == nil {
				ab.handle = t.app[1-ctx.dir].handle // both directions carry the same protocol
			}
			ab.chosen = ab.handle != nil
		}
	}
	h := ab.handle
	if pi.Visited {
		h = info.appHandle
	} else {
		info.appHandle = h
	}
	if h == nil {
		return false
	}
	name := "Decrypted TLS"
	if len(buf) != len(plain) {
		name = "Reassembled Decrypted TLS"
	}
	tvb := pi.AddSource(name, buf)
	snap := pi.Snapshot(tree)
	ctx.inApp = true
	pi.Call(h, tvb, tree)
	ctx.inApp = false
	off, _, _, need := pi.TakeDesegment()
	if !pi.Visited && need && off < len(buf) && len(buf) < maxReasm {
		ab.pending = append([]byte(nil), buf[off:]...)
		info.appPartial = true
		info.appOff = off
		if off == 0 {
			info.appBuf = nil
		}
	}
	if info.appPartial && info.appOff == 0 {
		// Nothing was complete: show the record as a segment of a larger PDU.
		pi.Rollback(snap)
		tree.SetText("[TLS segment of a reassembled PDU]")
		return false
	}
	return true
}

// setTLSAppHandle redirects the protocol inside TLS (CONNECT, Upgrade).
func setTLSAppHandle(pi *d.PacketInfo, h *d.Handle) bool {
	ctx, _ := pi.Scratch(protoTLS).(*tlsFrameCtx)
	if ctx == nil || !ctx.inApp {
		return false
	}
	if !pi.Visited {
		t := ctx.sess.dec()
		for i := range t.app {
			t.app[i].handle, t.app[i].chosen = h, true
		}
	}
	return true
}

func tlsAppSummary(s string) string { return strings.TrimSpace(s) }
