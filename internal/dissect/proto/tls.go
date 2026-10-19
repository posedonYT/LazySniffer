package proto

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	d "github.com/poseydon/lazysniffer/internal/dissect"
)

var (
	protoTLS = d.RegisterProto("Transport Layer Security", "TLS", "tls")

	hfTLSDecData     = protoTLS.Field("tls.decrypted.data", "Decrypted application data", d.FtBytes)
	hfTLSRecord      = protoTLS.Field("tls.record", "Record Layer", d.FtNone)
	hfTLSContentType = protoTLS.Field("tls.record.content_type", "Content Type", d.FtUint8, d.WithVS(tlsContentTypes))
	hfTLSOpaqueType  = protoTLS.Field("tls.record.opaque_type", "Opaque Type", d.FtUint8, d.WithVS(tlsContentTypes))
	hfTLSRecVersion  = protoTLS.Field("tls.record.version", "Version", d.FtUint16, d.WithBase(d.BaseHex), d.WithVS(tlsVersionVS()))
	hfTLSRecLength   = protoTLS.Field("tls.record.length", "Length", d.FtUint16)
	hfTLSCCS         = protoTLS.Field("tls.change_cipher_spec", "Change Cipher Spec Message", d.FtNone)
	hfTLSAppData     = protoTLS.Field("tls.app_data", "Encrypted Application Data", d.FtBytes)
	hfTLSAppProto    = protoTLS.Field("tls.app_data_proto", "Application Data Protocol", d.FtString)
	hfTLSAlert       = protoTLS.Field("tls.alert_message", "Alert Message", d.FtNone)
	hfTLSAlertLevel  = protoTLS.Field("tls.alert_message.level", "Level", d.FtUint8, d.WithVS(tlsAlertLevels))
	hfTLSAlertDesc   = protoTLS.Field("tls.alert_message.desc", "Description", d.FtUint8, d.WithVS(tlsAlertDescs))
	hfTLSHeartbeat   = protoTLS.Field("tls.heartbeat_message", "Heartbeat Message", d.FtBytes)

	hfHS          = protoTLS.Field("tls.handshake", "Handshake Protocol", d.FtNone)
	hfHSType      = protoTLS.Field("tls.handshake.type", "Handshake Type", d.FtUint8, d.WithVS(tlsHandshakeTypes))
	hfHSLength    = protoTLS.Field("tls.handshake.length", "Length", d.FtUint24)
	hfHSVersion   = protoTLS.Field("tls.handshake.version", "Version", d.FtUint16, d.WithBase(d.BaseHex), d.WithVS(tlsVersionVS()))
	hfHSRandom    = protoTLS.Field("tls.handshake.random", "Random", d.FtBytes)
	hfHSSidLen    = protoTLS.Field("tls.handshake.session_id_length", "Session ID Length", d.FtUint8)
	hfHSSid       = protoTLS.Field("tls.handshake.session_id", "Session ID", d.FtBytes)
	hfHSCookieLen = protoTLS.Field("tls.handshake.cookie_length", "Cookie Length", d.FtUint8)
	hfHSCookie    = protoTLS.Field("tls.handshake.cookie", "Cookie", d.FtBytes)
	hfHSCSLen     = protoTLS.Field("tls.handshake.cipher_suites_length", "Cipher Suites Length", d.FtUint16)
	hfHSCSList    = protoTLS.Field("tls.handshake.ciphersuites", "Cipher Suites", d.FtNone)
	hfHSCS        = protoTLS.Field("tls.handshake.ciphersuite", "Cipher Suite", d.FtUint16, d.WithBase(d.BaseHex), d.WithVS(withGREASE(tlsCiphers)))
	hfHSCompLen   = protoTLS.Field("tls.handshake.comp_methods_length", "Compression Methods Length", d.FtUint8)
	hfHSComp      = protoTLS.Field("tls.handshake.comp_method", "Compression Method", d.FtUint8, d.WithVS(tlsCompressions))
	hfHSExtsLen   = protoTLS.Field("tls.handshake.extensions_length", "Extensions Length", d.FtUint16)
	hfHSExt       = protoTLS.Field("tls.handshake.extension", "Extension", d.FtNone)
	hfHSExtType   = protoTLS.Field("tls.handshake.extension.type", "Type", d.FtUint16, d.WithVS(withGREASE(tlsExtensions)))
	hfHSExtLen    = protoTLS.Field("tls.handshake.extension.len", "Length", d.FtUint16)
	hfHSExtData   = protoTLS.Field("tls.handshake.extension.data", "Data", d.FtBytes)
	hfHSSNIListLn = protoTLS.Field("tls.handshake.extensions_server_name_list_len", "Server Name list length", d.FtUint16)
	hfHSSNIType   = protoTLS.Field("tls.handshake.extensions_server_name_type", "Server Name Type", d.FtUint8, d.WithVS(map[uint64]string{0: "host_name"}))
	hfHSSNILen    = protoTLS.Field("tls.handshake.extensions_server_name_len", "Server Name length", d.FtUint16)
	hfHSSNI       = protoTLS.Field("tls.handshake.extensions_server_name", "Server Name", d.FtString)
	hfHSGroupsLen = protoTLS.Field("tls.handshake.extensions_supported_groups_length", "Supported Groups List Length", d.FtUint16)
	hfHSGroup     = protoTLS.Field("tls.handshake.extensions_supported_group", "Supported Group", d.FtUint16, d.WithBase(d.BaseHex), d.WithVS(withGREASE(tlsGroups)))
	hfHSECPFLen   = protoTLS.Field("tls.handshake.extensions_ec_point_formats_length", "EC point formats Length", d.FtUint8)
	hfHSECPF      = protoTLS.Field("tls.handshake.extensions_ec_point_format", "EC point format", d.FtUint8, d.WithVS(tlsECPointFormats))
	hfHSSigLen    = protoTLS.Field("tls.handshake.sig_hash_alg_len", "Signature Hash Algorithms Length", d.FtUint16)
	hfHSSigAlg    = protoTLS.Field("tls.handshake.sig_hash_alg", "Signature Algorithm", d.FtUint16, d.WithBase(d.BaseHex), d.WithVS(withGREASE(tlsSigAlgs)))
	hfHSALPNLen   = protoTLS.Field("tls.handshake.extensions_alpn_len", "ALPN Extension Length", d.FtUint16)
	hfHSALPNStrLn = protoTLS.Field("tls.handshake.extensions_alpn_str_len", "ALPN string length", d.FtUint8)
	hfHSALPN      = protoTLS.Field("tls.handshake.extensions_alpn_str", "ALPN Next Protocol", d.FtString)
	hfHSSVLen     = protoTLS.Field("tls.handshake.extensions.supported_versions_len", "Supported Versions length", d.FtUint8)
	hfHSSV        = protoTLS.Field("tls.handshake.extensions.supported_version", "Supported Version", d.FtUint16, d.WithBase(d.BaseHex), d.WithVS(tlsVersionVS()))
	hfHSKSLen     = protoTLS.Field("tls.handshake.extensions_key_share_client_length", "Client Key Share Length", d.FtUint16)
	hfHSKSGroup   = protoTLS.Field("tls.handshake.extensions_key_share_group", "Group", d.FtUint16, d.WithBase(d.BaseHex), d.WithVS(withGREASE(tlsGroups)))
	hfHSKSKeyLen  = protoTLS.Field("tls.handshake.extensions_key_share_key_exchange_length", "Key Exchange Length", d.FtUint16)
	hfHSKSKey     = protoTLS.Field("tls.handshake.extensions_key_share_key_exchange", "Key Exchange", d.FtBytes)
	hfHSPSKModes  = protoTLS.Field("tls.extension.psk_ke_mode", "PSK Key Exchange Mode", d.FtUint8, d.WithVS(tlsPSKModes))
	hfHSPSKIdLen  = protoTLS.Field("tls.handshake.extensions.psk.identity.identity_length", "Identity Length", d.FtUint16)
	hfHSPSKId     = protoTLS.Field("tls.handshake.extensions.psk.identity.identity", "Identity", d.FtBytes)
	hfHSPSKAge    = protoTLS.Field("tls.handshake.extensions.psk.identity.obfuscated_ticket_age", "Obfuscated Ticket Age", d.FtUint32)
	hfHSPSKSel    = protoTLS.Field("tls.handshake.extensions.psk.identity.selected", "Selected Identity", d.FtUint16)
	hfHSPadding   = protoTLS.Field("tls.handshake.extensions_padding_data", "Padding Data", d.FtBytes)
	hfHSReneg     = protoTLS.Field("tls.handshake.extensions_reneg_info_len", "Renegotiation info extension length", d.FtUint8)
	hfHSRecSize   = protoTLS.Field("tls.record_size_limit", "Record Size Limit", d.FtUint16)
	hfHSCompCert  = protoTLS.Field("tls.compress_certificate.algorithm", "Algorithm", d.FtUint16, d.WithVS(tlsCertCompression))
	hfHSStatusTyp = protoTLS.Field("tls.handshake.extensions_status_request_type", "Certificate Status Type", d.FtUint8, d.WithVS(map[uint64]string{1: "OCSP", 2: "OCSP Multi"}))
	hfHSTicket    = protoTLS.Field("tls.handshake.extensions.session_ticket", "Session Ticket", d.FtBytes)
	hfHSECHType   = protoTLS.Field("tls.ech.client_hello_type", "Client Hello type", d.FtUint8, d.WithVS(map[uint64]string{0: "Outer Client Hello", 1: "Inner Client Hello"}))
	hfHSECHKDF    = protoTLS.Field("tls.ech.cipher_suite.kdf_id", "KDF Id", d.FtUint16, d.WithVS(map[uint64]string{1: "HKDF-SHA256", 2: "HKDF-SHA384", 3: "HKDF-SHA512"}))
	hfHSECHAEAD   = protoTLS.Field("tls.ech.cipher_suite.aead_id", "AEAD Id", d.FtUint16, d.WithVS(map[uint64]string{1: "AES-128-GCM", 2: "AES-256-GCM", 3: "ChaCha20Poly1305"}))
	hfHSECHCfgID  = protoTLS.Field("tls.ech.config_id", "Config Id", d.FtUint8)
	hfHSECHEnc    = protoTLS.Field("tls.ech.enc", "Enc", d.FtBytes)
	hfHSECHPay    = protoTLS.Field("tls.ech.payload", "Payload", d.FtBytes)
	hfHSHRR       = protoTLS.Field("tls.handshake.hello_retry_request", "Hello Retry Request", d.FtBool)
	hfHSCertsLen  = protoTLS.Field("tls.handshake.certificates_length", "Certificates Length", d.FtUint24)
	hfHSCertLen   = protoTLS.Field("tls.handshake.certificate_length", "Certificate Length", d.FtUint24)
	hfHSCert      = protoTLS.Field("tls.handshake.certificate", "Certificate", d.FtBytes)
	hfHSCertCtx   = protoTLS.Field("tls.handshake.certificate_request_context_length", "Certificate Request Context Length", d.FtUint8)
	hfHSCurveType = protoTLS.Field("tls.handshake.server_curve_type", "Curve Type", d.FtUint8, d.WithVS(map[uint64]string{1: "explicit_prime", 2: "explicit_char2", 3: "named_curve"}))
	hfHSNamedCrv  = protoTLS.Field("tls.handshake.server_named_curve", "Named Curve", d.FtUint16, d.WithBase(d.BaseHex), d.WithVS(tlsGroups))
	hfHSServerPt  = protoTLS.Field("tls.handshake.server_point", "Pubkey", d.FtBytes)
	hfHSClientPt  = protoTLS.Field("tls.handshake.client_point", "Pubkey", d.FtBytes)
	hfHSSig       = protoTLS.Field("tls.handshake.sig", "Signature", d.FtBytes)
	hfHSEPMS      = protoTLS.Field("tls.handshake.epms", "Encrypted PreMaster", d.FtBytes)
	hfHSDHp       = protoTLS.Field("tls.handshake.p", "p", d.FtBytes)
	hfHSDHg       = protoTLS.Field("tls.handshake.g", "g", d.FtBytes)
	hfHSDHYs      = protoTLS.Field("tls.handshake.ys", "Pubkey", d.FtBytes)
	hfHSTktHint   = protoTLS.Field("tls.handshake.session_ticket_lifetime_hint", "Session Ticket Lifetime Hint", d.FtUint32, d.WithUnit("seconds"))
	hfHSTktAgeAdd = protoTLS.Field("tls.handshake.session_ticket_age_add", "Session Ticket Age Add", d.FtUint32)
	hfHSTktNonce  = protoTLS.Field("tls.handshake.session_ticket_nonce", "Session Ticket Nonce", d.FtBytes)
	hfHSTktLen    = protoTLS.Field("tls.handshake.session_ticket_length", "Session Ticket Length", d.FtUint16)
	hfHSTkt       = protoTLS.Field("tls.handshake.session_ticket", "Session Ticket", d.FtBytes)
	hfHSVerify    = protoTLS.Field("tls.handshake.verify_data", "Verify Data", d.FtBytes)
	hfHSKeyUpdate = protoTLS.Field("tls.handshake.key_update.request_update", "KeyUpdateRequest", d.FtUint8, d.WithVS(map[uint64]string{0: "update_not_requested", 1: "update_requested"}))
	hfHSData      = protoTLS.Field("tls.handshake.data", "Handshake data", d.FtBytes)
	hfHSJA3       = protoTLS.Field("tls.handshake.ja3", "JA3", d.FtString)
	hfHSJA3Full   = protoTLS.Field("tls.handshake.ja3_full", "JA3 Fullstring", d.FtString)
	hfHSJA3S      = protoTLS.Field("tls.handshake.ja3s", "JA3S", d.FtString)
	hfHSJA3SFull  = protoTLS.Field("tls.handshake.ja3s_full", "JA3S Fullstring", d.FtString)
	hfHSJA4       = protoTLS.Field("tls.handshake.ja4", "JA4", d.FtString)
	hfHSJA4R      = protoTLS.Field("tls.handshake.ja4_r", "JA4_r", d.FtString)
	hfHSJA4S      = protoTLS.Field("tls.handshake.ja4s", "JA4S", d.FtString)
	hfHSJA4SR     = protoTLS.Field("tls.handshake.ja4s_r", "JA4S_r", d.FtString)
	hfTLSReasmIn  = protoTLS.Field("tls.handshake.reassembled_in", "Reassembled TLS handshake in frame", d.FtFrameNum)
	hfTLSFragment = protoTLS.Field("tls.handshake.fragment", "Handshake fragment", d.FtBytes)
	eiTLSIgnored  = protoTLS.Expert("tls.ignored_unknown_record", d.GroupProtocol, d.SevWarn, "Ignored Unknown Record")
	eiTLSCertExp  = protoTLS.Expert("tls.handshake.certificate.expired", d.GroupSecurity, d.SevWarn, "Certificate has expired")
	eiTLSWeak     = protoTLS.Expert("tls.handshake.weak_version", d.GroupSecurity, d.SevNote, "Obsolete protocol version")

	tlsHandle = d.RegisterHandle("tls", d.NewHandle(protoTLS, dissectTLSStream))
)

// TLSPorts are TCP ports where TLS is expected without heuristics.
var TLSPorts = []uint64{443, 465, 563, 585, 614, 636, 853, 989, 990, 992, 993, 994, 995, 1443, 2083, 2087, 2096, 3269, 4433, 5061, 5223, 5349, 6697, 8443, 8883, 9443, 10443}

func init() {
	for _, p := range TLSPorts {
		TCPPortTable.Add(p, tlsHandle)
	}
	TCPHeur.Add("tls_tcp", protoTLS, func(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) bool {
		if !looksLikeTLS(tvb) {
			return false
		}
		dissectTLSStream(tvb, pi, tree)
		return true
	})
}

func looksLikeTLS(tvb *d.Tvb) bool {
	if tvb.Len() < 5 {
		return false
	}
	t, maj, min, l := tvb.U8(0), tvb.U8(1), tvb.U8(2), tvb.U16(3)
	if t < 20 || t > 24 || maj != 3 || min > 4 || l == 0 || l > 18432 {
		return false
	}
	if t == 22 && tvb.Len() >= 6 {
		hs := tvb.U8(5)
		return hs == 1 || hs == 2 || hs == 11 || hs == 4 || hs == 16 || hs == 12 || hs == 14
	}
	return true
}

// tlsSession is per-connection TLS state.
type tlsSession struct {
	version      uint16 // negotiated version (0 until the Server Hello)
	cipher       uint16
	clientRandom []byte
	serverRandom []byte
	sni          string
	alpn         string
	clientALPN   []string
	ccs          [2]bool // Change Cipher Spec seen per direction
	hs           [2]hsReasm
	keys         any // decryption state (set by the decryptor)
}

// TLSSessionInfo is the public view of a TLS connection.
type TLSSessionInfo struct {
	Version      uint16
	Cipher       uint16
	ClientRandom []byte
	ServerRandom []byte
	SNI          string
	ALPN         string
}

// hsReasm reassembles handshake messages spanning records (first pass).
type hsReasm struct {
	pending []d.FragRef
	have    int
	need    int // total message size; -1 while the header is incomplete
	recs    []*tlsRecInfo
}

// tlsRecInfo is stored per record in the first pass.
type tlsRecInfo struct {
	encrypted  bool
	reasm      *d.Reassembled // a message completed with bytes of this record
	directFrom int            // first byte of complete messages in this record
	directTo   int            // end of complete messages (start of an unfinished one)
	partial    bool           // the whole record belongs to an unfinished message
	in         uint32         // frame where the unfinished message completed
	version    uint16         // session version at this record

	// Decryption (first pass results, reused by later passes).
	tried      bool
	dec        bool   // the record was decrypted
	plain      []byte // plaintext (TLS 1.3: without the inner type and padding)
	inner      byte   // content type of the plaintext
	appBuf     []byte // reassembled application data passed to the inner dissector
	appHandle  *d.Handle
	appPartial bool // inner dissector wants more data
	appOff     int  // bytes of the data the dissector consumed before asking for more
}

type tlsFrameCtx struct {
	rec   int
	node  *d.Node
	infos []string
	sess  *tlsSession
	dir   int
	inApp bool // an inner (decrypted) dissector is running
	app   bool // an inner dissector produced the Info column
}

func tlsSessionOf(pi *d.PacketInfo) (*tlsSession, int) {
	dir := 0
	if ti := CurrentTCP(pi); ti != nil && !ti.FromA {
		dir = 1
	} else if pi.Conv != nil && !pi.Conv.FromA(pi.Src, pi.SrcPort) {
		dir = 1
	}
	if pi.Conv == nil {
		return &tlsSession{}, dir
	}
	s, _ := pi.Conv.Data(protoTLS).(*tlsSession)
	if s == nil {
		s = &tlsSession{}
		if !pi.Visited {
			pi.Conv.SetData(protoTLS, s)
		}
	}
	return s, dir
}

// TLSSession returns the TLS state of the frame's connection, if any.
func TLSSession(pi *d.PacketInfo) *TLSSessionInfo {
	if pi.Conv == nil {
		return nil
	}
	s, _ := pi.Conv.Data(protoTLS).(*tlsSession)
	if s == nil {
		return nil
	}
	return &TLSSessionInfo{Version: s.version, Cipher: s.cipher, ClientRandom: s.clientRandom, ServerRandom: s.serverRandom, SNI: s.sni, ALPN: s.alpn}
}

// dissectTLSStream splits a TCP payload into TLS records.
func dissectTLSStream(tvb *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
	if tvb.Len() >= 5 && !looksLikeTLSRecordHeader(tvb) {
		return 0
	}
	ctx, _ := pi.Scratch(protoTLS).(*tlsFrameCtx)
	if ctx == nil {
		s, dir := tlsSessionOf(pi)
		ctx = &tlsFrameCtx{sess: s, dir: dir}
		pi.SetScratch(protoTLS, ctx)
	}
	n := TCPDissectPDUs(tvb, pi, tree, 5, func(tvb *d.Tvb, off int) int {
		return 5 + int(tvb.U16(off+3))
	}, func(rec *d.Tvb, pi *d.PacketInfo, tree *d.Node) int {
		dissectTLSRecord(rec, pi, tree, ctx)
		return rec.Len()
	})
	if len(ctx.infos) > 0 && !ctx.app {
		pi.SetInfo(strings.Join(ctx.infos, ", "))
	}
	return max(n, 1)
}

func looksLikeTLSRecordHeader(tvb *d.Tvb) bool {
	t, maj := tvb.U8(0), tvb.U8(1)
	return t >= 20 && t <= 26 && (maj == 3 || maj == 0xfe)
}

func versionShort(v uint16) string {
	if s, ok := tlsShortVersions[v]; ok {
		return s
	}
	return "TLS"
}

func (s *tlsSession) tls13() bool {
	return s.version == 0x0304 || (s.version >= 0x7f0e && s.version <= 0x7f1c)
}

func dissectTLSRecord(rec *d.Tvb, pi *d.PacketInfo, tree *d.Node, ctx *tlsFrameCtx) {
	sess := ctx.sess
	typ := uint64(rec.U8(0))
	ver := rec.U16(1)
	l := int(rec.U16(3))
	recIdx := ctx.rec
	ctx.rec++
	key := uint32(1000 + recIdx)
	var info *tlsRecInfo
	if pi.Visited {
		info, _ = pi.Sess.FrameData(protoTLS, pi.Num, key).(*tlsRecInfo)
	}
	if info == nil {
		info = &tlsRecInfo{directTo: l, version: sess.version}
		switch typ {
		case 22:
			info.encrypted = sess.ccs[ctx.dir] || (sess.tls13() && sess.serverRandom != nil && !isHRRSession(sess))
		case 21:
			info.encrypted = (sess.ccs[ctx.dir] && !sess.tls13()) || l != 2
		}
		if !pi.Visited {
			pi.Sess.SetFrameData(protoTLS, pi.Num, key, info)
		}
	}
	shown := info.version
	if shown == 0 {
		shown = sess.version
	}
	if shown == 0 {
		shown = ver
	}
	if ctx.node == nil {
		ctx.node = tree.AddProtocol(protoTLS, rec, 0, -1)
	}
	pi.SetProtocol(versionShort(shown))
	rt := ctx.node.AddValue(hfTLSRecord, rec, 0, rec.Len(), d.Value{})
	if sess.tls13() && typ == 23 {
		rt.AddUint(hfTLSOpaqueType, rec, 0, 1)
		if info.dec {
			rt.AddGenerated(hfTLSContentType, d.UintValue(d.FtUint8, uint64(info.inner)))
		}
	} else {
		rt.AddUint(hfTLSContentType, rec, 0, 1)
	}
	rt.AddUint(hfTLSRecVersion, rec, 1, 2)
	rt.AddUint(hfTLSRecLength, rec, 3, 2)
	body := rec.Sub(5, l)
	etyp, ebody := typ, body
	if !pi.Visited && !info.tried {
		info.tried = true
		if (sess.tls13() && typ == 23) || (!sess.tls13() && sess.ccs[ctx.dir] && typ >= 21 && typ <= 23) {
			if plain, inner, ok := sess.decryptRecord(ctx.dir, byte(typ), ver, rec.Bytes(0, 5), body.Bytes(0, body.Len())); ok {
				info.dec, info.plain, info.inner = true, plain, inner
			}
		}
	}
	encrypted := info.encrypted
	if info.dec {
		etyp, encrypted = uint64(info.inner), false
		ebody = pi.AddSource("Decrypted TLS", info.plain)
	}
	label := versionShort(shown) + " Record Layer: "
	switch etyp {
	case 20:
		rt.AddValue(hfTLSCCS, body, 0, body.Len(), d.Value{})
		if !pi.Visited {
			sess.ccs[ctx.dir] = true
		}
		label += "Change Cipher Spec Protocol: Change Cipher Spec"
		ctx.infos = append(ctx.infos, "Change Cipher Spec")
	case 21:
		if encrypted {
			rt.AddBytes(hfTLSAppData, body, 0, body.Len())
			label += "Encrypted Alert"
			ctx.infos = append(ctx.infos, "Encrypted Alert")
			break
		}
		an := rt.AddValue(hfTLSAlert, ebody, 0, 2, d.Value{})
		_, lv := an.AddUint(hfTLSAlertLevel, ebody, 0, 1)
		_, ds := an.AddUint(hfTLSAlertDesc, ebody, 1, 1)
		label += fmt.Sprintf("Alert (Level: %s, Description: %s)", tlsAlertLevels[lv], tlsAlertDescs[ds])
		an.SetText("Alert Message")
		ctx.infos = append(ctx.infos, fmt.Sprintf("Alert (Level: %s, Description: %s)", tlsAlertLevels[lv], tlsAlertDescs[ds]))
	case 22:
		if encrypted {
			en, _ := rt.AddBytes(hfHSData, body, 0, body.Len())
			en.SetText("Handshake Protocol: Encrypted Handshake Message")
			label += "Handshake Protocol: Encrypted Handshake Message"
			ctx.infos = append(ctx.infos, "Encrypted Handshake Message")
			break
		}
		names := tlsHandshakeRecord(ebody, pi, rt, ctx, info)
		label += "Handshake Protocol: " + strings.Join(names, ", ")
		if len(names) == 0 {
			label += "(fragment)"
		}
	case 23:
		rt.AddBytes(hfTLSAppData, body, 0, body.Len())
		if sess.alpn != "" {
			rt.AddGenerated(hfTLSAppProto, d.StringValue(alpnProtoName(sess.alpn)))
		}
		label += "Application Data Protocol: " + orDefault(alpnProtoName(sess.alpn), "Application Data")
		handled := false
		if info.dec {
			rt.AddGenerated(hfTLSDecData, d.BytesValue(d.FtBytes, info.plain)).SetHidden()
			dn := rt.AddText(ebody, 0, ebody.Len(), "Decrypted Application Data (%d bytes)", ebody.Len())
			handled = tlsDissectAppData(info.plain, info, pi, dn, ctx, true)
			if handled {
				ctx.app = true
			}
		}
		if !handled {
			if info.dec && info.appPartial && info.appOff == 0 {
				ctx.infos = append(ctx.infos, "[TLS segment of a reassembled PDU]")
			} else {
				ctx.infos = append(ctx.infos, "Application Data")
			}
		}
	case 24:
		rt.AddBytes(hfTLSHeartbeat, body, 0, body.Len())
		label += "Heartbeat"
		ctx.infos = append(ctx.infos, "Heartbeat")
	default:
		rt.AddExpert(eiTLSIgnored, "")
		label += "Ignored Unknown Record"
	}
	rt.SetText("%s", label)
}

// TLSDecryptHook is set by the decryption package to decrypt application data.
var TLSDecryptHook func(body *d.Tvb, pi *d.PacketInfo, tree *d.Node, sess any, dir int)

func alpnProtoName(a string) string {
	switch a {
	case "h2":
		return "HTTP2"
	case "http/1.1", "http/1.0":
		return "HTTP"
	case "h3":
		return "HTTP3"
	case "dot":
		return "DNS"
	case "imap":
		return "IMAP"
	case "pop3":
		return "POP"
	case "smb":
		return "SMB"
	case "mqtt":
		return "MQTT"
	}
	return a
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func isHRRSession(s *tlsSession) bool { return bytes.Equal(s.serverRandom, hrrRandom) }

// tlsHandshakeRecord handles one plaintext handshake record, with message
// reassembly across records. It returns the message names for the label.
func tlsHandshakeRecord(body *d.Tvb, pi *d.PacketInfo, rt *d.Node, ctx *tlsFrameCtx, info *tlsRecInfo) []string {
	sess := ctx.sess
	l := body.Len()
	if !pi.Visited {
		r := &sess.hs[ctx.dir]
		pos := 0
		if r.pending != nil {
			if r.need < 0 && r.have+l >= 4 {
				hdr := append(pi.Sess.Assemble(r.pending, r.have), body.Bytes(0, 4-r.have)...)
				r.need = 4 + (int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3]))
			}
			take := l
			if r.need >= 0 {
				take = min(l, r.need-r.have)
			}
			r.pending = append(r.pending, pi.Ref(body, 0, take, r.have))
			r.have += take
			pos = take
			if r.need < 0 || r.have < r.need {
				info.partial = true
				info.directFrom, info.directTo = l, l
				r.recs = append(r.recs, info)
				return nil
			}
			info.reasm = &d.Reassembled{Frags: r.pending, Total: r.need}
			for _, ri := range r.recs {
				ri.in = pi.Num
			}
			*r = hsReasm{}
		}
		info.directFrom = pos
		for pos < l {
			if l-pos < 4 {
				break
			}
			ml := 4 + int(body.U24(pos+1))
			if pos+ml > l {
				break
			}
			pos += ml
		}
		info.directTo = pos
		if pos < l {
			r.pending = []d.FragRef{pi.Ref(body, pos, l-pos, 0)}
			r.have = l - pos
			r.need = -1
			if l-pos >= 4 {
				r.need = 4 + int(body.U24(pos+1))
			}
			r.recs = []*tlsRecInfo{info}
		}
	}

	var names []string
	if info.partial {
		fr, _ := rt.AddBytes(hfTLSFragment, body, 0, l)
		fr.SetText("Handshake Fragment (%d bytes)", l)
		if info.in != 0 {
			rt.AddGenerated(hfTLSReasmIn, d.Value{U: uint64(info.in)}).SetLink(info.in)
		}
		return nil
	}
	if info.reasm != nil {
		buf := pi.Sess.Assemble(info.reasm.Frags, info.reasm.Total)
		mt := pi.AddSource("Reassembled TLS Handshake", buf)
		names = append(names, dissectHandshakeMsg(mt, pi, rt, ctx.sess, ctx.dir, "t", &ctx.infos))
	}
	for pos := info.directFrom; pos < info.directTo; {
		ml := 4 + int(body.U24(pos+1))
		names = append(names, dissectHandshakeMsg(body.Sub(pos, ml), pi, rt, ctx.sess, ctx.dir, "t", &ctx.infos))
		pos += ml
	}
	if info.directTo < l {
		fr, _ := rt.AddBytes(hfTLSFragment, body, info.directTo, l-info.directTo)
		fr.SetText("Handshake Fragment (%d bytes)", l-info.directTo)
		if info.in != 0 {
			rt.AddGenerated(hfTLSReasmIn, d.Value{U: uint64(info.in)}).SetLink(info.in)
		}
	}
	return names
}

var hrrRandom, _ = hex.DecodeString("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")

// helloInfo collects fingerprint inputs from a Client or Server Hello.
type helloInfo struct {
	legacyVersion uint16
	ciphers       []uint16
	exts          []uint16
	groups        []uint16
	pointFormats  []uint8
	sigAlgs       []uint16
	versions      []uint16
	alpn          []string
	sni           string
	ech           bool
}

// dissectHandshakeMsg dissects one handshake message (type, 3-byte length,
// body). transport is "t", "q" (QUIC) or "d" (DTLS) for JA4.
func dissectHandshakeMsg(m *d.Tvb, pi *d.PacketInfo, parent *d.Node, sess *tlsSession, dir int, transport string, infos *[]string) string {
	typ := uint64(m.U8(0))
	ml := int(m.U24(1))
	name := tlsHandshakeTypes[typ]
	if name == "" {
		name = fmt.Sprintf("Unknown (%d)", typ)
	}
	off := 4
	if transport == "d" {
		off = 12
	}
	if typ == 2 && m.Has(off+2, 32) && bytes.Equal(m.Bytes(off+2, 32), hrrRandom) {
		name = "Hello Retry Request"
	}
	ht := parent.AddValue(hfHS, m, 0, m.Len(), d.Value{})
	ht.SetText("Handshake Protocol: %s", name)
	ht.AddUint(hfHSType, m, 0, 1)
	ht.AddUint(hfHSLength, m, 1, 3)
	b := m.Sub(off, min(ml, m.Remaining(off)))
	info := name
	switch typ {
	case 1:
		h := dissectClientHello(b, pi, ht, sess, transport)
		if h.sni != "" {
			info += " (SNI=" + h.sni + ")"
		}
	case 2:
		dissectServerHello(b, pi, ht, sess, transport, name == "Hello Retry Request")
	case 11:
		dissectCertificate(b, pi, ht, sess)
	case 12:
		dissectServerKeyExchange(b, ht, sess)
	case 16:
		dissectClientKeyExchange(b, ht)
	case 4:
		dissectNewSessionTicket(b, ht, sess)
	case 8:
		if b.Len() >= 2 {
			h := &helloInfo{}
			dissectExtensions(b, 0, pi, ht, sess, h, false)
			if !pi.Visited && len(h.alpn) > 0 {
				sess.alpn = h.alpn[0]
			}
		}
	case 20:
		ht.AddBytes(hfHSVerify, b, 0, b.Len())
	case 24:
		if b.Len() >= 1 {
			ht.AddUint(hfHSKeyUpdate, b, 0, 1)
		}
	case 14, 0, 5:
	default:
		if b.Len() > 0 {
			ht.AddBytes(hfHSData, b, 0, b.Len())
		}
	}
	*infos = append(*infos, info)
	return name
}

func readList8(b *d.Tvb, off int) (int, int) { return int(b.U8(off)), off + 1 }

func dissectClientHello(b *d.Tvb, pi *d.PacketInfo, ht *d.Node, sess *tlsSession, transport string) *helloInfo {
	h := &helloInfo{}
	_, v := ht.AddUint(hfHSVersion, b, 0, 2)
	h.legacyVersion = uint16(v)
	ht.AddBytes(hfHSRandom, b, 2, 32)
	if !pi.Visited {
		sess.clientRandom = append([]byte(nil), b.Bytes(2, 32)...)
	}
	off := 34
	sl, _ := readList8(b, off)
	ht.AddUint(hfHSSidLen, b, off, 1)
	if sl > 0 {
		ht.AddBytes(hfHSSid, b, off+1, sl)
	}
	off += 1 + sl
	if transport == "d" {
		cl := int(b.U8(off))
		ht.AddUint(hfHSCookieLen, b, off, 1)
		if cl > 0 {
			ht.AddBytes(hfHSCookie, b, off+1, cl)
		}
		off += 1 + cl
	}
	csl := int(b.U16(off))
	ht.AddUint(hfHSCSLen, b, off, 2)
	cn := ht.AddValue(hfHSCSList, b, off+2, csl, d.Value{})
	cn.SetText("Cipher Suites (%d suites)", csl/2)
	for p := off + 2; p+2 <= off+2+csl; p += 2 {
		_, c := cn.AddUint(hfHSCS, b, p, 2)
		h.ciphers = append(h.ciphers, uint16(c))
	}
	off += 2 + csl
	cml := int(b.U8(off))
	ht.AddUint(hfHSCompLen, b, off, 1)
	cmn := ht.AddText(b, off+1, cml, "Compression Methods (%d method%s)", cml, plural(cml))
	for p := off + 1; p < off+1+cml; p++ {
		cmn.AddUint(hfHSComp, b, p, 1)
	}
	off += 1 + cml
	if b.Remaining(off) >= 2 {
		dissectExtensions(b, off, pi, ht, sess, h, true)
	}
	if !pi.Visited {
		sess.sni = h.sni
		sess.clientALPN = h.alpn
	}
	ja3Full := ja3String(h)
	ht.AddGenerated(hfHSJA3Full, d.StringValue(ja3Full))
	ht.AddGenerated(hfHSJA3, d.StringValue(md5hex(ja3Full)))
	ja4, ja4r := ja4Strings(h, transport)
	ht.AddGenerated(hfHSJA4, d.StringValue(ja4))
	ht.AddGenerated(hfHSJA4R, d.StringValue(ja4r))
	return h
}

func dissectServerHello(b *d.Tvb, pi *d.PacketInfo, ht *d.Node, sess *tlsSession, transport string, hrr bool) {
	h := &helloInfo{}
	_, v := ht.AddUint(hfHSVersion, b, 0, 2)
	h.legacyVersion = uint16(v)
	ht.AddBytes(hfHSRandom, b, 2, 32)
	if hrr {
		ht.AddGenerated(hfHSHRR, d.BoolValue(true))
	}
	off := 34
	sl := int(b.U8(off))
	ht.AddUint(hfHSSidLen, b, off, 1)
	if sl > 0 {
		ht.AddBytes(hfHSSid, b, off+1, sl)
	}
	off += 1 + sl
	_, cs := ht.AddUint(hfHSCS, b, off, 2)
	h.ciphers = []uint16{uint16(cs)}
	ht.AddUint(hfHSComp, b, off+2, 1)
	off += 3
	if b.Remaining(off) >= 2 {
		dissectExtensions(b, off, pi, ht, sess, h, false)
	}
	if !pi.Visited && !hrr {
		sess.serverRandom = append([]byte(nil), b.Bytes(2, 32)...)
		sess.cipher = uint16(cs)
		sess.version = h.legacyVersion
		if len(h.versions) > 0 {
			sess.version = h.versions[0]
		}
		if len(h.alpn) > 0 {
			sess.alpn = h.alpn[0]
		}
	}
	if !pi.Visited && hrr {
		sess.serverRandom = append([]byte(nil), b.Bytes(2, 32)...)
	}
	ver := h.legacyVersion
	if len(h.versions) > 0 {
		ver = h.versions[0]
	}
	if ver < 0x0303 && ver >= 0x0300 {
		ht.AddExpert(eiTLSWeak, "%s is obsolete and insecure", tlsVersions[uint64(ver)])
	}
	full := fmt.Sprintf("%d,%d,%s", h.legacyVersion, cs, joinU16(h.exts))
	ht.AddGenerated(hfHSJA3SFull, d.StringValue(full))
	ht.AddGenerated(hfHSJA3S, d.StringValue(md5hex(full)))
	ja4s, ja4sr := ja4sStrings(h, transport, uint16(cs))
	ht.AddGenerated(hfHSJA4S, d.StringValue(ja4s))
	ht.AddGenerated(hfHSJA4SR, d.StringValue(ja4sr))
}

func dissectExtensions(b *d.Tvb, off int, pi *d.PacketInfo, ht *d.Node, sess *tlsSession, h *helloInfo, client bool) {
	el := int(b.U16(off))
	ht.AddUint(hfHSExtsLen, b, off, 2)
	end := min(off+2+el, b.Len())
	for p := off + 2; p+4 <= end; {
		typ := b.U16(p)
		l := int(b.U16(p + 2))
		name := tlsName(tlsExtensions, typ)
		en := ht.AddValue(hfHSExt, b, p, min(4+l, end-p), d.Value{})
		en.SetText("Extension: %s (len=%d)", name, l)
		en.AddUint(hfHSExtType, b, p, 2)
		en.AddUint(hfHSExtLen, b, p+2, 2)
		v := p + 4
		if h != nil {
			h.exts = append(h.exts, typ)
		}
		if v+l > b.Len() {
			break
		}
		ev := b.Sub(v, l)
		dissectExtension(typ, ev, pi, en, sess, h, client)
		p = v + l
	}
}

func dissectExtension(typ uint16, ev *d.Tvb, pi *d.PacketInfo, en *d.Node, sess *tlsSession, h *helloInfo, client bool) {
	l := ev.Len()
	switch typ {
	case 0:
		if l == 0 {
			return
		}
		en.AddUint(hfHSSNIListLn, ev, 0, 2)
		for p := 2; p+3 <= l; {
			en.AddUint(hfHSSNIType, ev, p, 1)
			nl := int(ev.U16(p + 1))
			en.AddUint(hfHSSNILen, ev, p+1, 2)
			_, name := en.AddString(hfHSSNI, ev, p+3, nl)
			if h != nil && h.sni == "" {
				h.sni = name
			}
			en.AppendText(" name=%s", name)
			p += 3 + nl
		}
	case 10:
		gl := int(ev.U16(0))
		en.AddUint(hfHSGroupsLen, ev, 0, 2)
		for p := 2; p+2 <= 2+gl && p+2 <= l; p += 2 {
			_, g := en.AddUint(hfHSGroup, ev, p, 2)
			if h != nil && !isGREASE(uint16(g)) {
				h.groups = append(h.groups, uint16(g))
			}
		}
	case 11:
		n := int(ev.U8(0))
		en.AddUint(hfHSECPFLen, ev, 0, 1)
		for p := 1; p < 1+n && p < l; p++ {
			_, f := en.AddUint(hfHSECPF, ev, p, 1)
			if h != nil {
				h.pointFormats = append(h.pointFormats, uint8(f))
			}
		}
	case 13, 50:
		sl := int(ev.U16(0))
		en.AddUint(hfHSSigLen, ev, 0, 2)
		for p := 2; p+2 <= 2+sl && p+2 <= l; p += 2 {
			_, s := en.AddUint(hfHSSigAlg, ev, p, 2)
			if h != nil && typ == 13 && !isGREASE(uint16(s)) {
				h.sigAlgs = append(h.sigAlgs, uint16(s))
			}
		}
	case 16:
		en.AddUint(hfHSALPNLen, ev, 0, 2)
		var protos []string
		for p := 2; p < l; {
			sl := int(ev.U8(p))
			en.AddUint(hfHSALPNStrLn, ev, p, 1)
			_, s := en.AddString(hfHSALPN, ev, p+1, sl)
			protos = append(protos, s)
			p += 1 + sl
		}
		if h != nil {
			h.alpn = protos
		}
	case 43:
		if client {
			n := int(ev.U8(0))
			en.AddUint(hfHSSVLen, ev, 0, 1)
			for p := 1; p+2 <= 1+n && p+2 <= l; p += 2 {
				_, v := en.AddUint(hfHSSV, ev, p, 2)
				if h != nil && !isGREASE(uint16(v)) {
					h.versions = append(h.versions, uint16(v))
				}
			}
		} else if l >= 2 {
			_, v := en.AddUint(hfHSSV, ev, 0, 2)
			if h != nil {
				h.versions = []uint16{uint16(v)}
			}
		}
	case 51:
		switch {
		case client:
			en.AddUint(hfHSKSLen, ev, 0, 2)
			for p := 2; p+4 <= l; {
				kl := int(ev.U16(p + 2))
				ks := en.AddText(ev, p, 4+kl, "Key Share Entry: Group: %s, Key Exchange length: %d", tlsName(tlsGroups, ev.U16(p)), kl)
				ks.AddUint(hfHSKSGroup, ev, p, 2)
				ks.AddUint(hfHSKSKeyLen, ev, p+2, 2)
				if kl > 0 {
					ks.AddBytes(hfHSKSKey, ev, p+4, kl)
				}
				p += 4 + kl
			}
		case l == 2:
			en.AddUint(hfHSKSGroup, ev, 0, 2) // Hello Retry Request
		case l >= 4:
			kl := int(ev.U16(2))
			ks := en.AddText(ev, 0, 4+kl, "Key Share Entry: Group: %s, Key Exchange length: %d", tlsName(tlsGroups, ev.U16(0)), kl)
			ks.AddUint(hfHSKSGroup, ev, 0, 2)
			ks.AddUint(hfHSKSKeyLen, ev, 2, 2)
			ks.AddBytes(hfHSKSKey, ev, 4, kl)
		}
	case 45:
		n := int(ev.U8(0))
		for p := 1; p < 1+n && p < l; p++ {
			en.AddUint(hfHSPSKModes, ev, p, 1)
		}
	case 41:
		if !client {
			if l >= 2 {
				en.AddUint(hfHSPSKSel, ev, 0, 2)
			}
			return
		}
		il := int(ev.U16(0))
		for p := 2; p+2 <= 2+il; {
			idl := int(ev.U16(p))
			en.AddUint(hfHSPSKIdLen, ev, p, 2)
			en.AddBytes(hfHSPSKId, ev, p+2, idl)
			en.AddUint(hfHSPSKAge, ev, p+2+idl, 4)
			p += 2 + idl + 4
		}
	case 21:
		if l > 0 {
			en.AddBytes(hfHSPadding, ev, 0, l)
		}
	case 65281:
		if l >= 1 {
			en.AddUint(hfHSReneg, ev, 0, 1)
		}
	case 28:
		if l >= 2 {
			en.AddUint(hfHSRecSize, ev, 0, 2)
		}
	case 27:
		n := int(ev.U8(0))
		for p := 1; p+2 <= 1+n && p+2 <= l; p += 2 {
			en.AddUint(hfHSCompCert, ev, p, 2)
		}
	case 5:
		if l >= 1 {
			en.AddUint(hfHSStatusTyp, ev, 0, 1)
		}
	case 35:
		if l > 0 {
			en.AddBytes(hfHSTicket, ev, 0, l)
		}
	case 65037:
		if h != nil {
			h.ech = true
		}
		if l < 1 {
			return
		}
		_, ct := en.AddUint(hfHSECHType, ev, 0, 1)
		if ct == 0 && l >= 10 {
			en.AddUint(hfHSECHKDF, ev, 1, 2)
			en.AddUint(hfHSECHAEAD, ev, 3, 2)
			en.AddUint(hfHSECHCfgID, ev, 5, 1)
			encl := int(ev.U16(6))
			en.AddBytes(hfHSECHEnc, ev, 8, encl)
			pl := int(ev.U16(8 + encl))
			en.AddBytes(hfHSECHPay, ev, 10+encl, pl)
		}
	case 57, 65445:
		if QUICTransportParams != nil {
			QUICTransportParams(ev, en)
			return
		}
		fallthrough
	default:
		if l > 0 {
			en.AddBytes(hfHSExtData, ev, 0, l)
		}
	}
}

// QUICTransportParams is set by the QUIC dissector.
var QUICTransportParams func(ev *d.Tvb, en *d.Node)

func dissectCertificate(b *d.Tvb, pi *d.PacketInfo, ht *d.Node, sess *tlsSession) {
	off := 0
	tls13 := sess.tls13()
	if tls13 {
		cl := int(b.U8(0))
		ht.AddUint(hfHSCertCtx, b, 0, 1)
		off = 1 + cl
	}
	total := int(b.U24(off))
	ht.AddUint(hfHSCertsLen, b, off, 3)
	ct := ht.AddText(b, off+3, total, "Certificates (%d bytes)", total)
	end := min(off+3+total, b.Len())
	for p := off + 3; p+3 <= end; {
		cl := int(b.U24(p))
		ct.AddUint(hfHSCertLen, b, p, 3)
		cn, der := ct.AddBytes(hfHSCert, b, p+3, cl)
		describeCertificate(cn, der, pi.TS)
		p += 3 + cl
		if tls13 && p+2 <= end {
			el := int(b.U16(p))
			if el > 0 {
				dissectExtensions(b, p, pi, ct, sess, nil, false)
			}
			p += 2 + el
		}
	}
}

func dissectServerKeyExchange(b *d.Tvb, ht *d.Node, sess *tlsSession) {
	if b.Len() < 4 {
		return
	}
	// Distinguish ECDHE (curve type 3) from DHE by the first byte.
	if b.U8(0) == 3 {
		ht.AddUint(hfHSCurveType, b, 0, 1)
		ht.AddUint(hfHSNamedCrv, b, 1, 2)
		pl := int(b.U8(3))
		ht.AddBytes(hfHSServerPt, b, 4, pl)
		p := 4 + pl
		if b.Remaining(p) >= 4 {
			ht.AddUint(hfHSSigAlg, b, p, 2)
			sl := int(b.U16(p + 2))
			ht.AddBytes(hfHSSig, b, p+4, min(sl, b.Remaining(p+4)))
		}
		return
	}
	p := 0
	for _, hf := range []*d.FieldDef{hfHSDHp, hfHSDHg, hfHSDHYs} {
		l := int(b.U16(p))
		ht.AddBytes(hf, b, p+2, l)
		p += 2 + l
	}
	if b.Remaining(p) >= 4 {
		ht.AddUint(hfHSSigAlg, b, p, 2)
		sl := int(b.U16(p + 2))
		ht.AddBytes(hfHSSig, b, p+4, min(sl, b.Remaining(p+4)))
	}
	_ = sess
}

func dissectClientKeyExchange(b *d.Tvb, ht *d.Node) {
	l := b.Len()
	switch {
	case l >= 1 && int(b.U8(0)) == l-1:
		ht.AddBytes(hfHSClientPt, b, 1, l-1)
	case l >= 2 && int(b.U16(0)) == l-2:
		ht.AddBytes(hfHSEPMS, b, 2, l-2)
	default:
		ht.AddBytes(hfHSData, b, 0, l)
	}
}

func dissectNewSessionTicket(b *d.Tvb, ht *d.Node, sess *tlsSession) {
	ht.AddUint(hfHSTktHint, b, 0, 4)
	p := 4
	if sess.tls13() {
		ht.AddUint(hfHSTktAgeAdd, b, 4, 4)
		nl := int(b.U8(8))
		ht.AddBytes(hfHSTktNonce, b, 9, nl)
		p = 9 + nl
	}
	tl := int(b.U16(p))
	ht.AddUint(hfHSTktLen, b, p, 2)
	ht.AddBytes(hfHSTkt, b, p+2, tl)
}

// ---- fingerprints ----

func joinU16(v []uint16) string {
	var parts []string
	for _, x := range v {
		if !isGREASE(x) {
			parts = append(parts, strconv.Itoa(int(x)))
		}
	}
	return strings.Join(parts, "-")
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func ja3String(h *helloInfo) string {
	var pf []string
	for _, f := range h.pointFormats {
		pf = append(pf, strconv.Itoa(int(f)))
	}
	return fmt.Sprintf("%d,%s,%s,%s,%s", h.legacyVersion, joinU16(h.ciphers), joinU16(h.exts), joinU16(h.groups), strings.Join(pf, "-"))
}

func ja4Version(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	}
	return "00"
}

func alnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func ja4ALPN(alpn []string) string {
	if len(alpn) == 0 || alpn[0] == "" {
		return "00"
	}
	a := alpn[0]
	f, l := a[0], a[len(a)-1]
	if !alnum(f) || !alnum(l) {
		hx := hex.EncodeToString([]byte(a))
		return string([]byte{hx[0], hx[len(hx)-1]})
	}
	return string([]byte{f, l})
}

func hex4List(v []uint16, sortIt bool) string {
	var parts []string
	for _, x := range v {
		if !isGREASE(x) {
			parts = append(parts, fmt.Sprintf("%04x", x))
		}
	}
	if sortIt {
		sort.Strings(parts)
	}
	return strings.Join(parts, ",")
}

func sha12(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func countNonGREASE(v []uint16) int {
	n := 0
	for _, x := range v {
		if !isGREASE(x) {
			n++
		}
	}
	return min(n, 99)
}

// ja4Strings computes JA4 and JA4_r for a Client Hello.
func ja4Strings(h *helloInfo, transport string) (string, string) {
	ver := h.legacyVersion
	if len(h.versions) > 0 {
		ver = 0
		for _, v := range h.versions {
			if !isGREASE(v) && v > ver {
				ver = v
			}
		}
	}
	sni := "i"
	if h.sni != "" {
		sni = "d"
	}
	a := fmt.Sprintf("%s%s%s%02d%02d%s", transport, ja4Version(ver), sni, countNonGREASE(h.ciphers), countNonGREASE(h.exts), ja4ALPN(h.alpn))
	ciphers := hex4List(h.ciphers, true)
	var exts []uint16
	for _, e := range h.exts {
		if e != 0 && e != 16 {
			exts = append(exts, e)
		}
	}
	extStr := hex4List(exts, true)
	sigs := hex4List(h.sigAlgs, false)
	c := extStr
	if sigs != "" {
		c += "_" + sigs
	}
	ja4 := a + "_" + sha12(ciphers) + "_" + sha12(c)
	if extStr == "" {
		ja4 = a + "_" + sha12(ciphers) + "_000000000000"
	}
	return ja4, a + "_" + ciphers + "_" + c
}

// ja4sStrings computes JA4S and JA4S_r for a Server Hello.
func ja4sStrings(h *helloInfo, transport string, cipher uint16) (string, string) {
	ver := h.legacyVersion
	if len(h.versions) > 0 {
		ver = h.versions[0]
	}
	a := fmt.Sprintf("%s%s%02d%s", transport, ja4Version(ver), countNonGREASE(h.exts), ja4ALPN(h.alpn))
	exts := hex4List(h.exts, false)
	return a + fmt.Sprintf("_%04x_", cipher) + sha12(exts), a + fmt.Sprintf("_%04x_", cipher) + exts
}
