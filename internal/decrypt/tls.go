package decrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"

	"golang.org/x/crypto/chacha20poly1305"
)

// ---- TLS 1.3 ----

// TLS13Dir decrypts the records of one direction of a TLS 1.3 connection.
type TLS13Dir struct {
	Suite  uint16
	Secret []byte
	aead   *AEAD
	Seq    uint64
}

// NewTLS13Dir derives record keys from a traffic secret.
func NewTLS13Dir(suite uint16, secret []byte) (*TLS13Dir, error) {
	h := Hash(suite)
	key := ExpandLabel(h, secret, "key", nil, KeyLen(suite))
	iv := ExpandLabel(h, secret, "iv", nil, 12)
	a, err := NewAEAD(suite, key, iv)
	if err != nil {
		return nil, err
	}
	return &TLS13Dir{Suite: suite, Secret: secret, aead: a}, nil
}

// Next returns the keys after a KeyUpdate.
func (d *TLS13Dir) Next() (*TLS13Dir, error) {
	return NewTLS13Dir(d.Suite, ExpandLabel(Hash(d.Suite), d.Secret, "traffic upd", nil, len(d.Secret)))
}

// Open decrypts a record (header is the 5-byte record header). It returns
// the inner content type and the plaintext without padding.
func (d *TLS13Dir) Open(header, payload []byte) (typ byte, plain []byte, err error) {
	p, err := d.aead.Open(d.Seq, header, payload)
	if err != nil {
		return 0, nil, err
	}
	d.Seq++
	i := len(p) - 1
	for i >= 0 && p[i] == 0 {
		i--
	}
	if i < 0 {
		return 0, nil, errors.New("empty TLS 1.3 inner plaintext")
	}
	return p[i], p[:i], nil
}

// ---- TLS 1.2 ----

type suiteInfo struct {
	kind    int // 0 GCM, 1 ChaCha20, 2 CBC
	keyLen  int
	macLen  int
	macHash func() hash.Hash
	prf384  bool
}

const (
	kGCM = iota
	kChaCha
	kCBC
)

var suites12 = map[uint16]suiteInfo{}

func init() {
	gcm := func(key int, p384 bool, ids ...uint16) {
		for _, id := range ids {
			suites12[id] = suiteInfo{kind: kGCM, keyLen: key, prf384: p384}
		}
	}
	gcm(16, false, 0xc02f, 0xc02b, 0x009c, 0x009e, 0xc02d, 0xc031, 0xc0a0, 0xc0a2)
	gcm(32, true, 0xc030, 0xc02c, 0x009d, 0x009f, 0xc02e, 0xc032)
	for _, id := range []uint16{0xcca8, 0xcca9, 0xccaa} {
		suites12[id] = suiteInfo{kind: kChaCha, keyLen: 32}
	}
	cbc := func(key, mac int, h func() hash.Hash, p384 bool, ids ...uint16) {
		for _, id := range ids {
			suites12[id] = suiteInfo{kind: kCBC, keyLen: key, macLen: mac, macHash: h, prf384: p384}
		}
	}
	cbc(16, 20, sha1.New, false, 0xc013, 0xc009, 0x002f, 0x0033, 0xc004, 0xc00e)
	cbc(32, 20, sha1.New, false, 0xc014, 0xc00a, 0x0035, 0x0039, 0xc005, 0xc00f)
	cbc(16, 32, sha256.New, false, 0xc027, 0xc023, 0x003c, 0x0067, 0xc025, 0xc029)
	cbc(32, 32, sha256.New, false, 0x003d, 0x006b)
	cbc(32, 48, sha512.New384, true, 0xc028, 0xc024, 0xc026, 0xc02a)
}

// TLS12Supported reports whether a TLS 1.2 suite can be decrypted.
func TLS12Supported(suite uint16) bool { _, ok := suites12[suite]; return ok }

func pHash(h func() hash.Hash, secret, seed []byte, n int) []byte {
	out := make([]byte, 0, n)
	a := seed
	for len(out) < n {
		a = HMAC(h, secret, a)
		out = append(out, HMAC(h, secret, a, seed)...)
	}
	return out[:n]
}

// PRF12 is the TLS 1.2 pseudo-random function.
func PRF12(prf384 bool, secret []byte, label string, seed []byte, n int) []byte {
	h := sha256.New
	if prf384 {
		h = sha512.New384
	}
	return pHash(h, secret, append([]byte(label), seed...), n)
}

// TLS12Dir decrypts the records of one direction of a TLS 1.2 connection.
type TLS12Dir struct {
	info   suiteInfo
	aead   cipher.AEAD
	iv     []byte // implicit nonce part (GCM: 4 bytes, ChaCha20: 12 bytes)
	block  cipher.Block
	macKey []byte
	Seq    uint64
}

// NewTLS12Keys derives the client and server record keys from a master secret.
func NewTLS12Keys(suite uint16, master, clientRandom, serverRandom []byte) (client, server *TLS12Dir, err error) {
	si, ok := suites12[suite]
	if !ok {
		return nil, nil, errors.New("unsupported cipher suite")
	}
	ivLen := 0
	switch si.kind {
	case kGCM:
		ivLen = 4
	case kChaCha:
		ivLen = 12
	}
	n := 2*si.macLen + 2*si.keyLen + 2*ivLen
	kb := PRF12(si.prf384, master, "key expansion", append(append([]byte(nil), serverRandom...), clientRandom...), n)
	take := func(l int) []byte { b := kb[:l]; kb = kb[l:]; return b }
	cm, sm := take(si.macLen), take(si.macLen)
	ck, sk := take(si.keyLen), take(si.keyLen)
	ci, sci := take(ivLen), take(ivLen)
	mk := func(key, iv, mac []byte) (*TLS12Dir, error) {
		d := &TLS12Dir{info: si, iv: iv, macKey: mac}
		switch si.kind {
		case kGCM:
			b, err := aes.NewCipher(key)
			if err != nil {
				return nil, err
			}
			d.aead, err = cipher.NewGCM(b)
			return d, err
		case kChaCha:
			var err error
			d.aead, err = chacha20poly1305.New(key)
			return d, err
		default:
			b, err := aes.NewCipher(key)
			d.block = b
			return d, err
		}
	}
	if client, err = mk(ck, ci, cm); err != nil {
		return nil, nil, err
	}
	server, err = mk(sk, sci, sm)
	return
}

// Open decrypts one record body.
func (d *TLS12Dir) Open(typ byte, version uint16, payload []byte) ([]byte, error) {
	switch d.info.kind {
	case kGCM, kChaCha:
		var nonce []byte
		var ct []byte
		if d.info.kind == kGCM {
			if len(payload) < 8+16 {
				return nil, errors.New("short record")
			}
			nonce = append(append([]byte(nil), d.iv...), payload[:8]...)
			ct = payload[8:]
		} else {
			if len(payload) < 16 {
				return nil, errors.New("short record")
			}
			nonce = append([]byte(nil), d.iv...)
			for i := 0; i < 8; i++ {
				nonce[11-i] ^= byte(d.Seq >> (8 * uint(i)))
			}
			ct = payload
		}
		aad := make([]byte, 13)
		binary.BigEndian.PutUint64(aad, d.Seq)
		aad[8] = typ
		binary.BigEndian.PutUint16(aad[9:], version)
		binary.BigEndian.PutUint16(aad[11:], uint16(len(ct)-16))
		p, err := d.aead.Open(nil, nonce, ct, aad)
		if err != nil {
			return nil, err
		}
		d.Seq++
		return p, nil
	default:
		bs := d.block.BlockSize()
		if len(payload) < 2*bs || len(payload)%bs != 0 {
			return nil, errors.New("bad CBC record length")
		}
		iv, ct := payload[:bs], append([]byte(nil), payload[bs:]...)
		cipher.NewCBCDecrypter(d.block, iv).CryptBlocks(ct, ct)
		pad := int(ct[len(ct)-1])
		end := len(ct) - 1 - pad - d.info.macLen
		if end < 0 {
			return nil, errors.New("bad CBC padding")
		}
		// Verify the MAC so that a wrong key is detected.
		hdr := make([]byte, 13)
		binary.BigEndian.PutUint64(hdr, d.Seq)
		hdr[8] = typ
		binary.BigEndian.PutUint16(hdr[9:], version)
		binary.BigEndian.PutUint16(hdr[11:], uint16(end))
		if string(HMAC(d.info.macHash, d.macKey, hdr, ct[:end])) != string(ct[end:end+d.info.macLen]) {
			return nil, errors.New("bad record MAC")
		}
		d.Seq++
		return ct[:end], nil
	}
}
