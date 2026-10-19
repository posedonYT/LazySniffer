// Package decrypt implements the key schedules and record protection of
// TLS 1.2/1.3 and QUIC needed to decrypt captured traffic.
package decrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Hash returns the hash constructor for a TLS 1.3 / QUIC cipher suite.
func Hash(suite uint16) func() hash.Hash {
	switch suite {
	case 0x1302:
		return sha512.New384
	}
	return sha256.New
}

// ExpandLabel is TLS 1.3 HKDF-Expand-Label.
func ExpandLabel(h func() hash.Hash, secret []byte, label string, context []byte, length int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full)+len(context))
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	out := make([]byte, length)
	r := hkdf.Expand(h, secret, info)
	if _, err := r.Read(out); err != nil {
		panic(err)
	}
	return out
}

// Extract is HKDF-Extract.
func Extract(h func() hash.Hash, secret, salt []byte) []byte {
	return hkdf.Extract(h, secret, salt)
}

// AEAD wraps a record protection cipher.
type AEAD struct {
	aead cipher.AEAD
	iv   []byte
}

// KeyLen returns the key length of a cipher suite.
func KeyLen(suite uint16) int {
	switch suite {
	case 0x1302, 0x1303, 0xc02c, 0xc030, 0x009d, 0x009f, 0xcca8, 0xcca9, 0xccaa:
		return 32
	}
	return 16
}

// NewAEAD builds the AEAD of a TLS 1.3/QUIC suite (AES-GCM or ChaCha20-Poly1305).
func NewAEAD(suite uint16, key, iv []byte) (*AEAD, error) {
	var a cipher.AEAD
	var err error
	switch suite {
	case 0x1303, 0xcca8, 0xcca9, 0xccaa:
		a, err = chacha20poly1305.New(key)
	default:
		var b cipher.Block
		b, err = aes.NewCipher(key)
		if err == nil {
			a, err = cipher.NewGCM(b)
		}
	}
	if err != nil {
		return nil, err
	}
	return &AEAD{aead: a, iv: iv}, nil
}

// Open decrypts with the nonce iv XOR seq (left-padded).
func (a *AEAD) Open(seq uint64, aad, ciphertext []byte) ([]byte, error) {
	nonce := make([]byte, len(a.iv))
	copy(nonce, a.iv)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(seq >> (8 * uint(i)))
	}
	return a.aead.Open(nil, nonce, ciphertext, aad)
}

// Seal encrypts (used by tests to build captures).
func (a *AEAD) Seal(seq uint64, aad, plaintext []byte) []byte {
	nonce := make([]byte, len(a.iv))
	copy(nonce, a.iv)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(seq >> (8 * uint(i)))
	}
	return a.aead.Seal(nil, nonce, plaintext, aad)
}

// HeaderProtection computes the QUIC header protection mask from a sample.
type HeaderProtection struct {
	suite uint16
	key   []byte
	block cipher.Block
}

// NewHeaderProtection creates the header protection of a suite.
func NewHeaderProtection(suite uint16, key []byte) (*HeaderProtection, error) {
	hp := &HeaderProtection{suite: suite, key: key}
	if suite != 0x1303 {
		b, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		hp.block = b
	}
	return hp, nil
}

// Mask returns the 5-byte mask for a 16-byte sample.
func (h *HeaderProtection) Mask(sample []byte) ([]byte, error) {
	if len(sample) < 16 {
		return nil, errors.New("short sample")
	}
	if h.block != nil {
		out := make([]byte, 16)
		h.block.Encrypt(out, sample[:16])
		return out[:5], nil
	}
	counter := binary.LittleEndian.Uint32(sample[:4])
	c, err := chacha20.NewUnauthenticatedCipher(h.key, sample[4:16])
	if err != nil {
		return nil, err
	}
	c.SetCounter(counter)
	out := make([]byte, 5)
	c.XORKeyStream(out, out)
	return out, nil
}

// HMAC computes an HMAC (TLS 1.2 PRF and CBC MACs).
func HMAC(h func() hash.Hash, key []byte, parts ...[]byte) []byte {
	m := hmac.New(h, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}
