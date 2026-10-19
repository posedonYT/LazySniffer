package decrypt

import "crypto/sha256"

// QUIC versions with Initial packet protection.
const (
	QUICv1 = 0x00000001
	QUICv2 = 0x6b3343cf
)

var (
	saltV1      = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	saltV2      = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
	saltDraft29 = []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99}
)

// QUICKeys protects one direction of one packet number space.
type QUICKeys struct {
	Suite uint16
	Key   []byte
	IV    []byte
	HP    []byte
	AEAD  *AEAD
	HPC   *HeaderProtection
}

// QUICSupported reports whether Initial packets of a version can be decrypted.
func QUICSupported(version uint32) bool {
	return version == QUICv1 || version == QUICv2 || version == 0xff00001d || version == 0xff00001c || version == 0xff00001b
}

func labels(version uint32) (key, iv, hp string) {
	if version == QUICv2 {
		return "quicv2 key", "quicv2 iv", "quicv2 hp"
	}
	return "quic key", "quic iv", "quic hp"
}

// QUICKeysFromSecret derives packet protection keys from a traffic secret.
func QUICKeysFromSecret(version uint32, suite uint16, secret []byte) (*QUICKeys, error) {
	h := Hash(suite)
	kl, il, hl := labels(version)
	n := KeyLen(suite)
	k := &QUICKeys{Suite: suite,
		Key: ExpandLabel(h, secret, kl, nil, n),
		IV:  ExpandLabel(h, secret, il, nil, 12),
		HP:  ExpandLabel(h, secret, hl, nil, n)}
	var err error
	if k.AEAD, err = NewAEAD(suite, k.Key, k.IV); err != nil {
		return nil, err
	}
	if k.HPC, err = NewHeaderProtection(suite, k.HP); err != nil {
		return nil, err
	}
	return k, nil
}

// QUICInitialSecrets returns the client and server Initial secrets for the
// client's original Destination Connection ID.
func QUICInitialSecrets(version uint32, dcid []byte) (client, server []byte) {
	salt := saltV1
	switch {
	case version == QUICv2:
		salt = saltV2
	case version&0xffffff00 == 0xff000000:
		salt = saltDraft29
	}
	initial := Extract(sha256.New, dcid, salt)
	return ExpandLabel(sha256.New, initial, "client in", nil, 32), ExpandLabel(sha256.New, initial, "server in", nil, 32)
}

// QUICInitialKeys returns the Initial packet keys for both directions.
func QUICInitialKeys(version uint32, dcid []byte) (client, server *QUICKeys, err error) {
	cs, ss := QUICInitialSecrets(version, dcid)
	if client, err = QUICKeysFromSecret(version, 0x1301, cs); err != nil {
		return nil, nil, err
	}
	server, err = QUICKeysFromSecret(version, 0x1301, ss)
	return client, server, err
}
