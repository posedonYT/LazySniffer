package decrypt

import (
	"encoding/hex"
	"testing"
)

// RFC 9001 appendix A.1.
func TestQUICInitialKeysRFC9001(t *testing.T) {
	dcid, _ := hex.DecodeString("8394c8f03e515708")
	cs, ss := QUICInitialSecrets(QUICv1, dcid)
	if got := hex.EncodeToString(cs); got != "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea" {
		t.Errorf("client secret %s", got)
	}
	if got := hex.EncodeToString(ss); got != "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b" {
		t.Errorf("server secret %s", got)
	}
	c, s, err := QUICInitialKeys(QUICv1, dcid)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, got, want string }{
		{"client key", hex.EncodeToString(c.Key), "1f369613dd76d5467730efcbe3b1a22d"},
		{"client iv", hex.EncodeToString(c.IV), "fa044b2f42a3fd3b46fb255c"},
		{"client hp", hex.EncodeToString(c.HP), "9f50449e04a0e810283a1e9933adedd2"},
		{"server key", hex.EncodeToString(s.Key), "cf3a5331653c364c88f0f379b6067e37"},
		{"server iv", hex.EncodeToString(s.IV), "0ac1493ca1905853b0bba03e"},
		{"server hp", hex.EncodeToString(s.HP), "c206b8d9b9f0f37644430b490eeaa314"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %s, want %s", tc.name, tc.got, tc.want)
		}
	}
	// RFC 9001 A.2: header protection sample and mask of the client Initial.
	sample, _ := hex.DecodeString("d1b1c98dd7689fb8ec11d242b123dc9b")
	mask, _ := c.HPC.Mask(sample)
	if got := hex.EncodeToString(mask); got != "437b9aec36" {
		t.Errorf("mask %s", got)
	}
}
