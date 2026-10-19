package proto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"strings"
	"time"

	d "github.com/poseydon/lazysniffer/internal/dissect"
)

var (
	protoX509     = d.RegisterProto("X.509 Authentication Framework", "X509AF", "x509af")
	protoX509CE   = d.RegisterProto("X.509 Certificate Extensions", "X509CE", "x509ce")
	hfX509Version = protoX509.Field("x509af.version", "version", d.FtInt32, d.WithVS(map[uint64]string{0: "v1", 1: "v2", 2: "v3"}))
	hfX509Serial  = protoX509.Field("x509af.serialNumber", "serialNumber", d.FtBytes)
	hfX509SigAlg  = protoX509.Field("x509af.algorithm.id", "Algorithm Id", d.FtString)
	hfX509Issuer  = protoX509.Field("x509af.issuer", "issuer", d.FtString)
	hfX509Subject = protoX509.Field("x509af.subject", "subject", d.FtString)
	hfX509CN      = protoX509.Field("x509af.subject.commonName", "Subject CommonName", d.FtString)
	hfX509IssCN   = protoX509.Field("x509af.issuer.commonName", "Issuer CommonName", d.FtString)
	hfX509NotBef  = protoX509.Field("x509af.notBefore", "notBefore", d.FtAbsTime)
	hfX509NotAft  = protoX509.Field("x509af.notAfter", "notAfter", d.FtAbsTime)
	hfX509PKAlg   = protoX509.Field("x509af.subjectPublicKeyInfo.algorithm", "Public key algorithm", d.FtString)
	hfX509KeyBits = protoX509.Field("x509af.subjectPublicKeyInfo.bits", "Public key size", d.FtUint32, d.WithUnit("bits"))
	hfX509Sig     = protoX509.Field("x509af.encrypted", "encrypted", d.FtBytes)
	hfX509SelfSig = protoX509.Field("x509af.self_signed", "Self-signed", d.FtBool)
	hfX509IsCA    = protoX509CE.Field("x509ce.cA", "cA", d.FtBool)
	hfX509DNS     = protoX509CE.Field("x509ce.dNSName", "dNSName", d.FtString)
	hfX509IP      = protoX509CE.Field("x509ce.iPAddress", "iPAddress", d.FtString)
	hfX509Email   = protoX509CE.Field("x509ce.rfc822Name", "rfc822Name", d.FtString)
	hfX509URI     = protoX509CE.Field("x509ce.uniformResourceIdentifier", "uniformResourceIdentifier", d.FtString)
	hfX509KeyUse  = protoX509CE.Field("x509ce.KeyUsage", "KeyUsage", d.FtString)
	hfX509ExtUse  = protoX509CE.Field("x509ce.KeyPurposeId", "KeyPurposeId", d.FtString)
	hfX509OCSP    = protoX509CE.Field("x509ce.ocsp", "OCSP server", d.FtString)
)

func rdnString(n pkix.Name) string {
	var parts []string
	add := func(prefix string, vals []string) {
		for _, v := range vals {
			parts = append(parts, prefix+"="+v)
		}
	}
	if n.CommonName != "" {
		parts = append(parts, "CN="+n.CommonName)
	}
	add("O", n.Organization)
	add("OU", n.OrganizationalUnit)
	add("L", n.Locality)
	add("ST", n.Province)
	add("C", n.Country)
	if len(parts) == 0 {
		return n.String()
	}
	return strings.Join(parts, ",")
}

func keyInfo(c *x509.Certificate) (string, int) {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return "rsaEncryption", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "id-ecPublicKey (" + k.Curve.Params().Name + ")", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "id-Ed25519", 256
	}
	return c.PublicKeyAlgorithm.String(), 0
}

var keyUsageNames = []string{"digitalSignature", "contentCommitment", "keyEncipherment", "dataEncipherment",
	"keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"}

var extKeyUsageNames = map[x509.ExtKeyUsage]string{x509.ExtKeyUsageServerAuth: "id-kp-serverAuth",
	x509.ExtKeyUsageClientAuth: "id-kp-clientAuth", x509.ExtKeyUsageCodeSigning: "id-kp-codeSigning",
	x509.ExtKeyUsageEmailProtection: "id-kp-emailProtection", x509.ExtKeyUsageTimeStamping: "id-kp-timeStamping",
	x509.ExtKeyUsageOCSPSigning: "id-kp-OCSPSigning", x509.ExtKeyUsageAny: "anyExtendedKeyUsage"}

// describeCertificate decodes a DER certificate under cn. Items cover the
// whole certificate's bytes (individual DER elements are not mapped).
func describeCertificate(cn *d.Node, der []byte, packetTS int64) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		cn.AppendText(" [could not decode: %v]", err)
		return
	}
	cn.SetText("Certificate: %s (%s)", d.TruncHex(der, 8), rdnString(c.Subject))
	sc := cn.AddText(nil, 0, 0, "signedCertificate")
	sc.AddGenerated(hfX509Version, d.Value{U: uint64(c.Version - 1)})
	sc.AddGenerated(hfX509Serial, d.Value{B: c.SerialNumber.Bytes()}).
		SetText("serialNumber: 0x%x", c.SerialNumber.Bytes())
	sc.AddGenerated(hfX509SigAlg, d.StringValue(c.SignatureAlgorithm.String())).
		SetText("signature (%s)", c.SignatureAlgorithm)
	sc.AddGenerated(hfX509Issuer, d.StringValue(rdnString(c.Issuer))).SetText("issuer: %s", rdnString(c.Issuer))
	if c.Issuer.CommonName != "" {
		sc.AddGenerated(hfX509IssCN, d.StringValue(c.Issuer.CommonName)).SetHidden()
	}
	v := sc.AddText(nil, 0, 0, "validity")
	v.AddGenerated(hfX509NotBef, d.TimeValue(c.NotBefore.UnixNano())).SetText("notBefore: %s", c.NotBefore.UTC().Format("2006-01-02 15:04:05 (UTC)"))
	v.AddGenerated(hfX509NotAft, d.TimeValue(c.NotAfter.UnixNano())).SetText("notAfter: %s", c.NotAfter.UTC().Format("2006-01-02 15:04:05 (UTC)"))
	at := time.Unix(0, packetTS)
	if at.After(c.NotAfter) {
		v.AddExpert(eiTLSCertExp, "Certificate expired on %s (packet sent %s)", c.NotAfter.UTC().Format("2006-01-02"), at.UTC().Format("2006-01-02"))
	}
	sc.AddGenerated(hfX509Subject, d.StringValue(rdnString(c.Subject))).SetText("subject: %s", rdnString(c.Subject))
	if c.Subject.CommonName != "" {
		sc.AddGenerated(hfX509CN, d.StringValue(c.Subject.CommonName)).SetHidden()
	}
	alg, bits := keyInfo(c)
	pk := sc.AddText(nil, 0, 0, "subjectPublicKeyInfo")
	pk.AddGenerated(hfX509PKAlg, d.StringValue(alg)).SetText("algorithm (%s)", alg)
	if bits > 0 {
		pk.AddGenerated(hfX509KeyBits, d.Value{U: uint64(bits)})
	}
	ext := sc.AddText(nil, 0, 0, "extensions")
	if len(c.DNSNames)+len(c.IPAddresses)+len(c.EmailAddresses)+len(c.URIs) > 0 {
		san := ext.AddText(nil, 0, 0, "Extension (id-ce-subjectAltName)")
		for _, n := range c.DNSNames {
			san.AddGenerated(hfX509DNS, d.StringValue(n)).SetText("dNSName: %s", n)
		}
		for _, ip := range c.IPAddresses {
			san.AddGenerated(hfX509IP, d.StringValue(ip.String())).SetText("iPAddress: %s", ip)
		}
		for _, e := range c.EmailAddresses {
			san.AddGenerated(hfX509Email, d.StringValue(e))
		}
		for _, u := range c.URIs {
			san.AddGenerated(hfX509URI, d.StringValue(u.String()))
		}
	}
	if c.BasicConstraintsValid {
		bc := ext.AddText(nil, 0, 0, "Extension (id-ce-basicConstraints)")
		bc.AddGenerated(hfX509IsCA, d.BoolValue(c.IsCA))
	}
	if c.KeyUsage != 0 {
		var ku []string
		for i, n := range keyUsageNames {
			if c.KeyUsage&(1<<uint(i)) != 0 {
				ku = append(ku, n)
			}
		}
		kn := ext.AddText(nil, 0, 0, "Extension (id-ce-keyUsage): %s", strings.Join(ku, ", "))
		for _, k := range ku {
			kn.AddGenerated(hfX509KeyUse, d.StringValue(k)).SetHidden()
		}
	}
	if len(c.ExtKeyUsage) > 0 {
		en := ext.AddText(nil, 0, 0, "Extension (id-ce-extKeyUsage)")
		for _, u := range c.ExtKeyUsage {
			name := extKeyUsageNames[u]
			if name == "" {
				name = fmt.Sprint(int(u))
			}
			en.AddGenerated(hfX509ExtUse, d.StringValue(name)).SetText("KeyPurposeId: %s", name)
		}
	}
	for _, o := range c.OCSPServer {
		ext.AddGenerated(hfX509OCSP, d.StringValue(o))
	}
	if !ext.HasChildren() {
		ext.SetHidden()
	}
	selfSigned := c.Subject.String() == c.Issuer.String() && c.CheckSignatureFrom(c) == nil
	sc.AddGenerated(hfX509SelfSig, d.BoolValue(selfSigned))
	cn.AddGenerated(hfX509SigAlg, d.StringValue(c.SignatureAlgorithm.String())).SetText("algorithmIdentifier (%s)", c.SignatureAlgorithm)
	cn.AddGenerated(hfX509Sig, d.Value{B: c.Signature}).SetText("encrypted: %s", d.TruncHex(c.Signature, 16))
}
