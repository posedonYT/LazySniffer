package proto

// IANA TLS registries (names as Wireshark shows them).

var tlsVersions = map[uint64]string{
	0x0002: "SSL 2.0", 0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3",
	0x7f0e: "TLS 1.3 (draft 14)", 0x7f0f: "TLS 1.3 (draft 15)", 0x7f10: "TLS 1.3 (draft 16)", 0x7f11: "TLS 1.3 (draft 17)",
	0x7f12: "TLS 1.3 (draft 18)", 0x7f13: "TLS 1.3 (draft 19)", 0x7f14: "TLS 1.3 (draft 20)", 0x7f15: "TLS 1.3 (draft 21)",
	0x7f16: "TLS 1.3 (draft 22)", 0x7f17: "TLS 1.3 (draft 23)", 0x7f18: "TLS 1.3 (draft 24)", 0x7f19: "TLS 1.3 (draft 25)",
	0x7f1a: "TLS 1.3 (draft 26)", 0x7f1b: "TLS 1.3 (draft 27)", 0x7f1c: "TLS 1.3 (draft 28)",
	0xfeff: "DTLS 1.0", 0xfefd: "DTLS 1.2", 0xfefc: "DTLS 1.3", 0x0100: "DTLS 1.0 (OpenSSL pre 0.9.8f)",
}

var tlsShortVersions = map[uint16]string{0x0300: "SSLv3", 0x0301: "TLSv1", 0x0302: "TLSv1.1", 0x0303: "TLSv1.2", 0x0304: "TLSv1.3",
	0xfeff: "DTLSv1.0", 0xfefd: "DTLSv1.2", 0xfefc: "DTLSv1.3"}

var tlsContentTypes = map[uint64]string{20: "Change Cipher Spec", 21: "Alert", 22: "Handshake", 23: "Application Data", 24: "Heartbeat", 25: "Connection ID", 26: "ACK"}

var tlsHandshakeTypes = map[uint64]string{0: "Hello Request", 1: "Client Hello", 2: "Server Hello", 3: "Hello Verify Request",
	4: "New Session Ticket", 5: "End of Early Data", 6: "Hello Retry Request", 8: "Encrypted Extensions",
	11: "Certificate", 12: "Server Key Exchange", 13: "Certificate Request", 14: "Server Hello Done",
	15: "Certificate Verify", 16: "Client Key Exchange", 20: "Finished", 21: "Certificate URL", 22: "Certificate Status",
	23: "Supplemental Data", 24: "Key Update", 25: "Compressed Certificate", 26: "Encrypted Extensions",
	254: "Message Hash"}

var tlsAlertLevels = map[uint64]string{1: "Warning", 2: "Fatal"}

var tlsAlertDescs = map[uint64]string{0: "Close Notify", 10: "Unexpected Message", 20: "Bad Record MAC", 21: "Decryption Failed",
	22: "Record Overflow", 30: "Decompression Failure", 40: "Handshake Failure", 41: "No Certificate", 42: "Bad Certificate",
	43: "Unsupported Certificate", 44: "Certificate Revoked", 45: "Certificate Expired", 46: "Certificate Unknown",
	47: "Illegal Parameter", 48: "Unknown CA", 49: "Access Denied", 50: "Decode Error", 51: "Decrypt Error",
	60: "Export Restriction", 70: "Protocol Version", 71: "Insufficient Security", 80: "Internal Error",
	86: "Inappropriate Fallback", 90: "User Canceled", 100: "No Renegotiation", 109: "Missing Extension",
	110: "Unsupported Extension", 111: "Certificate Unobtainable", 112: "Unrecognized Name",
	113: "Bad Certificate Status Response", 114: "Bad Certificate Hash Value", 115: "Unknown PSK Identity",
	116: "Certificate Required", 120: "No application protocol", 121: "ECH Required"}

var tlsExtensions = map[uint64]string{0: "server_name", 1: "max_fragment_length", 2: "client_certificate_url",
	3: "trusted_ca_keys", 4: "truncated_hmac", 5: "status_request", 6: "user_mapping", 7: "client_authz", 8: "server_authz",
	9: "cert_type", 10: "supported_groups", 11: "ec_point_formats", 12: "srp", 13: "signature_algorithms", 14: "use_srtp",
	15: "heartbeat", 16: "application_layer_protocol_negotiation", 17: "status_request_v2",
	18: "signed_certificate_timestamp", 19: "client_certificate_type", 20: "server_certificate_type", 21: "padding",
	22: "encrypt_then_mac", 23: "extended_master_secret", 24: "token_binding", 25: "cached_info",
	26: "tls_lts", 27: "compress_certificate", 28: "record_size_limit", 29: "pwd_protect", 30: "pwd_clear",
	31: "password_salt", 32: "ticket_pinning", 33: "tls_cert_with_extern_psk", 34: "delegated_credential",
	35: "session_ticket", 36: "TLMSP", 37: "TLMSP_proxying", 38: "TLMSP_delegate", 39: "supported_ekt_ciphers",
	41: "pre_shared_key", 42: "early_data", 43: "supported_versions", 44: "cookie", 45: "psk_key_exchange_modes",
	47: "certificate_authorities", 48: "oid_filters", 49: "post_handshake_auth", 50: "signature_algorithms_cert",
	51: "key_share", 52: "transparency_info", 53: "connection_id (deprecated)", 54: "connection_id",
	55: "external_id_hash", 56: "external_session_id", 57: "quic_transport_parameters", 58: "ticket_request",
	59: "dnssec_chain", 60: "sequence_number_encryption_algorithms", 61: "rrc", 64768: "ech_outer_extensions",
	65037: "encrypted_client_hello", 65281: "renegotiation_info", 13172: "next_protocol_negotiation",
	17513: "application_settings (old)", 17613: "application_settings", 30031: "channel_id_old", 30032: "channel_id",
	65445: "quic_transport_parameters (drafts)"}

var tlsGroups = map[uint64]string{1: "sect163k1", 2: "sect163r1", 3: "sect163r2", 4: "sect193r1", 5: "sect193r2",
	6: "sect233k1", 7: "sect233r1", 8: "sect239k1", 9: "sect283k1", 10: "sect283r1", 11: "sect409k1", 12: "sect409r1",
	13: "sect571k1", 14: "sect571r1", 15: "secp160k1", 16: "secp160r1", 17: "secp160r2", 18: "secp192k1",
	19: "secp192r1", 20: "secp224k1", 21: "secp224r1", 22: "secp256k1", 23: "secp256r1", 24: "secp384r1",
	25: "secp521r1", 26: "brainpoolP256r1", 27: "brainpoolP384r1", 28: "brainpoolP512r1", 29: "x25519", 30: "x448",
	31: "brainpoolP256r1tls13", 32: "brainpoolP384r1tls13", 33: "brainpoolP512r1tls13", 34: "GC256A", 35: "GC256B",
	36: "GC256C", 37: "GC256D", 38: "GC512A", 39: "GC512B", 40: "GC512C", 41: "curveSM2",
	256: "ffdhe2048", 257: "ffdhe3072", 258: "ffdhe4096", 259: "ffdhe6144", 260: "ffdhe8192",
	512: "MLKEM512", 513: "MLKEM768", 514: "MLKEM1024", 4587: "SecP256r1MLKEM768", 4588: "X25519MLKEM768",
	4589: "SecP384r1MLKEM1024", 25497: "X25519Kyber768Draft00", 25498: "SecP256r1Kyber768Draft00",
	65281: "arbitrary_explicit_prime_curves", 65282: "arbitrary_explicit_char2_curves"}

var tlsSigAlgs = map[uint64]string{0x0201: "rsa_pkcs1_sha1", 0x0202: "SHA1 DSA", 0x0203: "ecdsa_sha1",
	0x0301: "SHA224 RSA", 0x0302: "SHA224 DSA", 0x0303: "SHA224 ECDSA", 0x0401: "rsa_pkcs1_sha256", 0x0402: "SHA256 DSA",
	0x0403: "ecdsa_secp256r1_sha256", 0x0420: "rsa_pkcs1_sha256_legacy", 0x0501: "rsa_pkcs1_sha384", 0x0502: "SHA384 DSA",
	0x0503: "ecdsa_secp384r1_sha384", 0x0520: "rsa_pkcs1_sha384_legacy", 0x0601: "rsa_pkcs1_sha512", 0x0602: "SHA512 DSA",
	0x0603: "ecdsa_secp521r1_sha512", 0x0620: "rsa_pkcs1_sha512_legacy", 0x0704: "eccsi_sha256", 0x0705: "iso_ibs1",
	0x0706: "iso_ibs2", 0x0707: "iso_chinese_ibs", 0x0708: "sm2sig_sm3", 0x0709: "gostr34102012_256a",
	0x0804: "rsa_pss_rsae_sha256", 0x0805: "rsa_pss_rsae_sha384", 0x0806: "rsa_pss_rsae_sha512", 0x0807: "ed25519",
	0x0808: "ed448", 0x0809: "rsa_pss_pss_sha256", 0x080a: "rsa_pss_pss_sha384", 0x080b: "rsa_pss_pss_sha512",
	0x081a: "ecdsa_brainpoolP256r1tls13_sha256", 0x081b: "ecdsa_brainpoolP384r1tls13_sha384",
	0x081c: "ecdsa_brainpoolP512r1tls13_sha512", 0x0904: "mldsa44", 0x0905: "mldsa65", 0x0906: "mldsa87"}

var tlsCompressions = map[uint64]string{0: "null", 1: "DEFLATE", 64: "LZS"}

var tlsECPointFormats = map[uint64]string{0: "uncompressed", 1: "ansiX962_compressed_prime", 2: "ansiX962_compressed_char2"}

var tlsPSKModes = map[uint64]string{0: "PSK-only key establishment (psk_ke)", 1: "PSK with (EC)DHE key establishment (psk_dhe_ke)"}

var tlsCertCompression = map[uint64]string{1: "zlib", 2: "brotli", 3: "zstd"}

var tlsCiphers = map[uint64]string{
	0x0000: "TLS_NULL_WITH_NULL_NULL", 0x0001: "TLS_RSA_WITH_NULL_MD5", 0x0002: "TLS_RSA_WITH_NULL_SHA",
	0x0004: "TLS_RSA_WITH_RC4_128_MD5", 0x0005: "TLS_RSA_WITH_RC4_128_SHA", 0x000a: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", 0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA", 0x0032: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
	0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", 0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA", 0x0038: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
	0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", 0x003c: "TLS_RSA_WITH_AES_128_CBC_SHA256", 0x003d: "TLS_RSA_WITH_AES_256_CBC_SHA256",
	0x0040: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", 0x0041: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", 0x0045: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
	0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", 0x006a: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", 0x006b: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
	0x0084: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", 0x0088: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", 0x008c: "TLS_PSK_WITH_AES_128_CBC_SHA",
	0x008d: "TLS_PSK_WITH_AES_256_CBC_SHA", 0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256", 0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
	0x009e: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", 0x009f: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", 0x00a2: "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
	0x00a3: "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", 0x00a8: "TLS_PSK_WITH_AES_128_GCM_SHA256", 0x00a9: "TLS_PSK_WITH_AES_256_GCM_SHA384",
	0x00ff: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
	0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0x1304: "TLS_AES_128_CCM_SHA256", 0x1305: "TLS_AES_128_CCM_8_SHA256", 0x5600: "TLS_FALLBACK_SCSV",
	0xc009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 0xc00a: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	0xc011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA", 0xc012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	0xc023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", 0xc024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
	0xc027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 0xc028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
	0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	0xc035: "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA", 0xc036: "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
	0xc09c: "TLS_RSA_WITH_AES_128_CCM", 0xc09d: "TLS_RSA_WITH_AES_256_CCM", 0xc0ac: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
	0xc0ad: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM", 0xc0ae: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8", 0xc0af: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
	0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	0xccaa: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 0xccab: "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
	0xccac: "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256", 0xccad: "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
	0xd001: "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256", 0xd002: "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384",
}

var quicVersions = map[uint64]string{0x00000001: "1", 0x6b3343cf: "2", 0x00000000: "Version Negotiation",
	0xff00001d: "draft-29", 0xff00001c: "draft-28", 0xff00001b: "draft-27", 0x709a50c4: "2 (draft-00)",
	0x51303530: "Google Q050", 0x54303530: "Google T050", 0x54303531: "Google T051", 0xfaceb002: "Facebook mvfst (draft-27)"}

// isGREASE reports RFC 8701 reserved values (0x?a?a).
func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

func tlsName(m map[uint64]string, v uint16) string {
	if isGREASE(v) {
		return "Reserved (GREASE)"
	}
	if s, ok := m[uint64(v)]; ok {
		return s
	}
	return "Unknown"
}

func tlsVersionVS() map[uint64]string {
	out := map[uint64]string{}
	for k, v := range tlsVersions {
		out[k] = v
	}
	for b := uint64(0x0a); b <= 0xfa; b += 0x10 {
		out[b<<8|b] = "Reserved (GREASE)"
	}
	return out
}

func withGREASE(m map[uint64]string) map[uint64]string {
	out := map[uint64]string{}
	for k, v := range m {
		out[k] = v
	}
	for b := uint64(0x0a); b <= 0xfa; b += 0x10 {
		out[b<<8|b] = "Reserved (GREASE)"
	}
	return out
}
