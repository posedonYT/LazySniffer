package proto_test

import (
	"testing"

	g "github.com/poseydon/lazysniffer/internal/testutil/pktgen"
)

func TestServiceProtocols(t *testing.T) {
	pkts := g.SampleServices()
	c := load(t, pkts)
	for filter, want := range map[string]int{
		`dhcp.option.dhcp == 1`:                         1,
		`dhcp.id == 0xdeadbeef`:                         1,
		`dhcp.option.hostname == "host"`:                1,
		`dhcp.option.requested_ip_address == 10.0.0.77`: 1,
		`dhcp.hw.mac_addr == aa:bb:cc:00:00:01`:         1,
		`ntp.flags.mode == 3`:                           1,
		`syslog.level == 2`:                             1,
		`stun.type == 0x0101`:                           1,
		`stun.att.ipv4 == 192.168.1.2`:                  1,
		`stun.att.port == 8222`:                         0,
		`wg.type == 1`:                                  1,
		`isakmp.exchangetype == 34`:                     1,
		`esp.spi == 0x1234`:                             1,
		`openvpn.opcode == 7`:                           1,
		`ssh.protocol contains "OpenSSH"`:               1,
		`ssh.message_code == 20`:                        1,
		`ssh.kex.hassh matches "^[0-9a-f]{32}$"`:        1,
	} {
		if got := matches(t, c, filter); len(got) != want {
			t.Errorf("%s: %v (want %d)", filter, got, want)
		}
	}
}

func TestTextProtocols(t *testing.T) {
	pkts := g.SampleTextProtocols()
	c := load(t, pkts)
	for filter, want := range map[string]int{
		`ftp.request.command == "USER" && ftp.request.arg == "anonymous"`: 1,
		`ftp.response.code == 230`:               1,
		`ftp-data`:                               1,
		`ftp-data.data contains "file contents"`: 1,
		`pop.request.command == "USER"`:          1,
		`pop.response.indicator == "+OK"`:        -1,
		`imap.request.command == "LOGIN"`:        1,
		`smtp.req.command == "EHLO"`:             1,
		`smtp.response.code == 354`:              1,
		`telnet.cmd == 253`:                      1,
		`socks.remote_name == "example.com"`:     1,
		`socks.port == 443`:                      1,
	} {
		got := matches(t, c, filter)
		if (want >= 0 && len(got) != want) || (want < 0 && len(got) == 0) {
			t.Errorf("%s: %v (want %d)", filter, got, want)
		}
	}
}

func TestDatabaseAndMiscProtocols(t *testing.T) {
	pkts := g.SampleDatabases()
	c := load(t, pkts)
	for filter, want := range map[string]int{
		`resp.command == "SET"`:                             1,
		`resp.string == "OK"`:                               1,
		`pgsql.user == "alice"`:                             1,
		`pgsql.query == "SELECT 1"`:                         1,
		`pgsql.authtype == 0`:                               1,
		`mysql.version == "8.0.36"`:                         2,
		`mysql.user == "root"`:                              1,
		`mysql.query == "select now()"`:                     1,
		`mqtt.msgtype == 1 && mqtt.clientid == "cid"`:       1,
		`mqtt.topic == "a/b" && mqtt.msg == 68:65:6c:6c:6f`: 1,
		`snmp.community == "public"`:                        1,
		`snmp.name == "1.3.6.1.2.1.1.1.0"`:                  1,
		`lldp.chassis.id.mac == aa:bb:cc:00:00:01`:          1,
		`lldp.tlv.system.name == "sw1"`:                     1,
	} {
		if got := matches(t, c, filter); len(got) != want {
			t.Errorf("%s: %v (want %d)", filter, got, want)
		}
	}
}
