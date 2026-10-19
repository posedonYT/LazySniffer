# lazysniffer

**English** | [Русский](README.ru.md)

A terminal network protocol analyzer in the spirit of lazygit and lazydocker:
Wireshark's three-pane layout and display filter language, driven entirely
from the keyboard (or mouse) with on-screen key hints.

```
 ◆  File  Edit  View  Go  Analyze  Statistics  Tools  Help        F10 menu · ctrl+p commands · ? help
 Filter tcp.len > 0                                                                       ✓ applied
╭─ Packets ─────────────────────────────────────────────────────────────────────────────────── 1/3 ╮
│  No.      Time  Source    Destination  Protocol  Length  Info                                    │
│▶   4  0.001092  10.1.1.2  10.1.1.1     TCP          138  44644 → 80 [PSH, ACK] Seq=1 Ack=1 Len=72│
│    6  0.004113  10.1.1.1  10.1.1.2     TCP           89  80 → 44644 [PSH, ACK] Seq=1 Ack=73 Len=23│
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Details ──────────────────────────────────────────────────────────────────────────────────── tcp ╮
│▼ Transmission Control Protocol, Src Port: 44644, Dst Port: 80, Seq: 1, Ack: 1, Len: 72           │
│    Source Port: 44644                                                                            │
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Bytes ────────────────────────────────────────────────────────────────────── 32 byte(s) at 0x0022 ╮
│0020  01 01 ae 64 00 50 93 49  c8 31 f9 a8 17 db 80 18  ...d.P.I.1......                        │
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
```

## What it does

- **Live capture:** start screen with every interface, its addresses and a live traffic sparkline;
  capture on one or several interfaces with a validated BPF capture filter, promiscuous/monitor mode, snaplen,
  buffer, autostop and ring-buffer options; capture over SSH (`--ssh user@host:eth0`), from stdin
  (`tcpdump -w - | lazysniffer -i -`), through **extcap** tools of an installed Wireshark (sshdump, udpdump, …),
  or replay a file as a live stream. Capture runs in a small helper process, so the UI and the dissectors never
  need root. Process column: exact process name and pid from PKTAP on macOS, socket-table sampling on Linux.
  `lazysniffer doctor` explains missing permissions and `sudo lazysniffer setup` fixes them once.
- **Capture a command and read its HTTPS:** `lazysniffer run -- curl https://example.com` captures while the
  command runs, sets `SSLKEYLOGFILE` and opens the result with TLS already decrypted.
- **Files:** pcap and pcapng (all block types, comments, several interfaces, decryption secrets), gzip/zstd/lz4
  captures, Save As, Export Specified Packets, Save With TLS Keys (pcapng DSB), Export Packet Dissections
  (text, CSV, JSON, PSML, PDML), Export Objects (HTTP, HTTP/2, HTTP/3, FTP-DATA).
- **Dissectors (native, with Wireshark's field names, checked against tshark):** Ethernet, 802.1Q, LLC/SNAP, ARP, IPv4/IPv6
  (+ fragments), ICMP/ICMPv6, TCP (full sequence analysis and reassembly), UDP, GRE/VXLAN/Geneve/MPLS/PPP/PPPoE,
  IGMP/MLD, SCTP, DNS/mDNS/LLMNR, DHCP, NTP, **TLS 1.0–1.3** (JA3/JA3S/JA4, X.509, ECH, **decryption** from key
  logs for AES-GCM, ChaCha20 and AES-CBC), DTLS, **QUIC** v1/v2 (Initial packets decrypted without keys, so the SNI is
  visible; Handshake and 1-RTT packets decrypt with a key log) and **HTTP/3 + QPACK** (including the dynamic table), HTTP/1.x (chunked, gzip/br/zstd), **HTTP/2 + HPACK**, gRPC/protobuf, WebSocket, SSH (HASSH),
  WireGuard, OpenVPN, IKE/ESP/AH, L2TP, STUN, FTP, SMTP, POP3, IMAP, Telnet, SOCKS, Syslog, SNMP, NBNS, SSDP, LLDP,
  CDP, STP, Redis, PostgreSQL, MySQL, MQTT, **SIP/SDP/RTP/RTCP**, **802.11 + radiotap + EAPOL**, USB (usbmon) and
  Bluetooth HCI/ATT. Anything else: press `D` for the **deep engine** (Wireshark's sharkd).
- **Display filters:** the full Wireshark language (comparisons, `contains`, `matches`, `in {…}`, slices, layers,
  arithmetic, functions, CIDR …). Filters on fields only Wireshark knows are evaluated by the deep engine.
- **Analysis windows (tabs):** Follow TCP/UDP/TLS/HTTP stream, Expert Information, **Conversations**, **Endpoints**,
  **Protocol Hierarchy**, Packet Lengths, **I/O Graph** (braille charts, several filtered series, field
  aggregates), **Flow Graph**, **TCP Stream Graphs** (Stevens, throughput, RTT, window), HTTP and DNS statistics,
  **VoIP Calls**, **RTP Streams** (loss, jitter, delta — same numbers as Wireshark — and G.711 audio export/play),
  WLAN Traffic, Credentials, Export Objects, Wireshark Taps (deep).
- **Power features:** Decode As, Enabled Protocols, Display Filter Buttons, Expression builder, Time Shift,
  Firewall ACL rules (iptables, nftables, pf, ipfw, Cisco), configuration profiles, **Lua plugins** (Wireshark Lua
  API subset: Proto, ProtoField, DissectorTable, Tvb, TreeItem, Pinfo.cols).
- **CLI tools:** `read` (tshark -r, with `-T json|csv|psml|pdml`), `stat conv|endpoints|phs|len`, `info` (capinfos),
  `merge` (mergecap), `edit` (editcap: ranges, snaplen, dedup, time shift, split, inject TLS secrets), `reorder`,
  `text2pcap`, `fields`, `dftest`, `dumpcap`, `doctor`, `setup`, `run`.

## Install

```
go install github.com/poseydon/lazysniffer/cmd/lazysniffer@latest
```

Requires Go 1.27+ and cgo with libpcap headers (included with Xcode on
macOS; `libpcap-dev` on Debian/Ubuntu).

## Usage

```
lazysniffer                       # start screen: pick an interface or a file
lazysniffer -i en0 -f 'tcp port 443'
lazysniffer --ssh admin@server:eth0
sudo tcpdump -U -w - | lazysniffer -i -
lazysniffer -Y 'tcp.port == 443' capture.pcap.gz
lazysniffer read -Y 'icmp' -V capture.pcapng
```

Live capture needs access to the capture devices. Check with
`lazysniffer doctor`; grant it once with `sudo lazysniffer setup` (macOS:
access_bpf group + launch daemon; Linux: a `lazysniffer-dumpcap` helper with
`cap_net_raw,cap_net_admin`), or run with sudo.

Every feature is reachable three ways: the **F10** menu bar (same menus as
Wireshark), the **ctrl+p** command palette and the **.** context menu.
Press **?** for all key bindings.

| Key | Action | Key | Action |
|---|---|---|---|
| `↑↓` `j/k` | move | `tab` | next pane |
| `enter` | open details / follow link | `+` | maximize pane |
| `/` | edit display filter | `ctrl+x` | clear filter |
| `a` / `p` / `A` | apply / prepare as filter, apply as column | `.` | context menu |
| `m` / `i` / `t` | mark / ignore / time reference | `C` | packet comment |
| `ctrl+f` `n` `N` | find, next, previous | `ctrl+g` `:` | go to packet |
| `y` | copy menu | `T` | time format |
| `f` | follow TCP/UDP stream | `!` | expert information |
| `[` `]` `x` | switch / close tabs | `c` | start/stop capture |
| `ctrl+s` | save as | `q` | quit |

Settings live in `~/.config/lazysniffer/config.yml` (override with
`LAZYSNIFFER_CONFIG_DIR`), coloring rules in `~/.config/lazysniffer/colorfilters`.

## TLS decryption in three steps

1. Run the application with `SSLKEYLOGFILE=/tmp/keys.log` (curl, Firefox, Chrome, Python, Go, … honour it), or use
   `lazysniffer run -- <command>`.
2. Capture, then tell lazysniffer where the keys are: `lazysniffer --keylog /tmp/keys.log capture.pcapng`
   (or Edit → TLS Key Log File, or `$SSLKEYLOGFILE`). Keys embedded in a pcapng are used automatically.
3. HTTP requests, bodies, images, HTTP/2 streams and Follow TLS now show the plaintext. Statistics → Export Objects
   saves the files.

## Deep engine

If Wireshark is installed (`brew install wireshark` / `apt install tshark`), lazysniffer starts `sharkd`
on demand: `D` shows Wireshark's complete dissection of the selected packet, filters on fields lazysniffer lacks
run in Wireshark, and Statistics → Wireshark Tap runs any of Wireshark's statistics. `--no-deep` turns it off.

## Development

```
make test      # unit, golden and UI snapshot tests
make race      # with the race detector
make difftest  # compare fields, Info columns, protocol hierarchy, Lua and capture tools with a real tshark
make fuzz      # fuzz the capture reader, filter compiler and dissectors
make generate  # refresh embedded IEEE OUI / IANA service tables
```

`internal/difftest` is the oracle suite: it generates captures for every protocol and checks hundreds of fields and
the Info column against tshark. It skips itself when tshark is not installed.

## License

MIT. lazysniffer does not contain Wireshark code; the optional deep mode talks
to an installed Wireshark as a separate process.
