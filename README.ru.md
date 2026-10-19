# lazysniffer

[English](README.md) | **Русский**

Терминальный анализатор сетевых протоколов в духе lazygit и lazydocker:
трёхпанельный интерфейс и язык фильтров Wireshark, управление полностью с клавиатуры
(или мышью) и подсказки клавиш прямо на экране.

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

Интерфейс программы только на английском; в этом файле описано, как им пользоваться.

## Возможности

- **Живой захват:** стартовый экран со всеми интерфейсами, их адресами и графиком трафика в реальном времени;
  захват на одном или нескольких интерфейсах с проверяемым BPF-фильтром, promiscuous/monitor-режимом, snaplen,
  буфером, автоостановкой и кольцевым буфером файлов; захват по SSH (`--ssh user@host:eth0`), из stdin
  (`tcpdump -w - | lazysniffer -i -`), через **extcap**-утилиты установленного Wireshark (sshdump, udpdump, …)
  или воспроизведение файла как живого потока. Захват выполняет небольшой вспомогательный процесс, поэтому
  интерфейсу и диссекторам root не нужен. Колонка Process: точное имя и pid процесса через PKTAP на macOS,
  опрос таблицы сокетов на Linux. `lazysniffer doctor` объясняет, каких прав не хватает, а
  `sudo lazysniffer setup` выдаёт их один раз.
- **Захват команды и чтение её HTTPS:** `lazysniffer run -- curl https://example.com` пишет трафик, пока команда
  работает, выставляет `SSLKEYLOGFILE` и открывает результат с уже расшифрованным TLS.
- **Файлы:** pcap и pcapng (все типы блоков, комментарии, несколько интерфейсов, секреты расшифровки),
  захваты gzip/zstd/lz4, Save As, Export Specified Packets, Save With TLS Keys (pcapng DSB),
  Export Packet Dissections (text, CSV, JSON, PSML, PDML), Export Objects (HTTP, HTTP/2, HTTP/3, FTP-DATA).
- **Диссекторы** (нативные, с именами полей Wireshark, сверены с tshark): Ethernet, 802.1Q, LLC/SNAP, ARP,
  IPv4/IPv6 (+ фрагменты), ICMP/ICMPv6, TCP (полный анализ последовательностей и сборка потока), UDP,
  GRE/VXLAN/Geneve/MPLS/PPP/PPPoE, IGMP/MLD, SCTP, DNS/mDNS/LLMNR, DHCP, NTP, **TLS 1.0–1.3**
  (JA3/JA3S/JA4, X.509, ECH, **расшифровка** по key log для AES-GCM, ChaCha20 и AES-CBC), DTLS,
  **QUIC** v1/v2 (Initial-пакеты расшифровываются без ключей, поэтому виден SNI; Handshake и 1-RTT
  расшифровываются по key log) и **HTTP/3 + QPACK** (включая динамическую таблицу), HTTP/1.x
  (chunked, gzip/br/zstd), **HTTP/2 + HPACK**, gRPC/protobuf, WebSocket, SSH (HASSH), WireGuard, OpenVPN,
  IKE/ESP/AH, L2TP, STUN, FTP, SMTP, POP3, IMAP, Telnet, SOCKS, Syslog, SNMP, NBNS, SSDP, LLDP, CDP, STP,
  Redis, PostgreSQL, MySQL, MQTT, **SIP/SDP/RTP/RTCP**, **802.11 + radiotap + EAPOL**, USB (usbmon) и
  Bluetooth HCI/ATT. Всё остальное: нажмите `D`, чтобы открыть **deep-движок** (sharkd из Wireshark).
- **Display-фильтры:** полный язык Wireshark (сравнения, `contains`, `matches`, `in {…}`, срезы, слои,
  арифметика, функции, CIDR …). Фильтры по полям, известным только Wireshark, выполняет deep-движок.
- **Окна анализа (вкладки):** Follow TCP/UDP/TLS/HTTP stream, Expert Information, **Conversations**,
  **Endpoints**, **Protocol Hierarchy**, Packet Lengths, **I/O Graph** (braille-графики, несколько рядов
  с фильтрами, агрегаты по полям), **Flow Graph**, **TCP Stream Graphs** (Stevens, throughput, RTT, window),
  статистика HTTP и DNS, **VoIP Calls**, **RTP Streams** (потери, джиттер, delta — те же числа, что в
  Wireshark — и экспорт/проигрывание звука G.711), WLAN Traffic, Credentials, Export Objects,
  Wireshark Taps (deep).
- **Для опытных пользователей:** Decode As, Enabled Protocols, Display Filter Buttons, конструктор выражений,
  Time Shift, правила Firewall ACL (iptables, nftables, pf, ipfw, Cisco), профили конфигурации,
  **Lua-плагины** (подмножество Lua API Wireshark: Proto, ProtoField, DissectorTable, Tvb, TreeItem, Pinfo.cols).
- **CLI-утилиты:** `read` (аналог tshark -r, с `-T json|csv|psml|pdml`), `stat conv|endpoints|phs|len`,
  `info` (capinfos), `merge` (mergecap), `edit` (editcap: диапазоны, snaplen, дедупликация, сдвиг времени,
  разбиение, вставка TLS-секретов), `reorder`, `text2pcap`, `fields`, `dftest`, `dumpcap`, `doctor`,
  `setup`, `run`.

## Установка

```
go install github.com/poseydon/lazysniffer/cmd/lazysniffer@latest
```

Нужны Go 1.27+ и cgo с заголовками libpcap (на macOS они входят в Xcode;
на Debian/Ubuntu — пакет `libpcap-dev`).

## Использование

```
lazysniffer                       # стартовый экран: выбрать интерфейс или файл
lazysniffer -i en0 -f 'tcp port 443'
lazysniffer --ssh admin@server:eth0
sudo tcpdump -U -w - | lazysniffer -i -
lazysniffer -Y 'tcp.port == 443' capture.pcap.gz
lazysniffer read -Y 'icmp' -V capture.pcapng
```

Для живого захвата нужен доступ к устройствам захвата. Проверьте его командой
`lazysniffer doctor`; выдайте один раз через `sudo lazysniffer setup` (macOS:
группа access_bpf и launch daemon; Linux: помощник `lazysniffer-dumpcap` с
`cap_net_raw,cap_net_admin`) либо запускайте через sudo.

Любая функция доступна тремя способами: строка меню по **F10** (те же меню, что в Wireshark),
палитра команд по **ctrl+p** и контекстное меню по **.**.
Все клавиши показывает **?**.

| Клавиша | Действие | Клавиша | Действие |
|---|---|---|---|
| `↑↓` `j/k` | перемещение | `tab` | следующая панель |
| `enter` | открыть детали / перейти по ссылке | `+` | развернуть панель |
| `/` | редактировать display-фильтр | `ctrl+x` | очистить фильтр |
| `a` / `p` / `A` | применить / подготовить как фильтр, добавить колонку | `.` | контекстное меню |
| `m` / `i` / `t` | пометить / игнорировать / опорное время | `C` | комментарий к пакету |
| `ctrl+f` `n` `N` | поиск, далее, назад | `ctrl+g` `:` | перейти к пакету |
| `y` | меню копирования | `T` | формат времени |
| `f` | follow TCP/UDP-потока | `!` | Expert Information |
| `[` `]` `x` | переключить / закрыть вкладки | `c` | начать/остановить захват |
| `ctrl+s` | сохранить как | `q` | выход |

Настройки хранятся в `~/.config/lazysniffer/config.yml` (путь меняется через
`LAZYSNIFFER_CONFIG_DIR`), правила раскраски — в `~/.config/lazysniffer/colorfilters`.

## Расшифровка TLS за три шага

1. Запустите приложение с `SSLKEYLOGFILE=/tmp/keys.log` (его понимают curl, Firefox, Chrome, Python, Go, …)
   или используйте `lazysniffer run -- <команда>`.
2. Сделайте захват и укажите lazysniffer, где лежат ключи: `lazysniffer --keylog /tmp/keys.log capture.pcapng`
   (или Edit → TLS Key Log File, или переменная `$SSLKEYLOGFILE`). Ключи, встроенные в pcapng,
   используются автоматически.
3. HTTP-запросы, тела ответов, изображения, потоки HTTP/2 и Follow TLS теперь показывают открытый текст.
   Statistics → Export Objects сохраняет файлы.

## Deep-движок

Если установлен Wireshark (`brew install wireshark` / `apt install tshark`), lazysniffer по требованию
запускает `sharkd`: клавиша `D` показывает полный разбор выбранного пакета средствами Wireshark, фильтры по
полям, которых нет в lazysniffer, выполняются в Wireshark, а Statistics → Wireshark Tap запускает любую
статистику Wireshark. Флаг `--no-deep` отключает движок. Без Wireshark всё остальное работает как обычно.

## Разработка

```
make test      # юнит-, golden- и snapshot-тесты интерфейса
make race      # то же с детектором гонок
make difftest  # сверка полей, колонок Info, иерархии протоколов, Lua и утилит с настоящим tshark
make fuzz      # фаззинг читателя файлов, компилятора фильтров и диссекторов
make generate  # обновить встроенные таблицы IEEE OUI / IANA services
```

`internal/difftest` — набор тестов-эталонов: он генерирует захваты для каждого протокола и сверяет сотни
полей и колонку Info с tshark. Если tshark не установлен, тесты пропускаются.

## Лицензия

MIT. В lazysniffer нет кода Wireshark; необязательный deep-режим общается
с установленным Wireshark как с отдельным процессом.
