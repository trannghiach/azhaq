# W3a: UDP ports, and products and versions of open ports (proposed text)

## README / ports

**UDP.** `azhaq ports -udp` also asks the common UDP ports (53, 67, 69, 123,
137, 161, 500, 514, 520, 623, 1194, 1900, 3478, 4500, 5353, 5683, 11211, 27015,
47808, 51820); `-pu LIST` asks a list instead (`-pu 1-1024`, `-pu top`), and
`-p none` leaves the TCP ports out. In `run` it is `-ports-udp SPEC` (`top` or a
list). No privileges are needed: each port gets one datagram on a connected
socket, and the kernel tells an ICMP port unreachable from silence.

| What came back | State |
| --- | --- |
| a datagram | `open`, with the service, product, version and banner the reply gives |
| an ICMP port unreachable | `closed` |
| nothing, twice | `open\|filtered`: a service that ignores the request, or a filter |

The request is the harmless one of the protocol the port usually carries: DNS
`. NS`, an NTP client request, an SNMP GET of sysDescr.0 (community `public`),
SSDP M-SEARCH, an mDNS service query, a NetBIOS node status request, an IKEv2
header, a STUN binding request, memcached `version`, BACnet Who-Is, CoAP
`GET /.well-known/core`; the others get an empty datagram. Nothing logs in,
guesses a credential or changes state. Every datagram counts against
`-max-requests`, is paced by `-rate` and goes in the request ledger as kind `udp`.
A CDN or WAF address is not asked.

JSON rows have `"protocol":"udp"` and `"state"`; the payload has `udp_open`,
`udp_open_filtered`, `udp_closed`, `udp_scanned` and `udp_services` (port, state,
service, product, version, banner). Plain output lists `host:port/udp` for the
open ones only; `open|filtered` ports are in the JSON and the summary note.

`open|filtered` on a loopback or LAN address usually means a service that does
not answer a request it does not understand; a closed port there answers with
an ICMP error, so it is reported `closed`. Across a firewall that drops ICMP,
closed ports also read `open|filtered`.

**Products and versions.** Each open TCP port gets `product` and `version` next
to `service`, from what it says first or answers to the probe azhaq already
sends:

| Source | Example | Product, version |
| --- | --- | --- |
| SSH greeting | `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20` | OpenSSH, 9.6p1 |
| FTP, SMTP, POP3, IMAP greeting | `220 (vsFTPd 3.0.5)`, `ESMTP Exim 4.96`, `Dovecot` | vsftpd 3.0.5, Exim 4.96, Dovecot |
| MySQL, MariaDB handshake | server version in the first packet | MySQL 8.0.35, MariaDB 10.11.6 |
| HTTP `Server` | `Werkzeug/2.2.3 Python/3.11`, `Apache/2.4.25 (Debian)`, `CUPS/2.4` | Werkzeug 2.2.3, Apache httpd 2.4.25, CUPS 2.4 |
| HTTP `X-Powered-By` (when `Server` names none) | `Express` | Express |
| `GET /` body, when the heads name no product | `Ollama is running`; Elasticsearch or OpenSearch JSON `version.number` | Ollama; Elasticsearch 8.11.1 |
| 5432: SSLRequest answer | one byte, `S` or `N` | PostgreSQL (no version) |
| 6379: `PING` | `+PONG` or `-NOAUTH` | Redis (no version) |
| 27017-27019: isMaster over OP_MSG | `maxWireVersion` | MongoDB, release as major.minor |

`service` is unchanged. The `GET /` for a body is one more connection on a web
port whose HEAD answer gave no product and is a 200 or 401 of type JSON or text;
it counts, is paced and is recorded like a connect.

## CHANGELOG

- ports: `-udp` and `-pu LIST` (run: `-ports-udp`) ask the common UDP ports without privileges, with the request of each protocol, and report `open`, `open|filtered` and `closed` apart; UDP datagrams count against the budget and go in the ledger as kind `udp`.
- ports: open TCP ports carry `product` and `version` (SSH, FTP, SMTP, POP3, IMAP, MySQL and MariaDB, HTTP `Server` and `X-Powered-By`, Elasticsearch, OpenSearch, Ollama, PostgreSQL, Redis, MongoDB), read from what the port says or answers to a harmless request.
