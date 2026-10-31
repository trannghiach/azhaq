# azhaq ports

Finds the open TCP ports of hosts with a connect scan, so it needs no root. It names each service by what the port answers, on any port, and gives products and versions. Ranges, CIDR blocks and AS numbers have no size cap. `-udp` also asks the common UDP ports. Replaces naabu (see [Migrating](../MIGRATING.md#naabu-azhaq-ports)).

## Synopsis

```
azhaq ports -host HOST[,HOST…] | -l FILE | stdin | TARGET…  [-p LIST | -tp 100|1000|full | -pf FILE] [-ep LIST] [-udp | -pu LIST] [-rate N] [-T0..5] [-connect-timeout MS] [-retries N] [-c N] [-sn | -wn] [-cdn-full] [-csv | -json] [-oX F] [-oG F] [-oA BASE]
```

## Examples

```
# the 1,000 likeliest ports of one host, as JSON
azhaq ports -host scanme.nmap.org -p top-1000 -json

# three ports of a /16, 2,000 connects a second, only the addresses that are up
azhaq ports 10.0.0.0/16 -p 22,80,443 -rate 2000 -wn

# UDP ports 1 to 1024 of one host, no TCP
azhaq ports -host 127.0.0.1 -p none -pu 1-1024 -json

# hosts from a file, slower timing, two ports left out, all output formats
azhaq ports -l hosts.txt -tp 1000 -ep 25,3306 -T2 -oA scan

# which addresses of a range are up
azhaq ports 192.0.2.0/24 -sn
```

## What it does

1. Takes targets: names, addresses, `host:port`, URLs, CIDR ranges or AS numbers. See [Targets](#targets).
2. Connects to each port in a random order, the likeliest first, paced by `-rate`. `-p` chooses the ports.
3. Asks the ports that neither accepted nor refused a connect once more, when few did not answer.
4. Names the service of each open port from what it says or answers, with its product and version.
5. With `-udp`, also sends each UDP port one harmless datagram.
6. Prints one line for each open port.

A port that says nothing is asked the request of its own protocol, an HTTP `HEAD /` and a TLS handshake. Then it gets one harmless request of each other protocol. That is at most 24 connects after the first. Nothing logs in, sends a credential or changes anything. Raw printing ports (9100–9107) are never asked anything. A CDN or WAF address is asked ports 80, 443, 8080 and 8443 only.

## Output

Plain output is `host:port` for each open port, and `host:port/udp` for an open UDP port. `-json` prints one object per open port, and `-csv` the same fields as columns. [More on formats](#more-on-formats) has the nmap files and the options that choose fields.

| Flag | Output |
| --- | --- |
| (none) | `host:port`; a UDP port is `host:port/udp` |
| `-json`, `-j` | one object per open port |
| `-csv` | a header line, then the same fields as columns |
| `-oX FILE`, `-oG FILE` | nmap XML and nmap greppable output |
| `-oA BASE` | `BASE.json`, `BASE.xml`, `BASE.gnmap` |
| `-sn` | the addresses that are up, one per line; with `-json`, `{"host","ip","up":true,"timestamp"}` |

The fields of a `-json` row, which are naabu's plus azhaq's:

| Field | Meaning |
| --- | --- |
| `host` | The host scanned. |
| `ip` | Its address. |
| `port` | The port number. |
| `protocol` | `tcp`, or `udp`. |
| `tls` | `true` on a TLS port. |
| `cdn` | `true` on a CDN or WAF address. |
| `cdn-name` | The CDN or WAF. |
| `timestamp` | UTC, RFC 3339. |
| `service` | The service the port answered as. A name ending in `?` is only the port's usual service. |
| `product`, `version` | What the service states: see [Products and versions](#products-and-versions-of-tcp-ports). |
| `title` | The `<title>` of a web page that names no product. |
| `banner` | What the port said. A binary answer to the `HEAD` is `(binary)` and its first bytes in hex. |
| `subject_cn`, `subject_an` | The certificate's subject names of a TLS port, as httpx calls them. |
| `state` | UDP only: `open`, or `open\|filtered`. |

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes). The summary of `ports` says:

| Summary | Says |
| --- | --- |
| `addresses`, in `counts` | The addresses asked, wholly or in part when a limit stopped the run. |
| notes | How many addresses were not up (`-wn`), were outside the scope, or had ports that neither accepted nor refused a connect. |
| AS prefixes | The prefixes RIPEstat lists for an AS number. |
| `IPv6 addresses of 1 name not scanned: no IPv6 route from this machine` | A name's IPv6 addresses were not scanned, because this machine cannot reach them. |
| CDN or WAF | The addresses that were asked only ports 80, 443, 8080 and 8443. |
| the host `-pts` stopped on | The host that `-pts` stopped asking: it answers every port. |
| `-proxy` or `-source-ip` | The scan asked the banner only. |
| `-wn` or `-sn` | How many hosts were called down. |
| `open ports whose protocol was not probed, …` | The open ports that `-unnamed` stopped asking. |
| `ports that neither accepted nor refused a connect, asked twice: scanme.nmap.org (45.33.32.156) port 80; …` | Ports where an open port may hide. |
| UDP lines | What `open\|filtered` means, and the closed ports: see [UDP](#udp-ports-and-their-states). |

## Details

### Targets
- A target is a name, an address, `host:port`, a URL, a CIDR range or an AS number. Give them comma-separated in `-host`, one per line in `-l` or on stdin, or as arguments.
- A CIDR range is IPv4, or IPv6 down to /104. A larger IPv6 range is refused, since no scan finishes it.
- `AS13335` stands for the prefixes RIPEstat lists, and the summary says so.
- A `host:port` is asked that port only, unless `-p`, `-tp` or `-pf` is given. They then apply to every target.
- A range is split into blocks of 256 addresses. The run takes them one at a time and records them. So a range has no size limit and is not expanded in memory, and `azhaq resume` continues it.
- A name costs the DNS queries of its A and AAAA records and no others.
- One row is made for each address. A name's first two IPv4 and first two IPv6 addresses are scanned, IPv6 where this machine can reach it. `-sa` scans every address, and `-iv 4` or `-iv 6` keeps one family.
- An address that shows nothing has no row.
- `-wn` scans only the addresses that accept or refuse a connect to 80 or 443. `-sn` lists them and scans nothing.
- For `-wn` and `-sn`, an address is up when a connect to 80 or 443 is accepted or refused, asked twice. A host that drops both is called down.

### Ports, order and pace
- `-p`, `-tp 100|1000|full` and `-pf FILE` add ports. `-ep LIST|FILE` takes ports out.
- `-p -` is every port, `-p u:53` is a UDP port, and `-p none` leaves the TCP ports out.
- The ports of a host are asked in a random order, the likeliest first: nmap's top 100, then its top 1000. `-order asc` asks them by number, and `-seed N` repeats an order.
- `-rate` paces the scan. The default is 1500 connects a second. This machine's loopback is not paced unless you give `-rate`.
- `-T0` to `-T5` set the rate, the connect timeout and the retries as nmap's templates do. An explicit flag wins.
- `-c` is how many connects are in flight.
- `-timeout` is how long the whole run may take, such as `90s`. `ports -timeout 500` is refused, with a pointer to `-connect-timeout`.
- `-connect-timeout` is the wait for one connect. A bare number is milliseconds.

### How an open port is named
A service that speaks first (`ssh`, `ftp`, `smtp`, `telnet`, `irc`, …) is named from what it says. A port that waits is asked what it serves, by what it answers and not by its port number. The steps, in this order:

1. The request of the protocol whose usual port it is.
2. An HTTP `HEAD / HTTP/1.0` on the open connection. An HTTP answer is `http`, and its banner is the `Server` header or the status line. A `405` or `501` is asked `GET /` for the page's title and product.
3. For an answer that is not HTTP text, a TLS handshake on a second connection, counted like a connect. The service is `tls`, or `https` when HTTP answers inside it. A greeting inside it, as an IMAPS or SMTPS server sends, is read first and names the service, with `tls` true.
4. One harmless request of each other protocol, each on a connection of its own, a few at a time. The first in the list that answers is the port's, with the product and version it states.

- A `HEAD` that stays unanswered for half a second is waited on while the handshake and the list are asked beside it. A port that answers neither is done when the `HEAD`'s wait ends, not after a wait for each protocol.
- Every connect, whatever its purpose, counts against `-max-requests`, takes a token of the pace and is in the ledger.
- An open port costs at most 24 connects after the first. A port named by a late protocol may cost a few more than asking the protocols one by one would. Several are asked at once.
- A port that accepts a connection and closes it without a word is `tcpwrapped`.
- Raw printing ports (9100–9107) are never asked anything.
- A service on a port that usually speaks first (22, 21, 25, 3306, …) gets a second wait for its greeting before it is asked anything. A greeting that arrives in reply to the `HEAD` is read as one.
- When no greeting came at all, the port gets one more connect after the scan. sshd drops greetings when many connects arrive at once.
- A second name on the same address has its web and TLS ports asked again under its own name.
- After six open ports of one address that no request could name, the remaining silent ports of that address are not asked the whole list. `-unnamed N` changes the six, `run -port-unnamed N` does the same in `run`, and `-1` means no limit. A workspace row says how many in `unprobed`, and the summary names them.

### Ports that stay silent
- A port that neither accepts nor refuses a connect, by a timeout or an ICMP unreachable, is asked once more after the others. That happens when such ports are at most 64 or a tenth of the scan.
- A loaded or lossy host drops a connect now and then. A firewall that drops nearly everything would only double the scan, so it is not asked again.
- `-retries N` asks them N more times, and `-retries 0` never.
- When a connect timed out, the pass first waits one connect timeout, at most 3 s. A listener whose accept queue is full makes Linux drop the SYN, and the port is open once its service has drained the queue.
- Each ask counts against `-max-requests` and is in the ledger.
- A port still silent is in the row's `filtered_ports` and in the summary.
- In `run` and `query`, the `ports` row of a scanned address counts these silent ports in `filtered`. It lists them in `filtered_ports` when there are no more than 64.

### Limits, and what the scan does not do silently
- A CDN or WAF address is asked ports 80, 443, 8080 and 8443 only, because its other ports are the provider's other customers'. The row has `cdn` and a `note`, and the summary names the addresses. `-cdn-full` scans them in full.
- `-pts N` stops asking a host after N open ports, for a host that answers every port. The row has `"threshold":true` and the summary names the host. Ports already in flight are still asked, so a few more than N may be listed.
- `-detect` says what is asked of an open port:
  - `none` connects and closes: one connect per port, as naabu without `-sV`.
  - `banner` reads what the service says on that connection.
  - `all` is the default. It also asks a silent port for HTTP and TLS, then one request of each protocol that waits to be asked. Each goes on a connection of its own, several at once while the scan has workers free.
- `-proxy host:port` (SOCKS5) and `-source-ip` make the TCP connects go through that proxy or from that address. The service probes beyond the first connection dial on their own, so with either the scan asks the banner only, and the summary says so.
- UDP is not sent through a proxy. `-proxy` with `-udp` is refused.

### More on formats
- `-csv` writes a list joined with spaces. `-lof` lists the fields and stops.
- `-eof a,b` leaves fields out of `-json`, `-csv` and `-oA`'s JSON.
- `-json` rows have `timestamp` in UTC, RFC 3339, and `subject_cn` and `subject_an` on a TLS port.
- `-oX FILE` and `-oG FILE` take `-` for stdout. Hosts are in address order and ports by number. `service` has no `?`, which marks a guess from the port number alone (`method="table"` in the XML).
- The XML and greppable layouts follow naabu's.

### UDP, products and versions

#### UDP ports
- `ports -udp` asks the 25 common UDP ports. `-pu top` asks the same: 53, 67, 69, 111, 123, 137, 161, 500, 514, 520, 623, 1194, 1434, 1900, 3478, 4500, 5060, 5351, 5353, 5683, 10001, 11211, 27015, 47808 and 51820.
- `-pu LIST` asks a list instead, such as `-pu 1-1024` or `-pu top,5354`. List names and numbers combine, in `-p` too.
- `-p none` leaves the TCP ports out. In `run` it is `-ports-udp SPEC`, with `top`, `full` or a list.
- No privileges are needed. Each port gets one datagram on a connected socket, and the kernel tells an ICMP port unreachable from silence.
- Every datagram counts against `-max-requests`, is paced by `-rate` and goes in the request ledger as kind `udp`.
- A CDN or WAF address is not asked.
- Nothing logs in, guesses a credential or changes state.

#### UDP ports and their states

| What came back | State |
| --- | --- |
| a datagram | `open`, with the service, product, version and banner the reply gives |
| an ICMP port unreachable | `closed` |
| nothing, every way asked | `open\|filtered`: a service that ignores the request, or a filter |

The request is the harmless one of the protocol the port usually carries:

- DNS: `. NS`.
- NTP: a client request.
- SNMP: a GET of `sysDescr.0`, community `public`. As the second ask of 161, an SNMPv3 engine id discovery: the vendor is read from the engine id.
- SSDP: M-SEARCH.
- mDNS: a service query.
- NetBIOS: a node status request.
- IKEv2: a header.
- STUN: a binding request.
- memcached: `version`.
- BACnet: Who-Is.
- CoAP: `GET /.well-known/core`.
- TFTP: a read of a file that does not exist. An ERROR packet proves TFTP. It is read on a socket that is not connected, since the server answers from a port of its own.
- The portmapper: DUMP, which lists the programs.
- SQL Server Browser: CLNT_UCAST_EX, which gives the version.
- SIP: OPTIONS.
- NAT-PMP: the public address request.
- Ubiquiti: its discovery request.
- ASF: a presence ping.

A sysDescr that names Linux, Cisco IOS, JUNOS or Windows gives `product` and `version`. A port with no known protocol is asked a DNS query first. Then come an SNMP get with community `public`, memcached's version and an empty datagram, until one answers. DNS, SNMP and memcached are what move to odd ports: 5354, 8053, 10161.

#### UDP rows and lines
- JSON rows have `"protocol":"udp"` and `"state"`. `-json` and `-csv` rows of a silent port have `"state":"open|filtered"`, and each is a result, counted in `results`.
- Plain output lists `host:port/udp` for an open port and `host:port/udp open|filtered` for a silent one. The first field is the same, and `-silent` prints the same lines.
- A closed port is not a result, because nmap lists closed ports only on request.

In a workspace, the `ports` row has these UDP fields:

| Field | Meaning |
| --- | --- |
| `udp_open`, `udp_open_filtered` | The ports in each state. |
| `udp_closed` | How many ports the host refused. |
| `udp_closed_ports` | The first 16 of them. |
| `udp_scanned` | How many UDP ports were scanned. |
| `udp_limited` | Silent ports that may be closed: see below. |
| `udp_services` | For each listed port: port, state, service, product, version, banner. |
| `udp_unlisted` | How many `open\|filtered` ports the row does not list one by one. |
| `udp_silent_ports`, `udp_silent_addresses` | On a range row, the silent ports and addresses that answered nothing on UDP. |

#### What the summary says about UDP
- It says what the state means: `1 UDP port open|filtered: no reply and no ICMP port unreachable after every request its protocol has (a silent service or a firewall); …`.
- It names the closed ports, so that a scan that found nothing says what it saw: `1 UDP port closed (ICMP port unreachable): 127.0.0.1:9`. Up to three are shown as `address:port`, then `and N more`. In a range, the addresses that refused ports and showed nothing else are counted.
- An address asked on its own, or a name, lists every silent port up to 64. Past that the rows would be noise: the summary counts them, and the workspace row's `udp_open_filtered` keeps them.
- In a range, an address that answered nothing at all on UDP, because it is down or drops it, has no rows. The range row counts its `udp_silent_ports` and `udp_silent_addresses`, and the summary says so. Ask the address on its own to list them.
- An address that refused or answered some port, or has an open one, lists its silent ports.

#### Why a UDP port reads open|filtered
- A port is `closed` only on an ICMP unreachable for that port.
- On a loopback or LAN address, `open|filtered` usually means a service that does not answer a request it does not understand. A closed port there answers with an ICMP error and is reported `closed`.
- Across a firewall that drops ICMP, closed ports also read `open|filtered`.
- A host that refuses with ICMP but rate-limits it, as Linux does at about one a second, leaves closed ports silent too. When some ports were refused and at most 80 silent ones remain, those are asked again one at a time at that pace. Each reply can then arrive. This is slower, and happens on a non-loopback address only.
- When more than 80 remain, they stay `open|filtered`, `udp_limited` counts them and the summary says some may be closed.

#### Products and versions of TCP ports
Each open TCP port gets `product` and `version` next to `service`, from what it says first or answers:

| Source | Example | Product, version |
| --- | --- | --- |
| SSH greeting | `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20` | OpenSSH, 9.6p1 |
| FTP, SMTP, POP3, IMAP greeting | `220 (vsFTPd 3.0.5)`, `ESMTP Exim 4.96`, `Dovecot` | vsftpd 3.0.5, Exim 4.96, Dovecot |
| MySQL, MariaDB handshake | server version in the first packet | MySQL 8.0.35, MariaDB 10.11.6 |
| HTTP `Server` | `Werkzeug/2.2.3 Python/3.11`, `Apache/2.4.25 (Debian)`, `CUPS/2.4` | Werkzeug 2.2.3, Apache httpd 2.4.25, CUPS 2.4 |
| HTTP `X-Powered-By`, when `Server` names none | `Express` | Express |
| `GET /` body, when the head names no product | `Ollama is running`; Elasticsearch or OpenSearch JSON `version.number` | Ollama; Elasticsearch 8.11.1 |
| Redis: `INFO server` | `redis_version:7.4.12` (a server that wants a password says `-NOAUTH`: Redis, no version) | Redis 7.4.12 |
| PostgreSQL: a startup message of a protocol version that does not exist | the error names the versions the server supports | PostgreSQL, a range of majors from them (`14 - 17`) |
| MongoDB: `isMaster`, then `buildInfo` | `version` | MongoDB 7.0.45 |
| MQTT: a CONNECT without credentials, a subscribe to `$SYS/broker/version` | CONNACK, the broker's version message | Mosquitto 2.0.22 (the CONNACK alone: `mqtt`) |
| AMQP: the protocol header | Connection.Start's server properties | RabbitMQ 3.13.7 |
| memcached: `version` | `VERSION 1.6.45` | memcached 1.6.45 |
| LDAP: an anonymous root DSE search | `vendorName`, `vendorVersion`, `namingContexts`, the object classes | OpenLDAP; the vendor and version where the server states them; Active Directory's functional level |
| SMB: a NEGOTIATE, no session | dialect, signing, server start time (zero on Samba) | `smb` with the dialect; Samba smbd |
| DNS over TCP: a length-prefixed query, then `version.bind` CHAOS TXT | an answer; the version string | `dns`; BIND, dnsmasq or Unbound with the version where the server answers |
| Kafka: ApiVersions | the response | `kafka` |
| ZooKeeper: `srvr` | `Zookeeper version: 3.9.2` | Apache ZooKeeper 3.9.2 |
| SQL Server: a TDS prelogin | the VERSION token | Microsoft SQL Server 2019 15.0.2000 |
| Oracle TNS: a connect with a ping | VSNNUM in the answer | Oracle TNS Listener 19.0.0.0.0 |
| Cassandra: an OPTIONS frame | SUPPORTED | `cassandra` |
| Kerberos: an AS-REQ for a principal that does not exist | KRB-ERROR with the realm | `kerberos` |
| RDP: an X.224 connection request | the selected protocol | `rdp` |
| X11: a connection setup with no authorization | the vendor and release of an open server | `x11` |
| SOCKS5, STOMP, XMPP, RTSP, SIP, JDWP, AFP, Minecraft, gopher, finger | the method reply, the CONNECTED frame, the stream header, the status line and `Server` header, the handshake, and so on | the service; a product where the answer states one |
| Greetings: VNC, Telnet, IRC, NNTP, ManageSieve, ICY | `RFB 003.008`, an option negotiation, `NOTICE AUTH`, `200 …`, `"IMPLEMENTATION" "…"`, `ICY 200 OK` | `vnc` with the protocol version; the service; INN, Icecast and Dovecot Pigeonhole where named |
| A web page's title, when the head names no product (and for a `HEAD` that was refused) | `<title>Mailpit</title>` and its stylesheet's version | Mailpit 1.20.7 |
| `GET /version` of a Go server that answers `/` with a 404 | etcd, Kubernetes or Docker JSON | etcd, Kubernetes, Docker Engine with the version |

- `service` is unchanged.
- A web page that names no product gets its `<title>` in `title`, and its `<meta name="generator">` as the product.
- The `GET /` for a body is one more connection on a web port. It is made when the `HEAD` answer gave no product and is a 200 or 401 of type JSON or text. It is also made when the `HEAD` was refused (403, 404, 405, 501). It counts, is paced and is recorded like a connect.
- Every request above is sent only to a port that said nothing and is not one of the raw printing ports (9100–9107). None logs in, sends a credential or changes anything.
- A binary answer is read by the protocols' readers, and by none that does not recognise it. So a port with no recognised protocol keeps its banner and stays `service` empty.

## Flags

<!-- flags:begin ports -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-Pn` | bool |  | accepted: addresses are scanned without asking whether they are up, which is the default |
| `-T` | int | `-1` | timing template, 0 (paranoid) to 5 (insane); sets -rate, -connect-timeout and -retries where they are not given; 3 is the default |
| `-allow` | string, repeatable |  | a domain, host or address range the run may touch; with any -allow, nothing else is requested |
| `-c` | int |  | same as -workers |
| `-cdn` | bool |  | accepted: a CDN address is marked in the output, always |
| `-cdn-full` | bool |  | scan CDN and WAF addresses in full, not only ports 80, 443, 8080 and 8443 |
| `-connect-timeout` | string |  | wait this long for one port to accept or refuse a connect: 1500, 1500ms or 2s (default 1.5s; -timeout is the run's limit) |
| `-cp` | string |  | send this to each open TCP port before reading what it says (\r and \n are CR and LF) |
| `-csv` | bool |  | CSV output, a header line first |
| `-db` | string |  | keep the graph in this database for query, show, export and diff (default: a temporary one) |
| `-deny` | string, repeatable |  | a domain, host or address range the run must not touch, even when given as a target |
| `-detect` | string | `all` | what is asked of an open port: all (its banner, then HTTP and TLS, then one request of each protocol that waits to be asked, each on its own connection, several at once while the scan has workers free: at most 24 connects after the first), banner (what it says on the one connection) or none (connect and close, as naabu without -sV) |
| `-dns-rate` | float |  | DNS queries per second per resolver (0: no pace but the queries in flight, as dnsx) |
| `-ef` | string |  | file of hosts, addresses and ranges not to scan |
| `-eh` | string |  | hosts, addresses or ranges not to scan, comma-separated (same as -deny) |
| `-eof` | string |  | leave these fields out of -json, -csv and -oA's JSON, comma-separated |
| `-ep` | string |  | ports not to scan: a list or a file |
| `-host` | string, repeatable |  | hosts, addresses, CIDR ranges, AS numbers or host:port, comma-separated and repeatable |
| `-iv` | string |  | the address families of a name to scan: 4 or 6 (default both) |
| `-j` | bool |  | same as -json |
| `-json` | bool |  | JSONL output, and the summary as one JSON object on stderr |
| `-kill-file` | string |  | stop all sending, at once, when this file exists, and exit 4; azhaq resume works once it is removed (default DB.stop) |
| `-l` | string |  | file of targets (- for stdin) |
| `-ledger` | string |  | write every request and connection to a target to this file, a chain of hashes that azhaq ledger -verify checks (default DB.ledger.jsonl next to the workspace; off: none; with a temporary database, only when given) |
| `-lof` | bool |  | list the fields of -json and -csv, and stop |
| `-max-requests` | int |  | requests to targets this run may send (0: no cap); the work left over is for azhaq resume |
| `-max-retries` | int | `-1` | same as -retries |
| `-min-rate` | float |  | connects per second at least: raises -rate to this when lower |
| `-nc` | bool |  | accepted: no colours are printed |
| `-no-stdin` | bool |  | do not read targets from stdin when none is given |
| `-o` | string |  | also write results to this file |
| `-oA` | string |  | write JSON lines, XML and greppable output to BASE.json, BASE.xml and BASE.gnmap |
| `-oG` | string |  | write nmap greppable output to this file (- for stdout) |
| `-oX` | string |  | write nmap XML to this file (- for stdout) |
| `-order` | string | `random` | the order a host's ports are asked in: random (the likeliest ports first, each tier shuffled) or asc |
| `-p` | string | `top-100` | ports: top-100, top-1000, full, - (all), none, or a list of ports, ranges and these names, such as 22,80,8000-8100 or top-100,8888; u:53 is a UDP port |
| `-pf` | string |  | file of ports, one spec a line (added to -p) |
| `-program` | string |  | the program to take from a -scope list (handle, name or URL) |
| `-proxy` | string |  | connect to TCP ports through this SOCKS5 proxy (host:port); a port is then asked its banner only, and UDP is not sent |
| `-proxy-auth` | string |  | user:password for -proxy |
| `-pts` | int |  | stop asking a host after this many open ports: it answers every port (default: no limit) |
| `-pu` | string |  | UDP ports to ask: top, full or a list of ports, ranges and these names, such as 53,123,1-1024 or top,5354 (implies -udp) |
| `-r` | string |  | same as -resolvers |
| `-rate` | float |  | port connection attempts per second (0: 1500, as naabu's connect scan, and 127.0.0.1 unpaced) |
| `-resolvers` | string |  | DNS resolvers: a list such as 1.1.1.1,8.8.8.8:53 or a file, one a line (default: public resolvers) |
| `-retries` | int | `-1` | more passes over the ports that neither accepted nor refused: n passes over all of them, 0 none (default: one, when few did not answer) |
| `-sa` | bool |  | scan every address of a name, not the first two of each family |
| `-scope` | string |  | a program's scope: a file (HackerOne CSV, bounty-targets JSON, Burp options, lines) or hackerone, bugcrowd, intigriti, yeswehack |
| `-seed` | int |  | make the random port order repeat (default: a new one each run) |
| `-silent` | bool |  | results only: no progress; the summary only when something failed (a source that failed, a takeover candidate as a [takeover] line on stderr); stdout stays one result per line |
| `-sn` | bool |  | list the addresses that are up (a connect to 80 or 443 is accepted or refused) and scan nothing |
| `-source-ip` | string |  | connect from this local address |
| `-timeout` | duration |  | stop after this long and keep what was found; azhaq resume continues (0: no limit) |
| `-tp` | string |  | the most common TCP ports: 100, 1000 or full (added to -p) |
| `-udp` | bool |  | also ask the common UDP ports (25: dns, ntp, snmp, ssdp, mdns, ...) |
| `-unnamed` | int |  | after this many open ports of an address that no protocol probe could name, ask its other silent ports their banner only (0: 6, a guard against hosts that accept every connect; -1: no limit) |
| `-v` | bool |  | print a line for every finished task, not only failures |
| `-wn` | bool |  | scan only the addresses that are up (by -sn's test); the default scans every address |
| `-workers` | int |  | connects in flight at once, over all hosts (default: as many as the rate allows, up to 20000) |
<!-- flags:end -->
