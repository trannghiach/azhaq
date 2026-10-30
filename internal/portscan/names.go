package portscan

import "regexp"

// banners name the service from the first line a port sent: the text each
// protocol's specification gives a greeting.
var banners = []struct {
	re      *regexp.Regexp
	service string
}{
	{regexp.MustCompile(`^SSH-`), "ssh"},
	{regexp.MustCompile(`(?i)^220[ -].*(ftp|filezilla|vsftpd|proftpd)`), "ftp"},
	{regexp.MustCompile(`(?i)^220[ -].*(smtp|esmtp|postfix|exim|sendmail|mailpit)`), "smtp"},
	{regexp.MustCompile(`(?i)^\+OK`), "pop3"},
	{regexp.MustCompile(`(?i)^\* (OK|PREAUTH|BYE)`), "imap"},
	{regexp.MustCompile(`(?i)mysql|mariadb`), "mysql"},
	{regexp.MustCompile(`^-ERR|^-NOAUTH`), "redis"},
	{regexp.MustCompile(`(?i)^HTTP/`), "http"},
	{regexp.MustCompile(`^RFB \d`), "vnc"},
	{regexp.MustCompile(`^RTSP/\d`), "rtsp"},
	{regexp.MustCompile(`^SIP/2\.0 `), "sip"},
	{regexp.MustCompile(`^20[01][ -]`), "nntp"},
	{regexp.MustCompile(`^ICY \d`), "icy"},
	{regexp.MustCompile(`^220[ -]`), "ftp-or-smtp"},
}

// bannerService is the service a greeting names, if it does.
func bannerService(banner string) string {
	if banner == "" {
		return ""
	}
	for _, b := range banners {
		if b.re.MatchString(banner) {
			return b.service
		}
	}
	return ""
}

// wellKnown names the service a silent port usually runs (the IANA
// registry's names): a guess, marked with a question mark.
var wellKnown = map[int]string{
	7: "echo", 9: "discard", 13: "daytime", 17: "qotd", 19: "chargen", 37: "time", 43: "whois",
	70: "gopher", 79: "finger", 88: "kerberos", 106: "pop3pw", 111: "rpcbind", 113: "ident",
	119: "nntp", 135: "msrpc", 179: "bgp", 389: "ldap", 427: "svrloc", 465: "smtps", 512: "exec",
	513: "login", 514: "shell", 515: "printer", 548: "afp", 554: "rtsp", 587: "smtp", 631: "ipp",
	636: "ldaps", 873: "rsync", 990: "ftps", 993: "imaps", 995: "pop3s", 1080: "socks", 1723: "pptp",
	1883: "mqtt", 2049: "nfs", 2181: "zookeeper", 3128: "http-proxy", 4190: "sieve", 5060: "sip",
	5061: "sips", 5222: "xmpp-client", 5269: "xmpp-server", 5671: "amqps", 5672: "amqp", 6000: "x11",
	8883: "mqtts", 9042: "cassandra", 9092: "kafka", 25565: "minecraft",
	80: "http", 443: "https", 8080: "http", 8443: "https", 8000: "http", 8008: "http", 8888: "http",
	3000: "http", 5000: "http", 9000: "http", 53: "dns", 3306: "mysql", 5432: "postgresql",
	6379: "redis", 27017: "mongodb", 9200: "elasticsearch", 3389: "rdp", 445: "smb", 139: "netbios-ssn",
	5900: "vnc", 1433: "mssql", 1521: "oracle", 11211: "memcached", 2375: "docker", 6443: "kubernetes",
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 110: "pop3", 143: "imap",
}

func guess(port int, banner string) string {
	if s := bannerService(banner); s != "" {
		return s
	}
	if s, ok := wellKnown[port]; ok {
		return s + "?"
	}
	return ""
}
