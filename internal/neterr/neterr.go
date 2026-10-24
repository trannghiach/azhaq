package neterr

import (
	"errors"
	"net"
	"strings"
)

func UnknownHost(err error) bool {
	if err == nil {
		return false
	}
	var dns *net.DNSError
	if errors.As(err, &dns) && (dns.IsNotFound || dns.IsTimeout) {
		return dns.IsNotFound
	}
	return strings.Contains(err.Error(), "no such host")
}
