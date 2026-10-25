package neterr

import (
	"errors"
	"net"
	"strings"
)

// ErrEndsSession is returned instead of requesting a URL that looks like
// a logout while the run carries a session (-cookie or an Authorization
// header): one GET there would log the rest of the run out.
var ErrEndsSession = errors.New("not requested: it would end the session")

// Quiet errors are not failures of the run: a name that does not exist,
// or a request Azhaq chose not to send.
func Quiet(err error) bool {
	return UnknownHost(err) || errors.Is(err, ErrEndsSession)
}

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
