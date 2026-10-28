package neterr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
)

// ErrEndsSession is returned instead of requesting a URL that looks like
// a logout while the run carries a session (-cookie or an Authorization
// header): one GET there would log the rest of the run out.
var ErrEndsSession = errors.New("not requested: it would end the session")

// ErrOutOfScope is returned instead of requesting a host the run's scope
// (-allow, -deny, -scope) excludes.
var ErrOutOfScope = errors.New("not requested: outside the scope")

// ErrBudget is returned instead of sending a request once the run's
// request budget (-max-requests, a program's daily budget) is spent. The
// work is left for azhaq resume.
var ErrBudget = errors.New("not requested: the request budget is spent")

// ErrOriginDown is returned instead of requesting an origin that stopped
// answering: connects or timeouts in a row with no answer between them.
// The work is left for azhaq resume.
var ErrOriginDown = errors.New("not requested: the origin stopped answering")

// OriginDown is ErrOriginDown naming the origin and how often it was
// silent.
type OriginDown struct {
	Origin   string
	Failures int
}

func (e *OriginDown) Error() string {
	return fmt.Sprintf("not requested: %s stopped answering after %d timeouts", e.Origin, e.Failures)
}

func (e *OriginDown) Is(target error) bool { return target == ErrOriginDown }

// Quiet errors are not failures of the run: a name that does not exist,
// or a request Azhaq chose not to send.
func Quiet(err error) bool {
	return UnknownHost(err) || errors.Is(err, ErrEndsSession) || errors.Is(err, ErrOutOfScope) || errors.Is(err, ErrOriginDown)
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

// Unanswered: the origin gave no answer at all (a connect refused or
// without a route, a timeout), as opposed to an answer that was not
// wanted, or a request the run chose not to send or gave up on.
func Unanswered(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, ErrBudget) || Quiet(err) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	for _, no := range []error{syscall.ECONNREFUSED, syscall.EHOSTUNREACH, syscall.ENETUNREACH, syscall.EHOSTDOWN} {
		if errors.Is(err, no) {
			return true
		}
	}
	return false
}
