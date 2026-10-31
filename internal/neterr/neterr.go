package neterr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
)

// ErrDenied is returned instead of requesting a URL whose path a
// -deny-path rule keeps out. Denied carries the rule.
var ErrDenied = errors.New("not requested: -deny-path")

// Denied is ErrDenied naming the rule that matched.
type Denied struct{ Rule string }

func (e *Denied) Error() string { return "not requested: -deny-path " + e.Rule }

func (e *Denied) Is(target error) bool { return target == ErrDenied }

// ErrSessionLost is what a signed-in run refuses its requests with when its
// session ended and it cannot sign in again: it never goes on as an
// anonymous run. SessionLost carries the message.
var ErrSessionLost = errors.New("the session ended")

// SessionLost is ErrSessionLost saying how the session ended.
type SessionLost struct{ Msg string }

func (e *SessionLost) Error() string { return e.Msg }

func (e *SessionLost) Is(target error) bool { return target == ErrSessionLost }

// ErrOutOfScope is returned instead of requesting a host the run's scope
// (-allow, -deny, -scope) excludes.
var ErrOutOfScope = errors.New("not requested: outside the scope")

// ErrNotRepeated is returned instead of sending a write again that a run
// sent before it was killed: the ledger holds the request, nothing holds
// its answer, and sending it twice could do its work twice.
var ErrNotRepeated = errors.New("not sent again: sent before the run was killed, its answer was not stored")

// ErrBudget is returned instead of sending a request once the run's
// request budget (-max-requests, a program's daily budget) is spent. The
// work is left for azhaq resume.
var ErrBudget = errors.New("not requested: the request budget is spent")

// ErrKilled is what a kill file refuses with: a file named by -kill-file
// (default DB.stop) exists, so nothing more is sent. Killed carries the
// path; like ErrBudget it leaves the work for azhaq resume, once the file
// is removed.
var ErrKilled = errors.New("stopped: kill file exists")

// Killed is ErrKilled naming the file. It is also ErrBudget: every place
// that stops on a spent budget stops on this.
type Killed struct{ Path string }

func (e *Killed) Error() string { return "stopped: kill file " + e.Path + " exists" }

func (e *Killed) Is(target error) bool { return target == ErrKilled || target == ErrBudget }

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
	return UnknownHost(err) || errors.Is(err, ErrDenied) || errors.Is(err, ErrOutOfScope) || errors.Is(err, ErrOriginDown) || errors.Is(err, ErrNotRepeated)
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
