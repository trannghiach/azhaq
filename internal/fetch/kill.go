package fetch

import (
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trannghiach/azhaq/internal/neterr"
)

// KillCheck is how often the kill file is looked for.
const KillCheck = 100 * time.Millisecond

var (
	killMu   sync.Mutex
	killStop chan struct{}
	killNow  chan struct{} // closed once the file is seen: wakes what waits for the pace
	killed   atomic.Pointer[neterr.Killed]
)

// SetKill watches for the file at path: once it exists, Spend and Take
// refuse with neterr.ErrKilled and Spent says so. An empty path watches
// nothing. The file is looked for at once and then every KillCheck; the
// func returned stops the watch and forgets a file it saw.
func SetKill(path string) (stop func()) {
	killMu.Lock()
	if killStop != nil {
		close(killStop)
		killStop = nil
	}
	killed.Store(nil)
	if path == "" {
		killMu.Unlock()
		return func() {}
	}
	done := make(chan struct{})
	now := make(chan struct{})
	killStop, killNow = done, now
	killMu.Unlock()
	seen := func() bool {
		if _, err := os.Stat(path); err == nil {
			killed.Store(&neterr.Killed{Path: path})
			close(now)
			return true
		}
		return false
	}
	if !seen() {
		go func() {
			t := time.NewTicker(KillCheck)
			defer t.Stop()
			for {
				select {
				case <-done:
					return
				case <-t.C:
					if seen() {
						return
					}
				}
			}
		}()
	}
	return func() {
		killMu.Lock()
		defer killMu.Unlock()
		if killStop == done {
			close(done)
			killStop, killNow = nil, nil
			killed.Store(nil)
		}
	}
}

// killWake is closed once the kill file is seen; nil without a watch.
func killWake() <-chan struct{} {
	killMu.Lock()
	defer killMu.Unlock()
	return killNow
}

// Killed is the refusal a kill file the run has seen gives, or nil.
func Killed() error {
	if k := killed.Load(); k != nil {
		return k
	}
	return nil
}
