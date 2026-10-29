package fetch

import (
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trannghiach/azhaq/internal/neterr"
)

// KillCheck is how often the kill file is looked for.
const KillCheck = 500 * time.Millisecond

var (
	killMu   sync.Mutex
	killStop chan struct{}
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
	killStop = done
	killMu.Unlock()
	seen := func() bool {
		if _, err := os.Stat(path); err == nil {
			killed.Store(&neterr.Killed{Path: path})
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
			killStop = nil
			killed.Store(nil)
		}
	}
}

// Killed is the refusal a kill file the run has seen gives, or nil.
func Killed() error {
	if k := killed.Load(); k != nil {
		return k
	}
	return nil
}
