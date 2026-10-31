package egress

import (
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trannghiach/azhaq/internal/neterr"
)

// KillCheck is how often the kill file is looked for.
const KillCheck = 100 * time.Millisecond

// kill is a Policy's watch for its kill file.
type kill struct {
	killMu   sync.Mutex
	killStop chan struct{}
	killNow  chan struct{} // closed once the file is seen: wakes what waits for the pace
	killed   atomic.Pointer[neterr.Killed]
}

// SetKill watches for the file at path: once it exists, Spend and Take
// refuse with neterr.ErrKilled and Spent says so. An empty path watches
// nothing. The file is looked for at once and then every KillCheck; the
// func returned stops the watch and forgets a file it saw.
func (p *Policy) SetKill(path string) (stop func()) {
	p.killMu.Lock()
	if p.killStop != nil {
		close(p.killStop)
		p.killStop = nil
	}
	p.killed.Store(nil)
	if path == "" {
		p.killMu.Unlock()
		return func() {}
	}
	done := make(chan struct{})
	now := make(chan struct{})
	p.killStop, p.killNow = done, now
	p.killMu.Unlock()
	seen := func() bool {
		if _, err := os.Stat(path); err == nil {
			p.killed.Store(&neterr.Killed{Path: path})
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
		p.killMu.Lock()
		defer p.killMu.Unlock()
		if p.killStop == done {
			close(done)
			p.killStop, p.killNow = nil, nil
			p.killed.Store(nil)
		}
	}
}

// killWake is closed once the kill file is seen; nil without a watch.
func (p *Policy) killWake() <-chan struct{} {
	p.killMu.Lock()
	defer p.killMu.Unlock()
	return p.killNow
}

// Killed is the refusal a kill file the run has seen gives, or nil.
func (p *Policy) Killed() error {
	if k := p.killed.Load(); k != nil {
		return k
	}
	return nil
}

// SetKill is Current().SetKill.
func SetKill(path string) (stop func()) { return Current().SetKill(path) }

// Killed is Current().Killed.
func Killed() error { return Current().Killed() }
