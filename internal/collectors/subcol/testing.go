package subcol

import (
	"context"
	"sync"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// TestSource is a fake passive source. For tests only: it lets a command
// run with no network.
type TestSource struct {
	Name    string
	Default bool // in the default set
	Names   []string
	Err     error // returned after Names
	Delay   time.Duration
	Sampled bool // asked again by sampled(), as a keyless source is
}

var (
	testMu      sync.Mutex
	testSources []source
)

// UseTestSources makes New use only srcs until restore is called. For
// tests only.
func UseTestSources(srcs ...TestSource) (restore func()) {
	fake := []source{}
	for _, ts := range srcs {
		s := source{name: ts.Name, deflt: ts.Default, collect: func(ctx context.Context, _ string, _ []string, _ *subscraping.Session) ([]string, error) {
			if ts.Delay > 0 {
				select {
				case <-time.After(ts.Delay):
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return ts.Names, ts.Err
		}}
		if ts.Sampled {
			s = sampled(s)
		}
		fake = append(fake, s)
	}
	testMu.Lock()
	old := testSources
	testSources = fake
	testMu.Unlock()
	return func() {
		testMu.Lock()
		testSources = old
		testMu.Unlock()
	}
}

func testSourcesInUse() []source {
	testMu.Lock()
	defer testMu.Unlock()
	return testSources
}
