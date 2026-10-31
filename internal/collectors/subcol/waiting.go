package subcol

import (
	"sort"
	"sync"
	"time"
)

// A source still being waited for is what a long run is held by: the
// progress line names it, so the wait is not taken for a hang.
var waiting struct {
	mu sync.Mutex
	at map[string]map[string]time.Time // source → domain → when it was asked
}

// begin records that source was asked about domain; call the result when
// it has answered.
func begin(source, domain string) func() {
	waiting.mu.Lock()
	if waiting.at == nil {
		waiting.at = map[string]map[string]time.Time{}
	}
	if waiting.at[source] == nil {
		waiting.at[source] = map[string]time.Time{}
	}
	waiting.at[source][domain] = time.Now()
	waiting.mu.Unlock()
	return func() {
		waiting.mu.Lock()
		defer waiting.mu.Unlock()
		delete(waiting.at[source], domain)
		if len(waiting.at[source]) == 0 {
			delete(waiting.at, source)
		}
	}
}

// Wait is a source that has not answered yet.
type Wait struct {
	Source  string
	Domains int           // how many domains it is asked about
	Longest time.Duration // the oldest of its requests
}

// Waiting lists the sources not answered yet, the longest wait first.
func Waiting() []Wait {
	waiting.mu.Lock()
	defer waiting.mu.Unlock()
	var out []Wait
	for source, domains := range waiting.at {
		w := Wait{Source: source, Domains: len(domains)}
		for _, t := range domains {
			w.Longest = max(w.Longest, time.Since(t))
		}
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Longest != out[j].Longest {
			return out[i].Longest > out[j].Longest
		}
		return out[i].Source < out[j].Source
	})
	return out
}
