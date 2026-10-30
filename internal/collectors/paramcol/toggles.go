package paramcol

import "sync"

// toggleNames are parameters that switch a mode on for the value yes,
// true, 1 or on and do nothing for a random one: a page may read debug and
// show nothing different for debug=azf3a9. They are asked again after the
// list, each group with one value.
var toggleNames = []string{
	"debug", "test", "testing", "admin", "administrator", "source", "verbose", "trace", "dev", "devel", "development",
	"internal", "staging", "preview", "show", "raw", "dump", "demo", "beta", "edit", "editor", "config", "profile",
	"diag", "diagnostic", "log", "logs", "logging", "mock", "sandbox", "sudo", "root", "superuser", "force", "bypass",
	"skip", "noauth", "nocache", "cache", "refresh", "reload", "print", "full", "all", "details", "info", "stats",
	"metrics", "status", "health", "enabled", "disabled", "hidden", "private", "public", "secure", "insecure", "ssl",
	"xml", "json", "pretty", "expand", "explain", "dryrun", "dry_run", "safe", "unsafe", "legacy", "old", "new", "v2",
}

// toggleValues are what they are asked with.
var toggleValues = []string{"1", "true", "yes", "on"}

// toggleAnswer is what a group of toggle names did when sent with one value.
type toggleAnswer struct {
	value string
	v     verdict
	ok    bool
	names []string
}

// toggleSet is toggleNames minus what the page's URL or request holds.
func (s *search) toggleSet() []string {
	var names []string
	for _, n := range toggleNames {
		if !s.known[n] && (s.method != XML || xmlName(n)) {
			names = append(names, n)
		}
	}
	return names
}

// askToggles sends every toggle name once per value, the values at the
// same time (it runs beside the list).
func (s *search) askToggles() []toggleAnswer {
	names := s.toggleSet()
	out := make([]toggleAnswer, len(toggleValues))
	var wg sync.WaitGroup
	for i, val := range toggleValues {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, ok := s.test(names, val)
			out[i] = toggleAnswer{value: val, v: v, ok: ok, names: names}
		}()
	}
	wg.Wait()
	return out
}

// toggles finishes what askToggles began, after the list: a value whose
// group changed the answer is split down to names, one value after the
// other; a name found by the list, or by an earlier value, is not asked
// again. What answers differently is added to found, with its value.
func (s *search) toggles(answers []toggleAnswer, found, values map[string]string) {
	for _, a := range answers {
		if !a.ok || s.halted() {
			continue
		}
		var names []string
		for _, n := range a.names {
			if _, ok := found[n]; !ok {
				names = append(names, n)
			}
		}
		if len(names) == 0 || (a.v.why == "" && !a.v.crowd && len(a.v.reflected) == 0 && len(a.v.named) == 0) {
			continue
		}
		ck := &chunk{names: names, fixed: a.value, found: map[string]string{}}
		if len(names) == len(a.names) {
			s.process(ck, names, a.v, false)
		} else {
			s.narrow(ck, names) // names that the list found are out: ask again
		}
		for n, why := range ck.found {
			found[n] = why
			values[n] = a.value
		}
	}
}
