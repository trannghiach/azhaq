package paramcol

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

// toggles asks toggleNames the values that switch them on, one group per
// value, one value after the other, after the list: a name found by the
// list, or by an earlier value, is not asked again. What answers
// differently is added to found, with the value that did.
func (s *search) toggles(found, values map[string]string) {
	for _, v := range toggleValues {
		var names []string
		for _, n := range toggleNames {
			if _, ok := found[n]; !ok && !s.known[n] && (s.method != XML || xmlName(n)) {
				names = append(names, n)
			}
		}
		if len(names) == 0 || s.halted() {
			return
		}
		ck := &chunk{names: names, fixed: v, found: map[string]string{}}
		s.narrow(ck, names)
		for n, why := range ck.found {
			found[n] = why
			values[n] = v
		}
	}
}
