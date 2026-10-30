package subcol

import (
	"os"
	"strings"
)

// SourceInfo describes a source for -ls.
type SourceInfo struct {
	Name      string `json:"name"`
	Default   bool   `json:"default"`
	Recursive bool   `json:"recursive"`
	// KeyRequirement is none, optional or required, as subfinder says it.
	KeyRequirement string `json:"keyRequirement"`
}

// Sources lists every source the collector can run, in name order of the
// source table (the name history is a local file, not a source).
func Sources() []SourceInfo {
	var out []SourceInfo
	for _, s := range sourceTable() {
		if s.name == historyName {
			continue
		}
		need := "none"
		switch s.need {
		case optionalKey:
			need = "optional"
		case requiredKey:
			need = "required"
		}
		out = append(out, SourceInfo{Name: s.name, Default: s.deflt, Recursive: s.recurse, KeyRequirement: need})
	}
	return out
}

func sourceTable() []source {
	if fake := testSourcesInUse(); fake != nil {
		return fake
	}
	return allSources()
}

// Unknown returns the names that are no source's.
func Unknown(names []string) []string {
	known := map[string]bool{}
	for _, s := range sourceTable() {
		known[s.name] = true
	}
	var out []string
	for _, n := range names {
		if n = strings.ToLower(strings.TrimSpace(n)); n != "" && !known[n] {
			out = append(out, n)
		}
	}
	return out
}

// withEnv adds the key of $NAME_API_KEY for a source that takes one, as
// subfinder does.
func withEnv(keys map[string][]string) map[string][]string {
	for _, s := range sourceTable() {
		if s.need == noKey {
			continue
		}
		if v := strings.TrimSpace(os.Getenv(strings.ToUpper(s.name) + "_API_KEY")); v != "" {
			keys[s.name] = append(keys[s.name], v)
		}
	}
	return keys
}
