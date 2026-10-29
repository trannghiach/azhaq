package subcol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// historyName is the source that gives back the names earlier runs found:
// passive sources answer differently each time (subdomain.center returns a
// random 500 of 6,300), so what one run found is kept for the next.
const historyName = "history"

// maxHistory caps the names kept per apex; the oldest last_seen go first.
var maxHistory = 200000

var now = time.Now

// seenName is what is kept about one name.
type seenName struct {
	First   string   `json:"first_seen"`
	Last    string   `json:"last_seen"`
	Sources []string `json:"sources,omitempty"`
}

// DataDir is where Azhaq keeps what it learns across runs.
func DataDir() string {
	if d := os.Getenv("AZHAQ_DATA_DIR"); d != "" {
		return d
	}
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return filepath.Join(d, "azhaq")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "share", "azhaq")
}

// historyPath is the file of an apex, or "" when there is no place for it.
func historyPath(apex string) string {
	dir := DataDir()
	if dir == "" || apex == "" || strings.ContainsAny(apex, `/\`) || strings.HasPrefix(apex, ".") {
		return ""
	}
	return filepath.Join(dir, "names", apex+".json")
}

var historyMu sync.Mutex // one read-modify-write at a time in this process

func loadHistory(path string) (map[string]seenName, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]seenName{}, nil
	}
	if err != nil {
		return nil, err
	}
	m := map[string]seenName{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}

// historySource returns the stored names of the apex. It is a verify source:
// a stored name counts only if it resolves now.
func historySource() source {
	return source{
		name: historyName, need: noKey, deflt: true, verify: true,
		collect: func(_ context.Context, domain string, _ []string, _ *subscraping.Session) ([]string, error) {
			path := historyPath(domain)
			if path == "" {
				return nil, nil
			}
			historyMu.Lock()
			m, err := loadHistory(path)
			historyMu.Unlock()
			if err != nil {
				return nil, err
			}
			names := make([]string, 0, len(m))
			for n := range m {
				names = append(names, n)
			}
			sort.Strings(names)
			return names, nil
		},
	}
}

// remember stores the names a run kept (foundBy gives each one's sources),
// through a temp file and a rename so a crash leaves the old file whole.
// With unverified, a name only padding sources gave was never checked and
// is not stored.
func remember(domain string, names []string, foundBy map[string][]string, padding map[string]bool, unverified bool) error {
	path := historyPath(domain)
	if path == "" || len(names) == 0 {
		return nil
	}
	historyMu.Lock()
	defer historyMu.Unlock()
	m, err := loadHistory(path)
	if err != nil {
		// A file that does not parse is set aside, not overwritten.
		if rerr := os.Rename(path, path+".bad"); rerr != nil {
			return err
		}
		m = map[string]seenName{}
	}
	stamp := now().UTC().Format(time.RFC3339)
	for _, n := range names {
		by := foundBy[n]
		if unverified && allIn(by, padding) {
			continue
		}
		e, ok := m[n]
		if !ok {
			e.First = stamp
		}
		e.Last = stamp
		for _, s := range by {
			if s != historyName && !has(e.Sources, s) {
				e.Sources = append(e.Sources, s)
			}
		}
		sort.Strings(e.Sources)
		m[n] = e
	}
	if len(m) > maxHistory {
		old := make([]string, 0, len(m))
		for n := range m {
			old = append(old, n)
		}
		sort.Slice(old, func(i, j int) bool {
			if m[old[i]].Last != m[old[j]].Last {
				return m[old[i]].Last < m[old[j]].Last
			}
			return old[i] < old[j]
		})
		for _, n := range old[:len(m)-maxHistory] {
			delete(m, n)
		}
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(raw)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(tmp.Name())
		return werr
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}

func allIn(xs []string, set map[string]bool) bool {
	for _, x := range xs {
		if !set[x] {
			return false
		}
	}
	return true
}

func has(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
