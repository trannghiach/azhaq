package gallery

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/trannghiach/azhaq/internal/collectors/shotcol"
)

// Gallery is the index over one or more workspaces' screenshots.
type Gallery struct {
	shots    []*Shot
	failed   []Failed
	byID     map[string]*Shot
	srcs     []*source
	warnings []Warning
	groups   [][]int // group number → indexes into shots, in url order
	orders   map[string][]int
	multi    bool // more than one workspace: shots carry their workspace's name

	bodyDone    chan struct{}
	bodyIndexed atomic.Int64
	bodyKept    int

	thumbs thumbCache
	loaded time.Time
}

// Open reads the screenshots of the given workspaces. A workspace that
// cannot be read is a warning when others can; with one only, an error.
// found are warnings of the caller's, such as files of a directory that
// are not workspaces.
func Open(paths []string, found []Warning) (*Gallery, error) {
	g := &Gallery{byID: map[string]*Shot{}, warnings: found, multi: len(paths) > 1, loaded: time.Now()}
	for _, p := range paths {
		s, err := openSource(p)
		if err == nil {
			var shots []*Shot
			if shots, err = s.load(g.multi); err == nil {
				taken := map[string]time.Time{}
				for _, sh := range shots {
					taken[sh.URL] = sh.TakenAt
				}
				var failed []Failed
				if failed, err = s.loadFailed(g.multi, taken); err == nil {
					g.srcs = append(g.srcs, s)
					g.shots = append(g.shots, shots...)
					g.failed = append(g.failed, failed...)
					continue
				}
			}
			_ = s.db.Close()
			err = fmt.Errorf("%s: %w", p, err)
		}
		if len(paths) == 1 {
			return nil, err
		}
		g.warnings = append(g.warnings, Warning{Workspace: p, Message: "skipped: " + err.Error(), Partial: !errors.Is(err, ErrNotWorkspace)})
	}
	if len(g.srcs) == 0 {
		return nil, errors.New("no workspace could be read")
	}
	sort.SliceStable(g.failed, func(i, j int) bool { return g.failed[i].URL < g.failed[j].URL })
	g.build()
	return g, nil
}

// Close closes the workspaces.
func (g *Gallery) Close() {
	for _, s := range g.srcs {
		_ = s.db.Close()
	}
}

// Warnings are what could not be read, for the page and the exit code.
func (g *Gallery) Warnings() []Warning { return g.warnings }

// Len is how many pages the gallery lists.
func (g *Gallery) Len() int { return len(g.shots) }

// WaitBody blocks until the kept pages' text is indexed.
func (g *Gallery) WaitBody() { <-g.bodyDone }

func (g *Gallery) build() {
	sort.SliceStable(g.shots, func(i, j int) bool {
		a, b := g.shots[i], g.shots[j]
		if a.URL != b.URL {
			return a.URL < b.URL
		}
		return a.Workspace < b.Workspace
	})
	hashes, ok := make([]uint64, len(g.shots)), make([]bool, len(g.shots))
	for i, s := range g.shots {
		hashes[i], ok[i] = s.hash, s.hashOK
	}
	assign := shotcol.Cluster(hashes, ok, shotcol.NearBits)
	members := map[int][]int{}
	for i, a := range assign {
		members[a] = append(members[a], i)
	}
	// Group 0 is the largest, the rest follow by size.
	ids := make([]int, 0, len(members))
	for a := range members {
		ids = append(ids, a)
	}
	sort.Slice(ids, func(i, j int) bool {
		if len(members[ids[i]]) != len(members[ids[j]]) {
			return len(members[ids[i]]) > len(members[ids[j]])
		}
		return ids[i] < ids[j]
	})
	for n, a := range ids {
		g.groups = append(g.groups, members[a])
		for _, i := range members[a] {
			g.shots[i].Group, g.shots[i].GroupSize = n, len(members[a])
		}
	}
	for _, s := range g.shots {
		g.byID[s.ID] = s
	}
	g.orders = map[string][]int{}
	idx := func() []int {
		o := make([]int, len(g.shots))
		for i := range o {
			o[i] = i
		}
		return o
	}
	by := func(name string, less func(a, b *Shot) bool) {
		o := idx()
		sort.SliceStable(o, func(i, j int) bool { return less(g.shots[o[i]], g.shots[o[j]]) })
		g.orders[name] = o
	}
	g.orders["url"] = idx()
	by("host", func(a, b *Shot) bool { return a.lhost < b.lhost })
	by("title", func(a, b *Shot) bool { return a.ltitle < b.ltitle })
	by("status", func(a, b *Shot) bool { return a.Status < b.Status })
	by("group", func(a, b *Shot) bool { return a.Group < b.Group })
	by("time", func(a, b *Shot) bool { return a.TakenAt.After(b.TakenAt) })
	for _, s := range g.shots {
		if s.HasBody {
			g.bodyKept++
		}
	}
	g.bodyDone = make(chan struct{})
	go g.indexBodies()
	g.checkGaps()
}

// checkGaps says what the gallery cannot show: pictures gone from disk and
// pages that carry no status or hash (older workspaces).
func (g *Gallery) checkGaps() {
	var noFile, noHash, noStatus int
	for _, s := range g.shots {
		if !s.HasFile {
			noFile++
		}
		if !s.hashOK {
			noHash++
		}
		if s.Status == 0 {
			noStatus++
		}
	}
	add := func(n int, partial bool, msg string) {
		if n > 0 {
			g.warnings = append(g.warnings, Warning{Message: fmt.Sprintf("%d of %d pages: %s", n, len(g.shots), msg), Partial: partial})
		}
	}
	add(noFile, true, "the picture file is not on disk, so no picture is shown")
	add(noHash, false, "no perceptual hash (taken by an older azhaq), so the page is in no look-alike group")
	add(noStatus, false, "no status recorded (taken by an older azhaq), so a status filter does not list it")
}

// Stats counts what the gallery holds.
type Stats struct {
	Pages      int            `json:"pages"`
	Workspaces []WorkspaceRow `json:"workspaces"`
	Statuses   map[string]int `json:"statuses"`
	Partial    int            `json:"partial"`
	Headers    int            `json:"headers"`
	Requests   int            `json:"network_requests"`
	Console    int            `json:"console_lines"`
	Failed     int            `json:"not_taken"`
	Groups     int            `json:"groups"`
	Lookalike  int            `json:"pages_in_groups"`
	Largest    []GroupRow     `json:"largest_groups"`
	Tech       []Count        `json:"technologies"`
	NoFile     int            `json:"files_missing"`
	Body       BodyRow        `json:"body_text"`
	Warnings   []Warning      `json:"warnings"`
	Loaded     time.Time      `json:"loaded_at"`
}

// WorkspaceRow is one workspace's share.
type WorkspaceRow struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	Pages int    `json:"pages"`
	Bytes int64  `json:"bytes"`
}

// GroupRow is one look-alike group in a list.
type GroupRow struct {
	Group  int    `json:"group"`
	Size   int    `json:"size"`
	Sample string `json:"sample"` // id of a page of the group
	Title  string `json:"title"`
	Hosts  int    `json:"hosts"`
}

// Count is a value and how many pages carry it.
type Count struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

// BodyRow says how many pages have their text kept (-shot-html) and how
// many of those are read into the search so far.
type BodyRow struct {
	Kept    int  `json:"kept"`
	Indexed int  `json:"indexed"`
	Ready   bool `json:"ready"`
}

func (g *Gallery) stats() Stats {
	st := Stats{Pages: len(g.shots), Statuses: map[string]int{}, Failed: len(g.failed), Groups: len(g.groups), Warnings: append([]Warning{}, g.warnings...), Loaded: g.loaded}
	per := map[*source]int{}
	tech := map[string]int{}
	for _, s := range g.shots {
		per[s.src]++
		st.Statuses[statusName(s.Status)]++
		if s.Partial {
			st.Partial++
		}
		st.Headers, st.Requests, st.Console = st.Headers+s.nHeaders, st.Requests+s.nNetwork, st.Console+s.nConsole
		if !s.HasFile {
			st.NoFile++
		}
		if s.GroupSize > 1 {
			st.Lookalike++
		}
		for _, t := range uniq(s.Tech) {
			tech[t]++
		}
	}
	for _, s := range g.srcs {
		row := WorkspaceRow{Name: s.name, Path: s.path, Pages: per[s]}
		if fi, err := os.Stat(s.path); err == nil {
			row.Bytes = fi.Size()
		}
		st.Workspaces = append(st.Workspaces, row)
	}
	st.Tech = topCounts(tech, 30)
	for n, m := range g.groups {
		if len(m) < 2 || n >= 10 {
			break
		}
		st.Largest = append(st.Largest, g.groupRow(n))
	}
	select {
	case <-g.bodyDone:
		st.Body.Ready = true
	default:
	}
	st.Body.Kept, st.Body.Indexed = g.bodyKept, int(g.bodyIndexed.Load())
	return st
}

func (g *Gallery) groupRow(n int) GroupRow {
	m := g.groups[n]
	hosts := map[string]bool{}
	for _, i := range m {
		hosts[g.shots[i].Host] = true
	}
	first := g.shots[m[0]]
	return GroupRow{Group: n, Size: len(m), Sample: first.ID, Title: first.Title, Hosts: len(hosts)}
}

func statusName(code int) string {
	if code == 0 {
		return "none"
	}
	return fmt.Sprint(code)
}

func topCounts(m map[string]int, n int) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return strings.ToLower(out[i].Value) < strings.ToLower(out[j].Value)
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// uniq is the names of technologies, each once.
func uniq(tech []string) []string {
	var out []string
	for _, t := range tech {
		if n := techName(t); !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}
