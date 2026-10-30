// Package gallery serves a workspace's screenshots to a browser on this
// machine: a grid of thumbnails to triage thousands of pages, with
// filters, search, look-alike groups and a detail view per page. It reads
// the workspace and its picture files and sends nothing anywhere.
package gallery

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/trannghiach/azhaq/internal/collectors/shotcol"
)

// Shot is one page's screenshot with what the index needs to list, filter
// and search it. The record's long parts (headers, network, console) stay
// in the workspace until a detail view asks.
type Shot struct {
	ID        string    `json:"id"`
	Workspace string    `json:"workspace,omitempty"`
	URL       string    `json:"url"`
	FinalURL  string    `json:"final_url,omitempty"`
	Host      string    `json:"host"`
	Title     string    `json:"title"`
	Status    int       `json:"status"`
	Tech      []string  `json:"technologies"`
	Partial   bool      `json:"partial"`
	Hash      string    `json:"hash,omitempty"`
	Group     int       `json:"group"`
	GroupSize int       `json:"group_size"`
	TakenAt   time.Time `json:"taken_at"`
	HasFile   bool      `json:"has_file"`
	HasBody   bool      `json:"body_kept"`

	src                          *source
	obsID                        string
	entityID                     string
	files                        []string // where the picture may be, best first
	htmlFile                     string
	hash                         uint64
	hashOK                       bool
	nHeaders, nNetwork, nConsole int

	lurl, ltitle, lheaders, lhost string
	ltech, lname                  []string // technologies, and their names without a version
	body                          string   // lower-cased text of the kept page
}

// source is one workspace database, opened read-only.
type source struct {
	name string // label of the workspace, its file name
	path string
	dir  string
	db   *sql.DB
}

// Warning is something the gallery could not read or show, kept to say so
// in the page, on stderr and in the exit code.
type Warning struct {
	Workspace string `json:"workspace,omitempty"`
	Message   string `json:"message"`
	// Partial: something the user asked for is missing (a workspace or
	// pictures); not partial is a limit of old data, said as a note.
	Partial bool `json:"partial"`
}

type record struct {
	URL      string `json:"url"`
	File     string `json:"file"`
	FilePath string `json:"file_path"`
	HTMLFile string `json:"html_file"`
	Title    string `json:"title"`
	Final    string `json:"final_url"`
	Phash    string `json:"phash"`
	Partial  bool   `json:"partial"`
	Status   int    `json:"response_code"`
	Tech     []struct {
		Value string `json:"value"`
	} `json:"technologies"`
	Headers []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	} `json:"headers"`
	Network     []struct{} `json:"network"`
	NetworkMore int        `json:"network_more"`
	Console     []struct{} `json:"console"`
}

// ErrNotWorkspace is a database that is not an azhaq workspace.
var ErrNotWorkspace = errors.New("not an azhaq workspace (no observations table)")

// openSource opens a workspace file for reading only.
func openSource(path string) (*source, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("no such workspace %s", path)
	}
	if st.IsDir() {
		return nil, fmt.Errorf("%s is a directory", path)
	}
	q := url.Values{"mode": {"ro"}, "_pragma": {"busy_timeout(5000)"}}
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: abs, RawQuery: q.Encode()}).String())
	if err != nil {
		return nil, err
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name IN ('observations', 'entities')`).Scan(&n); err != nil || n != 2 {
		_ = db.Close()
		if err != nil {
			return nil, fmt.Errorf("%s is not a readable workspace: %v", path, err)
		}
		return nil, fmt.Errorf("%s: %w", path, ErrNotWorkspace)
	}
	return &source{name: filepath.Base(abs), path: abs, dir: filepath.Dir(abs), db: db}, nil
}

// load reads every screenshot observation of the workspace, the newest of
// each URL standing for it.
func (s *source) load(label bool) ([]*Shot, error) {
	rows, err := s.db.Query(`SELECT id, entity_id, payload, observed_at FROM observations WHERE collector = 'azhaq-shots' AND kind = 'screenshot' ORDER BY observed_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byURL := map[string]*Shot{}
	var order []string
	for rows.Next() {
		var id, ent, payload string
		var at int64
		if err := rows.Scan(&id, &ent, &payload, &at); err != nil {
			return nil, err
		}
		var r record
		if json.Unmarshal([]byte(payload), &r) != nil || r.URL == "" {
			continue
		}
		sh := &Shot{URL: r.URL, FinalURL: r.Final, Title: strings.TrimSpace(r.Title), Status: r.Status, Partial: r.Partial,
			Hash: r.Phash, TakenAt: time.Unix(0, at).UTC(), src: s, obsID: id, entityID: ent, htmlFile: r.HTMLFile}
		if u, err := url.Parse(r.URL); err == nil {
			sh.Host = u.Host
		}
		if label {
			sh.Workspace = s.name
		}
		sh.ID = shotID(s.path, r.URL)
		for _, t := range r.Tech {
			if t.Value != "" {
				sh.Tech = append(sh.Tech, t.Value)
			}
		}
		var hdr strings.Builder
		for _, h := range r.Headers {
			hdr.WriteString(strings.ToLower(h.Key + ": " + h.Value + "\n"))
		}
		for _, f := range []string{r.FilePath, r.File} {
			if f != "" {
				sh.files = append(sh.files, f)
			}
		}
		if r.File != "" {
			sh.files = append(sh.files, filepath.Join(s.dir, r.File), filepath.Join(s.dir, filepath.Base(r.File)))
		}
		sh.nHeaders, sh.nNetwork, sh.nConsole = len(r.Headers), len(r.Network)+r.NetworkMore, len(r.Console)
		sh.hash, sh.hashOK = shotcol.Hash(r.Phash)
		sh.lheaders = hdr.String()
		sh.index()
		if _, seen := byURL[r.URL]; !seen {
			order = append(order, r.URL)
		}
		byURL[r.URL] = sh
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]*Shot, 0, len(order))
	for _, u := range order {
		sh := byURL[u]
		sh.checkFiles()
		out = append(out, sh)
	}
	return out, nil
}

func (sh *Shot) index() {
	sh.lurl, sh.ltitle = strings.ToLower(sh.URL), strings.ToLower(sh.Title)
	sh.lhost = strings.ToLower(sh.Host)
	sh.ltech = sh.ltech[:0]
	if sh.Tech == nil {
		sh.Tech = []string{}
	}
	for _, t := range sh.Tech {
		sh.ltech = append(sh.ltech, strings.ToLower(t))
	}
	sh.lname = sh.lname[:0]
	for _, t := range sh.Tech {
		sh.lname = append(sh.lname, strings.ToLower(techName(t)))
	}
}

// checkFiles notes whether the picture and the kept page are on disk.
func (sh *Shot) checkFiles() {
	for _, f := range sh.files {
		if isPicture(f) {
			sh.HasFile = true
			break
		}
	}
	if sh.htmlFile != "" {
		for _, f := range []string{sh.htmlFile, filepath.Join(sh.src.dir, sh.htmlFile), filepath.Join(sh.src.dir, filepath.Base(sh.htmlFile))} {
			if st, err := os.Stat(f); err == nil && !st.IsDir() {
				sh.htmlFile, sh.HasBody = f, true
				break
			}
		}
	}
}

// shotID names a page of a workspace in the URLs of the API.
func shotID(path, page string) string {
	sum := sha256.Sum256([]byte(path + "\x00" + page))
	return hex.EncodeToString(sum[:8])
}

// sortedKeys is a map's keys in order.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// isPicture says whether a file is a PNG or a JPEG, by its first bytes.
func isPicture(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 512)
	n, _ := f.Read(head)
	switch http.DetectContentType(head[:n]) {
	case "image/png", "image/jpeg":
		return true
	}
	return false
}

// techName is a technology without its version: the fingerprints give
// "Nginx:1.25.3", and a filter for nginx means all of them.
func techName(t string) string {
	name, _, _ := strings.Cut(t, ":")
	return name
}

// Failed is a page that gave no picture: why, as the run recorded it.
type Failed struct {
	URL       string    `json:"url"`
	Kind      string    `json:"kind"` // error or note (left out on purpose, such as by -shot-codes)
	Reason    string    `json:"reason"`
	At        time.Time `json:"at"`
	Workspace string    `json:"workspace,omitempty"`
}

// loadFailed reads what the screenshot collector said of pages it did not
// take, leaving out a page a later run took.
func (s *source) loadFailed(label bool, taken map[string]time.Time) ([]Failed, error) {
	rows, err := s.db.Query(`SELECT e.key, o.kind, o.payload, o.observed_at FROM observations o JOIN entities e ON e.id = o.entity_id
WHERE o.collector = 'azhaq-shots' AND o.kind IN ('error', 'note') ORDER BY o.observed_at, o.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byKey := map[string]Failed{}
	for rows.Next() {
		var key, kind, payload string
		var at int64
		if err := rows.Scan(&key, &kind, &payload, &at); err != nil {
			return nil, err
		}
		var p struct{ Error, Note string }
		_ = json.Unmarshal([]byte(payload), &p)
		reason := p.Error
		if kind == "note" {
			reason = p.Note
		}
		if reason == "" || strings.HasPrefix(reason, "not requested:") {
			continue
		}
		f := Failed{URL: key, Kind: kind, Reason: reason, At: time.Unix(0, at).UTC()}
		if label {
			f.Workspace = s.name
		}
		byKey[key+"\x00"+kind] = f
	}
	var out []Failed
	for _, f := range byKey {
		if t, ok := taken[f.URL]; ok && t.After(f.At) {
			continue
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
