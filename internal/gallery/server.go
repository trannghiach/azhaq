package gallery

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

//go:embed ui
var uiFiles embed.FS

// csp lets the page load only its own script and style, from this server,
// and no connection to anywhere else: the browser enforces it.
const csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// Handler serves the page and its JSON API. listen is the address the
// server is bound to: a loopback one answers only requests that name a
// loopback host (a page on another site cannot reach it through DNS).
func (g *Gallery) Handler(listen string) http.Handler {
	mux := http.NewServeMux()
	ui, _ := fs.Sub(uiFiles, "ui")
	static := http.FileServerFS(ui)
	mux.Handle("GET /{$}", static)
	mux.Handle("GET /app.js", static)
	mux.Handle("GET /app.css", static)
	mux.HandleFunc("GET /api/{$}", g.apiIndex)
	mux.HandleFunc("GET /api/shots", g.apiShots)
	mux.HandleFunc("GET /api/shots/{id}", g.apiShot)
	mux.HandleFunc("GET /api/shots/{id}/show", g.apiShow)
	mux.HandleFunc("GET /api/facets", g.apiFacets)
	mux.HandleFunc("GET /api/groups", g.apiGroups)
	mux.HandleFunc("GET /api/failed", g.apiFailed)
	mux.HandleFunc("GET /api/stats", g.apiStats)
	mux.HandleFunc("GET /img/{id}/thumb", g.imgThumb)
	mux.HandleFunc("GET /img/{id}/full", g.imgFull)
	loopback := false
	if h, _, err := net.SplitHostPort(listen); err == nil {
		ip := net.ParseIP(h)
		loopback = h == "localhost" || ip != nil && ip.IsLoopback()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if loopback && !loopbackHost(r.Host) {
			http.Error(w, "this gallery answers on its loopback address only", http.StatusForbidden)
			return
		}
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		mux.ServeHTTP(w, r)
	})
}

func loopbackHost(host string) bool {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = strings.Trim(host, "[]")
	}
	ip := net.ParseIP(h)
	return h == "localhost" || ip != nil && ip.IsLoopback()
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func apiError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// parseQuery reads the filters of a request.
func parseQuery(v url.Values) (Query, error) {
	q := Query{Q: v.Get("q"), Title: v.Get("title"), Host: v.Get("host"), Workspace: v.Get("workspace"),
		Partial: v.Get("partial"), Group: -1, Sort: v.Get("sort"), Desc: v.Get("order") == "desc", Limit: 48}
	for _, s := range v["status"] {
		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(p); p != "" {
				q.Status = append(q.Status, p)
			}
		}
	}
	for _, s := range v["tech"] {
		if s != "" {
			q.Tech = append(q.Tech, s)
		}
	}
	switch v.Get("collapse") {
	case "1", "true", "yes":
		q.Collapse = true
	}
	if q.Partial != "" && q.Partial != "yes" && q.Partial != "no" {
		return q, errors.New("partial is yes or no")
	}
	switch q.Sort {
	case "", "url", "host", "title", "status", "group", "time":
	default:
		return q, errors.New("sort is url, host, title, status, group or time")
	}
	num := func(name string, dst *int, min, max int) error {
		if s := v.Get(name); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil || n < min || n > max {
				return errors.New(name + " must be a number from " + strconv.Itoa(min) + " to " + strconv.Itoa(max))
			}
			*dst = n
		}
		return nil
	}
	for _, e := range []error{num("group", &q.Group, 0, 1<<30), num("offset", &q.Offset, 0, 1<<30), num("limit", &q.Limit, 1, 500)} {
		if e != nil {
			return q, e
		}
	}
	return q, nil
}

func (g *Gallery) apiIndex(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"endpoints": apiDoc})
}

var apiDoc = []map[string]string{
	{"path": "/api/shots", "about": "one page of results: total, offset, limit, shots; query: q, status, tech, title, host, workspace, partial (yes|no), group, sort (url|host|title|status|group|time), order (desc), collapse (1: one page per look-alike group), offset, limit (1-500, default 48)"},
	{"path": "/api/shots/{id}", "about": "one page: its fields, its group's members, the stored record (headers, tls, console, network) and the text of the kept page"},
	{"path": "/api/shots/{id}/show", "about": "what the workspace holds of the page's URL: the entity, its links and its observations, with the azhaq show command"},
	{"path": "/api/facets", "about": "counts of status, technology, host, partial and workspace under the same filters (each facet under the others)"},
	{"path": "/api/groups", "about": "look-alike groups, largest first: group, size, sample, title, hosts; query: min (smallest size, default 2), limit"},
	{"path": "/api/failed", "about": "pages that gave no picture, with the run's reason: total, failed [{url, kind (error|note), reason, at}]; query: q (text in the URL or reason), kind, offset, limit"},
	{"path": "/api/stats", "about": "pages, status counts, groups, technologies, workspaces, kept page text and what could not be read"},
	{"path": "/img/{id}/thumb", "about": "the picture as a 360 pixel wide JPEG"},
	{"path": "/img/{id}/full", "about": "the picture file as taken"},
}

func (g *Gallery) apiShots(w http.ResponseWriter, r *http.Request) {
	q, err := parseQuery(r.URL.Query())
	if err != nil {
		apiError(w, 400, err.Error())
		return
	}
	t0 := time.Now()
	l := g.list(q)
	l.TookMS = float64(time.Since(t0).Microseconds()) / 1000
	writeJSON(w, 200, l)
}

func (g *Gallery) apiFacets(w http.ResponseWriter, r *http.Request) {
	q, err := parseQuery(r.URL.Query())
	if err != nil {
		apiError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, g.facets(q))
}

func (g *Gallery) apiFailed(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	q, kind := strings.ToLower(v.Get("q")), v.Get("kind")
	if kind != "" && kind != "error" && kind != "note" {
		apiError(w, 400, "kind is error or note")
		return
	}
	offset, limit := 0, 100
	for name, dst := range map[string]*int{"offset": &offset, "limit": &limit} {
		if s := v.Get(name); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil || n < 0 || name == "limit" && (n < 1 || n > 1000) {
				apiError(w, 400, name+" is out of range")
				return
			}
			*dst = n
		}
	}
	var match []Failed
	for _, f := range g.failed {
		if (kind == "" || f.Kind == kind) && (q == "" || strings.Contains(strings.ToLower(f.URL+" "+f.Reason), q)) {
			match = append(match, f)
		}
	}
	page := []Failed{}
	if offset < len(match) {
		page = match[offset:min(offset+limit, len(match))]
	}
	writeJSON(w, 200, map[string]any{"total": len(match), "offset": offset, "limit": limit, "failed": page})
}

func (g *Gallery) apiStats(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, g.stats()) }

func (g *Gallery) apiGroups(w http.ResponseWriter, r *http.Request) {
	min, limit := 2, 100
	if s := r.URL.Query().Get("min"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			apiError(w, 400, "min must be a number from 1")
			return
		}
		min = n
	}
	if s := r.URL.Query().Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 5000 {
			apiError(w, 400, "limit must be a number from 1 to 5000")
			return
		}
		limit = n
	}
	out := []GroupRow{}
	for n, m := range g.groups {
		if len(m) < min || len(out) >= limit {
			break
		}
		out = append(out, g.groupRow(n))
	}
	writeJSON(w, 200, map[string]any{"total": len(g.groups), "groups": out})
}

func (g *Gallery) shotOf(w http.ResponseWriter, r *http.Request) *Shot {
	sh := g.byID[r.PathValue("id")]
	if sh == nil {
		apiError(w, 404, "no such page")
	}
	return sh
}

// Detail is a page with everything the workspace holds of its record.
type Detail struct {
	*Shot
	Members     []Member        `json:"group_members"`
	ShowCommand string          `json:"show_command"`
	Record      json.RawMessage `json:"record"`
	BodyText    string          `json:"body_text,omitempty"`
	BodyHTML    string          `json:"body_html,omitempty"`
	BodyCut     bool            `json:"body_cut,omitempty"`
	Problem     string          `json:"problem,omitempty"`
}

// Member is another page of a look-alike group.
type Member struct {
	ID    string `json:"id"`
	URL   string `json:"url"`
	Title string `json:"title"`
}

const (
	detailBody = 20 << 10
	detailHTML = 64 << 10 // bytes of the page source shown
)

func (g *Gallery) apiShot(w http.ResponseWriter, r *http.Request) {
	sh := g.shotOf(w, r)
	if sh == nil {
		return
	}
	d := Detail{Shot: sh, Members: []Member{}, ShowCommand: showCommand(sh)}
	for _, i := range g.groups[sh.Group] {
		if m := g.shots[i]; m != sh && len(d.Members) < 24 {
			d.Members = append(d.Members, Member{m.ID, m.URL, m.Title})
		}
	}
	var payload string
	if err := sh.src.db.QueryRow(`SELECT payload FROM observations WHERE id = ?`, sh.obsID).Scan(&payload); err != nil {
		d.Problem = "the workspace no longer holds this record: " + err.Error()
	} else {
		d.Record = json.RawMessage(payload)
	}
	if sh.HasBody {
		if text, err := pageText(sh.htmlFile, detailBody+1); err == nil {
			if len(text) > detailBody {
				text, d.BodyCut = text[:detailBody], true
			}
			d.BodyText = text
		}
		if f, err := os.Open(sh.htmlFile); err == nil {
			buf, _ := io.ReadAll(io.LimitReader(f, detailHTML))
			_ = f.Close()
			d.BodyHTML = strings.ToValidUTF8(string(buf), "\ufffd")
		}
	}
	writeJSON(w, 200, d)
}

// showCommand is the command that prints everything the workspace knows
// of the page's URL.
func showCommand(sh *Shot) string {
	return "azhaq show -db " + shellQuote(sh.src.path) + " " + shellQuote(sh.URL)
}

func shellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-:@%+=,") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func (g *Gallery) apiShow(w http.ResponseWriter, r *http.Request) {
	sh := g.shotOf(w, r)
	if sh == nil {
		return
	}
	type ent struct {
		Type      string    `json:"type"`
		Key       string    `json:"key"`
		FirstSeen time.Time `json:"first_seen"`
		LastSeen  time.Time `json:"last_seen"`
	}
	type link struct {
		Rel  string `json:"rel"`
		Dir  string `json:"dir"`
		Type string `json:"type"`
		Key  string `json:"key"`
	}
	type obs struct {
		Collector  string    `json:"collector"`
		Kind       string    `json:"kind"`
		Source     string    `json:"source"`
		ObservedAt time.Time `json:"observed_at"`
		Bytes      int       `json:"payload_bytes"`
	}
	out := map[string]any{"command": showCommand(sh)}
	db := sh.src.db
	var e ent
	var fs, ls int64
	if err := db.QueryRow(`SELECT type, key, first_seen, last_seen FROM entities WHERE id = ?`, sh.entityID).Scan(&e.Type, &e.Key, &fs, &ls); err != nil {
		apiError(w, 404, "the workspace no longer holds this URL: "+err.Error())
		return
	}
	e.FirstSeen, e.LastSeen = time.Unix(0, fs).UTC(), time.Unix(0, ls).UTC()
	out["entity"] = e
	links := []link{}
	if rows, err := db.Query(`SELECT edges.type, 'out', e.type, e.key FROM edges JOIN entities e ON e.id = edges.to_id WHERE edges.from_id = ?
UNION ALL SELECT edges.type, 'in', e.type, e.key FROM edges JOIN entities e ON e.id = edges.from_id WHERE edges.to_id = ? ORDER BY 2, 1, 4 LIMIT 200`, sh.entityID, sh.entityID); err == nil {
		for rows.Next() {
			var l link
			if rows.Scan(&l.Rel, &l.Dir, &l.Type, &l.Key) == nil {
				links = append(links, l)
			}
		}
		_ = rows.Close()
	}
	out["links"] = links
	observations := []obs{}
	if rows, err := db.Query(`SELECT collector, kind, source, observed_at, LENGTH(payload) FROM observations WHERE entity_id = ? ORDER BY observed_at LIMIT 500`, sh.entityID); err == nil {
		for rows.Next() {
			var o obs
			var at int64
			if rows.Scan(&o.Collector, &o.Kind, &o.Source, &at, &o.Bytes) == nil {
				o.ObservedAt = time.Unix(0, at).UTC()
				observations = append(observations, o)
			}
		}
		_ = rows.Close()
	}
	out["observations"] = observations
	writeJSON(w, 200, out)
}

func (g *Gallery) imgThumb(w http.ResponseWriter, r *http.Request) {
	sh := g.byID[r.PathValue("id")]
	if sh == nil {
		http.NotFound(w, r)
		return
	}
	b, err := g.thumbnail(sh)
	if err != nil {
		http.Error(w, "no picture: "+err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "private, max-age=3600")
	_, _ = w.Write(b)
}

func (g *Gallery) imgFull(w http.ResponseWriter, r *http.Request) {
	sh := g.byID[r.PathValue("id")]
	if sh == nil {
		http.NotFound(w, r)
		return
	}
	raw, err := sh.readPicture()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.Error(w, "the picture file is not on disk", http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	w.Header().Set("Content-Type", http.DetectContentType(raw))
	w.Header().Set("Cache-Control", "private, max-age=3600")
	_, _ = w.Write(raw)
}

// Run answers on l until ctx ends.
func (g *Gallery) Run(ctx context.Context, l net.Listener) error {
	srv := &http.Server{Handler: g.Handler(l.Addr().String()), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sh)
	}()
	if err := srv.Serve(l); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
