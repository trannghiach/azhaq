package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/webextract"
)

// Write verdicts, listed before every read verdict.
const (
	verdictWriteAnyone = "anyone writes another role's object"
	verdictWriteCross  = "writes another role's object"
	verdictWriteOwner  = "only its owner writes it"
	verdictWriteVoid   = "the owner's own write was refused"
	verdictWriteDry    = "would be sent (-dry-writes)"
)

func init() {
	verdictOrder[verdictWriteAnyone] = -2
	verdictOrder[verdictWriteCross] = -1
	verdictOrder[verdictWriteOwner] = 20
	verdictOrder[verdictWriteVoid] = 21
	verdictOrder[verdictWriteDry] = -3
}

// writeOp is a write a route takes, as a role's run found it: PUT
// /api/Users/{id} from an API description, a script's call.
type writeOp struct {
	method   string
	bodyType string
}

// writeReq is one write to ask with the other roles' sessions: one its
// owner sent (recorded in the owner's HAR), or a route's write filled with
// the owner's object.
type writeReq struct {
	owner  string
	method string
	url    string
	header http.Header // the request's own headers: never a session's
	body   []byte
	from   string // what it is: "alice.har", or "PUT /api/Users/{id} with an empty body"
	status int    // what the owner got, recorded in its HAR; 0 for a map write
	empty  bool   // a map write: an empty object, which changes nothing
}

// writeMethods reads -replay-writes: the methods to replay, of POST, PUT,
// PATCH and DELETE.
func writeMethods(spec string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, m := range strings.Split(spec, ",") {
		m = strings.ToUpper(strings.TrimSpace(m))
		switch m {
		case "":
		case "POST", "PUT", "PATCH", "DELETE":
			out[m] = true
		default:
			return nil, usagef("-replay-writes %q: want a list of post, put, patch, delete", spec)
		}
	}
	if len(out) == 0 {
		return nil, usagef("-replay-writes: name the methods, such as post,put,patch (add delete to delete objects)")
	}
	return out, nil
}

// har is the part of an HTTP Archive a write replay reads.
type har struct {
	Log struct {
		Entries []struct {
			Request struct {
				Method   string `json:"method"`
				URL      string `json:"url"`
				Headers  []struct{ Name, Value string }
				PostData *struct {
					MimeType string `json:"mimeType"`
					Text     string `json:"text"`
				} `json:"postData"`
			} `json:"request"`
			Response struct {
				Status int `json:"status"`
			} `json:"response"`
		} `json:"entries"`
	} `json:"log"`
}

// keptHeaders are the headers of a recorded request a replay sends: what
// the body is and how the app is asked, never a session (cookies, tokens,
// a CSRF token bound to the owner's session).
var keptHeaders = map[string]bool{"Content-Type": true, "Accept": true, "X-Requested-With": true}

// harWrites reads the writes a role sent, from a HAR its browser or proxy
// saved: the methods asked for, on the run's own hosts, one each.
func harWrites(owner, path string, methods map[string]bool, own map[string]bool) ([]writeReq, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var h har
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, fmt.Errorf("%s: not a HAR file: %w", path, err)
	}
	var out []writeReq
	seen := map[string]bool{}
	for _, e := range h.Log.Entries {
		m := strings.ToUpper(e.Request.Method)
		u, err := url.Parse(e.Request.URL)
		if !methods[m] || err != nil || !own[normalize.Hostname(u.Hostname())] || endsSession(u) {
			continue
		}
		w := writeReq{owner: owner, method: m, url: e.Request.URL, header: http.Header{}, from: filepathBase(path), status: e.Response.Status}
		for _, hd := range e.Request.Headers {
			if k := http.CanonicalHeaderKey(hd.Name); keptHeaders[k] {
				w.header.Set(k, hd.Value)
			}
		}
		if e.Request.PostData != nil {
			w.body = []byte(e.Request.PostData.Text)
			if w.header.Get("Content-Type") == "" && e.Request.PostData.MimeType != "" {
				w.header.Set("Content-Type", e.Request.PostData.MimeType)
			}
		}
		if key := m + " " + w.url + "\x00" + string(w.body); !seen[key] {
			seen[key] = true
			out = append(out, w)
		}
	}
	return out, nil
}

func filepathBase(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

var logoutPath = regexp.MustCompile(`(?i)log[-_]?out|sign[-_]?out|log[-_]?off`)

// endsSession: a write that ends the session it is sent with spoils the
// comparison; it is never replayed.
func endsSession(u *url.URL) bool { return logoutPath.MatchString(u.Path) }

// mapWrites are the writes the routes the runs found take, filled with
// each role's own objects: PUT and PATCH with an empty object, which
// asks for the write and changes nothing; DELETE with no body.
func mapWrites(made map[string]instance, writes map[string][]writeOp, methods map[string]bool) []writeReq {
	var urls []string
	for u, in := range made {
		if in.owner != "" && len(writes[in.template]) > 0 {
			urls = append(urls, u)
		}
	}
	sort.Strings(urls)
	var out []writeReq
	for _, u := range urls {
		in := made[u]
		for _, op := range writes[in.template] {
			m := strings.ToUpper(op.method)
			if !methods[m] {
				continue
			}
			w := writeReq{owner: in.owner, method: m, url: u, header: http.Header{}, from: m + " " + routePath(in.template)}
			switch m {
			case "PUT", "PATCH":
				if op.bodyType != "" && !strings.Contains(op.bodyType, "json") {
					continue // a form's write wants its fields: the HAR has them
				}
				w.body, w.empty = []byte("{}"), true
				w.header.Set("Content-Type", "application/json")
				w.from += " with an empty body"
			case "DELETE":
			default:
				continue // a POST to an object makes something new: the HAR has the real ones
			}
			out = append(out, w)
		}
	}
	return out
}

func routePath(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Path != "" {
		return u.Path
	}
	return raw
}

// replayWrites sends each write with the other roles' sessions, and a map
// write with its owner's first: the owner must be let to write it, and
// its object must not have changed, before the others are asked. A DELETE
// goes to the others alone, the anonymous role first, and stops at the
// first that is let: the object is gone then, and its owner is asked
// whether it is. Every write counts against budget.
func replayWrites(roles []role, reqs []writeReq, answers map[string]map[string]answer, own map[string]bool, rate float64, budget int) ([]roleRow, int, error) {
	ctx := context.Background()
	fetch.Reset()
	defer fetch.Reset()
	fetch.SetRate(rate)
	fetch.Allow = func(h string) bool { return own[normalize.Hostname(h)] }
	client := *fetch.Client(nil)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	sent := 0
	send := func(r role, w writeReq) (answer, error) {
		if sent >= budget {
			return answer{}, errors.New("the replay's request budget is spent")
		}
		sent++
		return sendWrite(ctx, &client, r, w)
	}
	byName := map[string]role{}
	for _, r := range roles {
		byName[r.name] = r
	}
	var rows []roleRow
	var stop error
	for _, w := range reqs {
		owner, ok := byName[w.owner]
		if !ok {
			continue
		}
		row := roleRow{URL: w.url, Method: w.method, Status: map[string]int{}, Answers: map[string]answer{}, FoundBy: []string{w.owner},
			Owner: w.owner, OwnerBy: w.from, reqBody: w.body, reqType: w.header.Get("Content-Type")}
		ownerLet := w.status >= 200 && w.status < 300
		if w.status != 0 {
			row.Answers[w.owner] = answer{Status: w.status}
		}
		if w.empty {
			a, err := send(owner, w)
			if err != nil {
				stop = err
				break
			}
			row.Answers[w.owner] = a
			ownerLet = reads(a)
			checked := ownerLet && sent < budget
			if checked {
				sent++ // the owner's GET of its object, after the write
			}
			if checked && changedBy(owner, w.url, answers[w.owner][w.url]) {
				row.Verdict = verdictWriteVoid
				row.OwnerBy += "; the empty write changed the owner's object: no other role was asked"
				rows = append(rows, finishWriteRow(row))
				continue
			}
		}
		others := otherRoles(roles, w.owner)
		for _, r := range others {
			a, err := send(r, w)
			if err != nil {
				stop = err
				break
			}
			row.Answers[r.name] = a
			if w.method == "DELETE" && reads(a) {
				if gone, err := send(owner, writeReq{method: http.MethodGet, url: w.url, header: http.Header{}}); err == nil {
					row.OwnerBy += fmt.Sprintf("; afterwards its owner got %d for it", gone.Status)
				}
				break
			}
		}
		if stop != nil {
			break
		}
		row.Verdict = writeVerdict(roles, &row, ownerLet)
		rows = append(rows, finishWriteRow(row))
	}
	return rows, sent, stop
}

// otherRoles are the roles a write of owner's is asked with: the
// anonymous ones first, as a DELETE stops at the first let.
func otherRoles(roles []role, owner string) []role {
	var anon, signed []role
	for _, r := range roles {
		switch {
		case r.name == owner:
		case r.anonymous():
			anon = append(anon, r)
		default:
			signed = append(signed, r)
		}
	}
	return append(anon, signed...)
}

// changedBy asks url again as its owner after an empty write: the object
// changed when a value it held is gone or new, timestamps aside.
func changedBy(owner role, u string, before answer) bool {
	if before.Hash == "" {
		return false // nothing to compare with
	}
	fetch.Extra = owner.session.Clone()
	res, _, err := fetch.Do(context.Background(), fetch.Client(nil), u)
	if err != nil {
		return false
	}
	after, _ := resultAnswer(res)
	if after.Hash == before.Hash {
		return false
	}
	for v := range before.held {
		if !after.held[v] && !timeLike.MatchString(v) {
			return true
		}
	}
	for v := range after.held {
		if !before.held[v] && !timeLike.MatchString(v) {
			return true
		}
	}
	return false
}

var timeLike = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}|^\d{10,13}$`)

// sendWrite sends w as r: its method, body and own headers, r's session,
// inside the scope and the run's budget and pace, without following a
// redirect.
func sendWrite(ctx context.Context, client *http.Client, r role, w writeReq) (answer, error) {
	u, err := url.Parse(w.url)
	if err != nil || fetch.Allow != nil && !fetch.Allow(u.Hostname()) {
		return answer{}, fmt.Errorf("%s is outside the scope", w.url)
	}
	if err := fetch.Spend(ctx); err != nil {
		return answer{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, w.method, w.url, bytes.NewReader(w.body))
	if err != nil {
		return answer{}, err
	}
	for k, vs := range w.header {
		req.Header[k] = vs
	}
	fetch.Extra = r.session.Clone()
	fetch.ApplyHeaders(req)
	fetch.Extra = nil
	resp, err := client.Do(req)
	if err != nil {
		return answer{Status: 0}, nil // no answer: the row says so
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	a, _ := readAnswer(resp.StatusCode, body, resp.Header.Get("Content-Type"))
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		a.Location = bareLocation(resp.Header.Get("Location"))
	}
	keepBody(a.Hash, resp.Header.Get("Content-Type"), body)
	return a, nil
}

// writeVerdict: who besides the owner was let to write. A write is let
// when it is answered 2xx and not with an error shaped as data.
func writeVerdict(roles []role, row *roleRow, ownerLet bool) string {
	var anyone, signed []string
	for _, r := range roles {
		a, ok := row.Answers[r.name]
		if !ok || r.name == row.Owner || !reads(a) {
			continue
		}
		if r.anonymous() {
			anyone = append(anyone, r.name)
		} else {
			signed = append(signed, r.name)
		}
	}
	row.Readers = append(anyone, signed...)
	switch {
	case len(anyone) > 0:
		return verdictWriteAnyone
	case len(signed) > 0:
		return verdictWriteCross
	case ownerLet:
		return verdictWriteOwner
	}
	return verdictWriteVoid
}

func finishWriteRow(row roleRow) roleRow {
	for n, a := range row.Answers {
		row.Status[n] = a.Status
	}
	return row
}

// writeRoutes are the writes a run's routes take, by route: the methods
// besides GET its API descriptions and scripts name, with how the body is
// sent.
func (s runSeen) addWrites(raw string, methods []string, ops []struct {
	Method   string `json:"method"`
	BodyType string `json:"body_type"`
}) {
	u, err := normalize.URL(raw)
	if err != nil || !strings.Contains(raw, "{") {
		return
	}
	key := webextract.RouteKey(u)
	have := s.writes[key]
	add := func(m, bt string) {
		m = strings.ToUpper(m)
		if m == "GET" || m == "HEAD" || m == "OPTIONS" || slices.ContainsFunc(have, func(o writeOp) bool { return o.method == m }) {
			return
		}
		have = append(have, writeOp{method: m, bodyType: bt})
	}
	for _, op := range ops {
		add(op.Method, op.BodyType)
	}
	for _, m := range methods {
		add(m, "")
	}
	if len(have) > 0 {
		s.writes[key] = have
	}
}
