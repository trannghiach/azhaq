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

// Write verdicts. A proved cross write is listed above every read; a write
// that was answered but changed nothing of the owner's ranks below the
// proved reads.
const (
	verdictWriteAnyone   = "anyone writes another role's object"
	verdictWriteCross    = "writes another role's object"
	verdictWriteCreate   = "creates in another role's collection"
	verdictWriteNoChange = "answered 2xx but changed nothing of the owner's"
	verdictWriteOwner    = "only its owner writes it"
	verdictWriteVoid     = "the owner's own write was refused"
	verdictWriteRefused  = "the other roles were refused"
	verdictWriteDry      = "would be sent (-dry-writes)"
)

func init() {
	verdictOrder[verdictWriteAnyone] = -2
	verdictOrder[verdictWriteCross] = -1
	verdictOrder[verdictWriteDry] = -3
	verdictOrder[verdictWriteNoChange] = 15
	verdictOrder[verdictWriteCreate] = 16
	verdictOrder[verdictWriteOwner] = 20
	verdictOrder[verdictWriteVoid] = 21
	verdictOrder[verdictWriteRefused] = 20
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
	empty  bool   // a map write: an empty object, sent first as its owner
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
// each role's own objects: PATCH with an empty object, which asks for the
// write and changes nothing; PUT with an empty object, which changes
// nothing on a server that updates the fields sent and may clear the
// object on one that replaces it, so the owner's own goes first and its
// object is read again before anyone else is asked; DELETE with no body.
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

// replayWrites sends each write with the other roles' sessions and proves
// a cross-role write before it claims one: the owner's object is read as
// the owner before and after the write, and "X writes Y's object" is kept
// only when that object changed the way the write asks (or was deleted). A
// 2xx that left the owner's object unchanged is answered-but-changed-
// nothing, not a finding. A POST to a collection is a create, never a
// cross write. A map write (empty body) is sent first with its owner's
// session: the owner must be let, and its own object must not change. A
// DELETE goes to the others alone, the anonymous role first, and stops at
// the first proven. Every request counts against budget.
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
	// read gets the owner's object again, to see whether a write changed
	// it; a budget spent or a failed read leaves the write unproven.
	read := func(r role, u string) (answer, bool) {
		if sent >= budget {
			return answer{}, false
		}
		sent++
		a, err := readAs(ctx, &client, r, u)
		return a, err == nil
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
		if w.status != 0 {
			row.Answers[w.owner] = answer{Status: w.status}
		}
		// A POST to a collection makes a new object: never another role's
		// object written.
		if w.method == http.MethodPost {
			if err := replayCollection(&row, roles, w, send); err != nil {
				stop = err
				rows = append(rows, finishWriteRow(row))
				break
			}
			rows = append(rows, finishWriteRow(row))
			continue
		}
		vu := verifyURL(w, answers)
		ownerLet := w.status >= 200 && w.status < 300
		// The owner's object before any write: the one the owner's run
		// already read when its body is at hand, else read fresh, so its
		// values are there to compare against.
		var before answer
		haveBefore := false
		if vu != "" {
			if b := answers[w.owner][vu]; len(b.held) > 0 && reads(b) {
				before, haveBefore = b, true
			} else if b, ok := read(owner, vu); ok {
				before, haveBefore = b, true
			}
		}
		if w.empty {
			a, err := send(owner, w)
			if err != nil {
				stop = err
				break
			}
			row.Answers[w.owner] = a
			ownerLet = reads(a)
			if ownerLet && haveBefore {
				if after, ok := read(owner, vu); ok {
					if changed(before, after) {
						row.Verdict = verdictWriteVoid
						row.OwnerBy += "; the empty write changed the owner's object: no other role was asked"
						rows = append(rows, finishWriteRow(row))
						continue
					}
					before = after
				}
			}
		}
		var let, proven []string
		anon := map[string]bool{}
		for _, r := range otherRoles(roles, w.owner) {
			a, err := send(r, w)
			if err != nil {
				stop = err
				break
			}
			row.Answers[r.name] = a
			if !reads(a) {
				continue
			}
			let = append(let, r.name)
			if r.anonymous() {
				anon[r.name] = true
			}
			if vu == "" {
				continue // the owner's object cannot be read: let, but unproven
			}
			after, ok := read(owner, vu)
			if !ok {
				continue
			}
			if provesCross(w, before, after) {
				proven = append(proven, r.name)
				row.OwnerBy += "; " + writeProof(w, r.name, after)
				if w.method == http.MethodDelete {
					break // the object is gone
				}
			}
			before = after
		}
		if stop != nil {
			break
		}
		// A map DELETE is never asked of its owner: it would delete it.
		ownerAsked := w.status != 0 || w.empty
		row.Verdict = writeVerdict(&row, let, proven, anon, ownerLet, ownerAsked, vu != "")
		rows = append(rows, finishWriteRow(row))
	}
	return rows, sent, stop
}

// replayCollection replays a POST, which creates a new object in a
// collection. It is sent with the other roles, and a role that is let can
// create there, but a create is never another role's object written.
func replayCollection(row *roleRow, roles []role, w writeReq, send func(role, writeReq) (answer, error)) error {
	var let []string
	for _, r := range otherRoles(roles, w.owner) {
		a, err := send(r, w)
		if err != nil {
			return err
		}
		row.Answers[r.name] = a
		if reads(a) {
			let = append(let, r.name)
		}
	}
	row.Readers = let
	if len(let) > 0 {
		row.Verdict = verdictWriteCreate
	} else {
		row.Verdict = verdictWriteRefused
	}
	return nil
}

// provesCross: the owner's object changed the way the write asks. A DELETE
// is proven when the object is gone; a PUT or PATCH with a body when one
// of its values is now in the object and was not before; an empty PUT or
// PATCH when any value the object held changed (timestamps aside).
func provesCross(w writeReq, before, after answer) bool {
	if w.method == http.MethodDelete {
		return !reads(after)
	}
	if w.empty {
		return changed(before, after)
	}
	return wroteInto(before, after, w.body)
}

// writeProof says, for owner_by, what the owner's object showed after the
// cross write.
func writeProof(w writeReq, reader string, after answer) string {
	if w.method == http.MethodDelete {
		return "after " + reader + "'s DELETE the owner's object is gone (" + answerCell(after) + ")"
	}
	return "after " + reader + "'s " + w.method + " the owner's object changed to match it"
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

// changed: after differs from before in a value the object held, timestamps
// aside.
func changed(before, after answer) bool {
	if before.Hash == "" || after.Hash == "" || after.Hash == before.Hash {
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

// wroteInto: the owner's object now holds a value the write's body asks
// for and did not hold before. An empty body names nothing, so any change
// counts.
func wroteInto(before, after answer, body []byte) bool {
	vals := bodyValues(body)
	if len(vals) == 0 {
		return changed(before, after)
	}
	for _, v := range vals {
		if after.held[v] && !before.held[v] {
			return true
		}
	}
	return false
}

// bodyValues are the scalar values a JSON write body sets, timestamps aside.
func bodyValues(body []byte) []string {
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return nil
	}
	var out []string
	for _, x := range m {
		if s, ok := scalarString(x); ok && len(s) <= 64 && !timeLike.MatchString(s) {
			out = append(out, s)
		}
	}
	return out
}

// verifyURL is the owner's readable object a write is checked against: the
// write's own URL when the owner reads it (PUT, PATCH, DELETE on an
// object), else a readable ancestor (/users/v1/alice for a write to
// /users/v1/alice/email). "" when none is found.
func verifyURL(w writeReq, answers map[string]map[string]answer) string {
	ownerReads := func(u string) (string, bool) {
		if a, ok := answers[w.owner][u]; ok && reads(a) {
			return u, true
		}
		if n, err := normalize.URL(u); err == nil {
			if a, ok := answers[w.owner][n]; ok && reads(a) {
				return n, true
			}
		}
		return "", false
	}
	if u, ok := ownerReads(w.url); ok {
		return u
	}
	pu, err := url.Parse(w.url)
	if err != nil {
		return ""
	}
	path := strings.TrimRight(pu.Path, "/")
	for strings.Count(path, "/") > 1 {
		path = path[:strings.LastIndex(path, "/")]
		cand := *pu
		cand.Path, cand.RawQuery, cand.Fragment = path, "", ""
		if u, ok := ownerReads(cand.String()); ok {
			return u
		}
	}
	return ""
}

// readAs reads u as role r, past the cache, inside the scope and pace,
// without following a redirect; the body is kept as evidence.
func readAs(ctx context.Context, client *http.Client, r role, u string) (answer, error) {
	pu, err := url.Parse(u)
	if err != nil || fetch.Allow != nil && !fetch.Allow(pu.Hostname()) {
		return answer{}, fmt.Errorf("%s is outside the scope", u)
	}
	if err := fetch.Spend(ctx); err != nil {
		return answer{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return answer{}, err
	}
	fetch.Extra = r.session.Clone()
	fetch.ApplyHeaders(req)
	fetch.Extra = nil
	resp, err := client.Do(req)
	if err != nil {
		return answer{}, err
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

// writeVerdict reads the replay's result. A cross write is claimed only
// when it was proven (the owner's object changed), and anyone-writes when
// the anonymous role proved it. A role answered 2xx whose write changed
// nothing of the owner's is listed apart, below the proved reads, not as a
// finding.
func writeVerdict(row *roleRow, let, proven []string, anon map[string]bool, ownerLet, ownerAsked, canVerify bool) string {
	var provenAnon, provenSigned []string
	for _, n := range proven {
		if anon[n] {
			provenAnon = append(provenAnon, n)
		} else {
			provenSigned = append(provenSigned, n)
		}
	}
	switch {
	case len(provenAnon) > 0:
		row.Readers = append(provenAnon, provenSigned...)
		return verdictWriteAnyone
	case len(provenSigned) > 0:
		row.Readers = provenSigned
		return verdictWriteCross
	case len(let) > 0:
		row.Readers = let
		if canVerify {
			row.OwnerBy += "; the owner's object was unchanged after the write"
		} else {
			row.OwnerBy += "; the owner's object could not be read to verify the write"
		}
		return verdictWriteNoChange
	case ownerLet:
		return verdictWriteOwner
	case !ownerAsked:
		return verdictWriteRefused
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
