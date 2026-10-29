package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	// A write another role sent was answered 2xx, and nothing the owner's
	// object shows can tell whether it took.
	verdictWriteUnread = "writes another role's object: accepted; the change cannot be read back to confirm"
)

func init() {
	verdictOrder[verdictWriteAnyone] = -2
	verdictOrder[verdictWriteCross] = -1
	verdictOrder[verdictWriteUnread] = 0
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

// keptHeaders are the headers of a recorded request a replay sends: what
// the body is and how the app is asked, never a session (cookies, tokens,
// a CSRF token bound to the owner's session).
var keptHeaders = map[string]bool{"Content-Type": true, "Accept": true, "X-Requested-With": true}

// harWrites reads the writes a role sent, from a HAR its browser or proxy
// saved: the methods asked for, on the run's own hosts, one each.
func harWrites(owner, path string, methods map[string]bool, own map[string]bool) ([]writeReq, error) {
	es, err := readHAR(path)
	if err != nil {
		return nil, err
	}
	return writesFrom(owner, filepathBase(path), es, methods, own), nil
}

// writesFrom are the writes of a history's requests that a replay sends.
func writesFrom(owner, from string, entries []histEntry, methods map[string]bool, own map[string]bool) []writeReq {
	var out []writeReq
	seen := map[string]bool{}
	for _, e := range entries {
		u, err := url.Parse(e.url)
		if !methods[e.method] || err != nil || !own[normalize.Hostname(u.Hostname())] || endsSession(u) {
			continue
		}
		w := writeReq{owner: owner, method: e.method, url: e.url, header: http.Header{}, from: from, status: e.status}
		for k, vs := range e.header {
			if kept := http.CanonicalHeaderKey(k); keptHeaders[kept] && len(vs) > 0 {
				w.header.Set(kept, vs[0])
			}
		}
		if len(e.body) > 0 || e.mime != "" {
			w.body = e.body
			if w.header.Get("Content-Type") == "" && e.mime != "" {
				w.header.Set("Content-Type", e.mime)
			}
		}
		if key := e.method + " " + w.url + "\x00" + string(w.body); !seen[key] {
			seen[key] = true
			out = append(out, w)
		}
	}
	return out
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
	latest := map[string]answer{} // the owner's objects as last read: an earlier write may have changed what the run read
	send := func(r role, w writeReq) (answer, error) {
		if sent >= budget {
			return answer{}, fmt.Errorf("%w: some writes were not replayed", errReplayMax)
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
		if err == nil {
			latest[r.name+"\x00"+u] = a
		}
		return a, err == nil
	}
	byName := map[string]role{}
	for _, r := range roles {
		byName[r.name] = r
	}
	var rows []roleRow
	var stop error
	live := map[string]bool{} // owner and URL → the owner could not read it
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
			if b, ok := latest[w.owner+"\x00"+vu]; ok {
				before, haveBefore = b, reads(b)
			} else if b := answers[w.owner][vu]; len(b.held) > 0 && reads(b) {
				before, haveBefore = b, true
			} else if b, ok := read(owner, vu); ok {
				before, haveBefore = b, true
			}
		} else {
			// The history did not read the owner's object: ask for the write's
			// own URL, then its parents, as the owner.
			vu, before, haveBefore = liveVerify(w, owner, live, read)
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
		already := haveBefore && !w.empty && w.method != http.MethodDelete && alreadySet(before, w.body)
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
		why := unreadable(w, vu, before)
		row.Verdict = writeVerdict(&row, let, proven, anon, ownerLet, ownerAsked, vu != "", why, already)
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

// wroteInto: the owner's object now holds a value the write's body sets
// and did not hold before: in the field of that name when the object has
// one (quantity 2, though a ProductId of 2 was there already), else
// anywhere. An empty body names nothing, so any change counts.
func wroteInto(before, after answer, body []byte) bool {
	pairs := bodyPairs(body)
	if len(pairs) == 0 {
		return changed(before, after)
	}
	for _, p := range pairs {
		n := norm(p[0])
		if b, a := before.vals[n], after.vals[n]; len(b) > 0 && len(a) > 0 {
			if slices.Contains(a, p[1]) && !slices.Contains(b, p[1]) {
				return true
			}
			continue
		}
		if after.held[p[1]] && !before.held[p[1]] {
			return true
		}
	}
	return false
}

// alreadySet: the object holds every value the write's body sets, so the
// write cannot be seen to change it.
func alreadySet(obj answer, body []byte) bool {
	pairs := bodyPairs(body)
	for _, p := range pairs {
		if v := obj.vals[norm(p[0])]; len(v) > 0 {
			if !slices.Contains(v, p[1]) {
				return false
			}
		} else if !obj.held[p[1]] {
			return false
		}
	}
	return len(pairs) > 0
}

// bodyPairs are the fields and scalar values a JSON write body sets,
// timestamps aside.
func bodyPairs(body []byte) [][2]string {
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return nil
	}
	var out [][2]string
	for k, x := range m {
		if s, ok := scalarString(x); ok && len(s) <= 64 && !timeLike.MatchString(s) {
			out = append(out, [2]string{k, s})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
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
	if ok2xx(a.Status) && len(body) <= 300 && deniedText.Match(body) {
		a.Refusal = true // a short 2xx answer that says no ("Only Admins may delete users!")
	}
	keepBody(a.Hash, resp.Header.Get("Content-Type"), body)
	return a, nil
}

// deniedText: what a server says when it refuses a write and still answers 2xx.
var deniedText = regexp.MustCompile(`(?i)\bonly\s+(admin|administrator|owner|moderator)s?\b|not\s+(authori[sz]ed|permitted|allowed)|permission\s+denied|access\s+denied|\bforbidden\b|\bunauthori[sz]ed\b|insufficient\s+(privileges|permissions)`)

// writeVerdict reads the replay's result. A cross write is claimed only
// when it was proven (the owner's object changed), and anyone-writes when
// the anonymous role proved it. A role answered 2xx whose write changed
// nothing of the owner's is listed apart, below the proved reads, not as a
// finding.
func writeVerdict(row *roleRow, let, proven []string, anon map[string]bool, ownerLet, ownerAsked, canVerify bool, why string, already bool) string {
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
	case len(let) > 0 && why != "":
		// Accepted, and no GET shows the change: neither proved nor
		// disproved, so listed as what it is.
		row.Readers = let
		row.Evidence = fmt.Sprintf("%s's write was accepted (%d); %s", let[0], row.Answers[let[0]].Status, why)
		return verdictWriteUnread
	case len(let) > 0:
		row.Readers = let
		if already {
			row.OwnerBy += "; the owner's object already held what the write sets: no change could show"
		} else if canVerify {
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

// unreadable says why a write's change cannot be read back, or "" when it
// can: no GET of the owner's object answers, or the object it shows has none
// of the fields the write sets (a password is never in the user's answer).
// An empty write sets nothing to read back.
func unreadable(w writeReq, vu string, before answer) string {
	if w.empty {
		return ""
	}
	if vu == "" {
		return "no GET of the owner's object can be read, to see it change"
	}
	if w.method == http.MethodDelete {
		return ""
	}
	fields := setFields(w)
	if len(fields) == 0 || len(before.Keys) == 0 {
		return ""
	}
	have := map[string]bool{}
	for _, k := range before.Keys {
		k = strings.TrimSuffix(k, "[]")
		have[norm(k[strings.LastIndexAny(k, ".")+1:])] = true
	}
	for _, f := range fields {
		if have[norm(f)] {
			return ""
		}
	}
	return fmt.Sprintf("%s shows no %s, the field the write sets", pathOf(vu), strings.Join(fields, "/"))
}

// setFields are the names of the fields a write's body sets: a JSON object's
// or a form's.
func setFields(w writeReq) []string {
	var out []string
	var m map[string]any
	if json.Unmarshal(w.body, &m) == nil {
		for k := range m {
			out = append(out, k)
		}
	} else if q, err := url.ParseQuery(string(w.body)); err == nil && !strings.Contains(w.header.Get("Content-Type"), "json") {
		for k := range q {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// liveVerify finds the owner's object a write can be checked against when
// no answer of the history holds it: the write's own URL, then its parents
// down to two segments, each read as the owner (at most once each).
func liveVerify(w writeReq, owner role, live map[string]bool, read func(role, string) (answer, bool)) (string, answer, bool) {
	if w.method == http.MethodPost {
		return "", answer{}, false
	}
	pu, err := url.Parse(w.url)
	if err != nil {
		return "", answer{}, false
	}
	path := strings.TrimRight(pu.Path, "/")
	for first := true; ; first = false {
		last := path[strings.LastIndex(path, "/")+1:]
		if first || !versionSeg.MatchString(norm(last)) { // /users/v1 is the collection, not an object
			cand := *pu
			cand.Path, cand.RawPath, cand.RawQuery, cand.Fragment = path, "", "", ""
			u := cand.String()
			key := owner.name + "\x00" + u
			if !live[key] { // a failed read is not tried again; a good one is read afresh
				if got, ok := read(owner, u); ok && reads(got) {
					return u, got, true
				}
				live[key] = true
			}
		}
		if strings.Count(path, "/") < 3 {
			return "", answer{}, false // a parent one segment deep is a collection
		}
		path = path[:strings.LastIndex(path, "/")]
	}
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
