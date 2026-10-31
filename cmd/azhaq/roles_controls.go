package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/internal/egress"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/normalize"
)

// Negative controls: a role that reads another role's object is asked for
// a made-up identifier of the same shape on the same route. A route that
// answers that one as it answers a real object answers any identifier,
// and its 2xx says nothing of who may read what.

const verdictAnyID = "answers any identifier"

func init() { verdictOrder[verdictAnyID] = 2 }

// control is what the readers of a cross read got for a made-up
// identifier on the same route.
type control struct {
	URL     string            `json:"url"`
	Value   string            `json:"value"`
	Answers map[string]answer `json:"answers"`         // each reader's
	Alike   []string          `json:"alike,omitempty"` // the readers it answered as a real object
}

// askControls asks each cross read's readers for a made-up identifier on
// its route, at most budget requests. A row whose route answered every
// reader's made-up identifier alike answers any identifier; a reader it
// answered alike beside one it did not is no longer one of its readers.
// A reader is asked once per route and shape of identifier.
func askControls(roles []role, rows []roleRow, own map[string]bool, pages []refusalPage, refusal *regexp.Regexp, budget int) (int, error) {
	byName := map[string]role{}
	for _, r := range roles {
		byName[r.name] = r
	}
	ctx := context.Background()
	fakes := map[string]string{} // route and shape → the made-up value
	asked := map[string]answer{} // URL and reader → its answer
	held := map[string][]byte{}  // URL and reader → its body
	sent := 0
	for i := range rows {
		row := &rows[i]
		if row.Verdict != verdictCross || row.From == "" || row.value == "" {
			continue
		}
		key := row.From + "\x00" + idShape(row.value) + "\x00" + strconv.Itoa(len(row.value))
		fake, ok := fakes[key]
		if !ok {
			fake = madeUp(row.value)
			fakes[key] = fake
		}
		fu, ok := swapValue(row.URL, row.From, row.value, fake)
		if fake == "" || !ok {
			continue
		}
		c := &control{URL: fu, Value: fake, Answers: map[string]answer{}}
		for _, n := range row.Readers {
			k := fu + "\x00" + n
			a, ok := asked[k]
			if !ok {
				if sent >= budget {
					return sent, fmt.Errorf("%w: some cross reads were not checked with a made-up identifier", errReplayMax)
				}
				var body []byte
				var err error
				a, body, err = askFresh(ctx, byName[n].session, fu, own)
				sent++
				if err != nil {
					continue
				}
				if ok2xx(a.Status) && (matchesPage(fu, a, pages) || refusal != nil && refusal.Match(body)) {
					a.Refusal = true
				}
				asked[k], held[k] = a, body
			}
			c.Answers[n] = a
			if answersAnything(a, row.Answers[n], held[k], fake) {
				c.Alike = append(c.Alike, n)
			}
		}
		if len(c.Answers) == 0 {
			continue
		}
		row.Control = c
		switch {
		case len(c.Alike) == len(row.Readers):
			row.Verdict = verdictAnyID
		case len(c.Alike) > 0:
			row.Readers = slices.DeleteFunc(row.Readers, func(n string) bool { return slices.Contains(c.Alike, n) })
		}
	}
	return sent, nil
}

// answersAnything: the made-up identifier's answer is read as a real
// object's: the same body, or a JSON answer with the same fields holding
// data besides the made-up identifier (not a template of nulls).
func answersAnything(c, real answer, body []byte, fake string) bool {
	if !reads(c) || !reads(real) {
		return false
	}
	if c.Hash == real.Hash {
		return true
	}
	if !c.nested || len(real.Keys) == 0 || len(c.Keys) == 0 || fieldsDiffer(c, real) {
		return false
	}
	var v any
	return json.Unmarshal(body, &v) == nil && holdsData(v, "", fake, 0)
}

// holdsData: a JSON value holds a value besides the envelope's (status,
// message) and those made of fake: a template of nulls and the identifier
// asked for ("Book q-mfkrb") is a "not found" shaped as data.
func holdsData(v any, k, fake string, depth int) bool {
	if depth > maxDepth {
		return false
	}
	switch t := v.(type) {
	case map[string]any:
		for ck, cv := range t {
			if depth == 0 && envelope[norm(ck)] && norm(ck) != "data" && norm(ck) != "result" && norm(ck) != "results" {
				continue
			}
			if holdsData(cv, ck, fake, depth+1) {
				return true
			}
		}
	case []any:
		for _, e := range t {
			if holdsData(e, k, fake, depth+1) {
				return true
			}
		}
	case bool:
		return true
	case nil:
	default:
		s, ok := scalarString(t)
		return ok && !strings.Contains(s, fake)
	}
	return false
}

var uuidShape = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// madeUp is an identifier shaped like v that names no object: a number
// 1000003 past it (as long, at least), a random UUID, or a random string
// of v's length with each letter and digit replaced by one of its kind.
// "" when v has no letter or digit to change.
func madeUp(v string) string {
	if strings.Trim(v, "0123456789") == "" {
		if n, err := strconv.ParseUint(v, 10, 63); err == nil {
			s := strconv.FormatUint(n+1000003, 10)
			if len(s) < len(v) {
				s = strings.Repeat("0", len(v)-len(s)) + s
			}
			return s
		}
	}
	if uuidShape.MatchString(v) {
		b := make([]byte, 16)
		for i := range b {
			b[i] = byte(rand.IntN(256))
		}
		b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80
		s := fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
		if strings.ToUpper(v) == v {
			s = strings.ToUpper(s)
		}
		return s
	}
	for range 8 {
		out := []byte(v)
		changed := false
		for i, c := range out {
			switch {
			case c >= 'a' && c <= 'z':
				out[i] = byte('a' + rand.IntN(26))
			case c >= 'A' && c <= 'Z':
				out[i] = byte('A' + rand.IntN(26))
			case c >= '0' && c <= '9':
				out[i] = byte('0' + rand.IntN(10))
			default:
				continue
			}
			changed = true
		}
		if !changed {
			return ""
		}
		if s := string(out); s != v {
			return s
		}
	}
	return ""
}

// swapValue is the object URL u, made from template with value, made with
// fake instead.
func swapValue(u, template, value, fake string) (string, bool) {
	i := strings.Index(template, "{")
	if i < 0 {
		return "", false
	}
	prefix, esc := template[:i], url.PathEscape(value)
	if !strings.HasPrefix(u, prefix) || !strings.HasPrefix(u[len(prefix):], esc) {
		return "", false
	}
	return prefix + url.PathEscape(fake) + u[len(prefix)+len(esc):], true
}

// askFresh asks u once with header h, past the process cache, inside the
// scope (own) and the run's pace, without following a redirect; the body
// is kept as evidence.
func askFresh(ctx context.Context, h http.Header, u string, own map[string]bool) (answer, []byte, error) {
	p, err := url.Parse(u)
	if err != nil || !own[normalize.Hostname(p.Hostname())] {
		return answer{}, nil, fmt.Errorf("%s is outside the scope", u)
	}
	if err := egress.Spend(ctx); err != nil {
		return answer{}, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return answer{}, nil, err
	}
	for k, vs := range h {
		req.Header[k] = append([]string(nil), vs...)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", fetch.UserAgent)
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	}
	resp, err := fetch.Client(nil).Do(req)
	if err != nil {
		return answer{}, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(fetch.MaxBody)))
	ctype := resp.Header.Get("Content-Type")
	a, _ := readAnswer(resp.StatusCode, body, ctype)
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		a.Location = bareLocation(resp.Header.Get("Location"))
	}
	keepBody(a.Hash, ctype, body)
	return a, body, nil
}

// bothWays notes the routes on which two roles read each other's objects,
// and marks those rows.
func bothWays(rows []roleRow) []string {
	reads := map[string]map[string]bool{} // route → "reader\x00owner"
	for _, row := range rows {
		if row.Verdict != verdictCross || row.From == "" {
			continue
		}
		if reads[row.From] == nil {
			reads[row.From] = map[string]bool{}
		}
		for _, n := range row.Readers {
			reads[row.From][n+"\x00"+row.Owner] = true
		}
	}
	var notes []string
	said := map[string]bool{}
	for i := range rows {
		row := &rows[i]
		if row.Verdict != verdictCross || row.From == "" {
			continue
		}
		for _, n := range row.Readers {
			if !reads[row.From][row.Owner+"\x00"+n] {
				continue
			}
			row.BothWays = true
			row.mutual = append(row.mutual, n)
			a, b := min(n, row.Owner), max(n, row.Owner)
			if k := row.From + "\x00" + a + "\x00" + b; !said[k] {
				said[k] = true
				notes = append(notes, fmt.Sprintf("%s and %s read each other's objects on %s", a, b, pathOf(row.From)))
			}
		}
	}
	return notes
}
