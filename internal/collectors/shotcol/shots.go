// Package shotcol takes a screenshot of each web service's front page
// (-screenshots DIR) with a Chrome installed on the machine, and a
// perceptual hash so look-alike pages (default installs, login portals,
// parked domains) can be grouped.
package shotcol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"math/bits"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/corona10/goimagehash"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/browser"
	"github.com/trannghiach/azhaq/internal/collectors/rendercol"
	"github.com/trannghiach/azhaq/internal/egress"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/fingerprint"
	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/types"
)

const Name = "azhaq-shots"

type Collector struct {
	Dir     string
	Browser *browser.Browser
	// Only restricts the guessed schemes of a name or an address to
	// "http" or "https"; empty tries https, then http.
	Only string
	// Ports are the web ports tried on each name and address; empty: 443,
	// then 80.
	Ports  []int
	NoTech bool // no technologies from the rendered page
	HTML   bool // keep the rendered page beside the picture

	shot sync.Map // pages already taken: a name and its URL are one page
	need sync.Map // URL → requests the page asked for when the budget cut it short
}

func (c *Collector) Name() string { return Name }

// Forget lets a page, or the front pages of a name, be taken again, after a
// session that ended made the picture wrong (catalog.Forgetter).
func (c *Collector) Forget(key string) {
	if strings.Contains(key, "://") {
		c.shot.Delete(key)
		return
	}
	h := normalize.Hostname(key)
	if ip := net.ParseIP(h); ip != nil && ip.To4() == nil {
		h = "[" + h + "]"
	}
	for _, tries := range c.guesses(h) {
		for _, t := range tries {
			c.shot.Delete(t)
		}
	}
}

// Info: loads the page with its scripts and images, as a browser does.
func (c *Collector) Info() catalog.Info {
	return catalog.Info{Kind: catalog.Touch, After: "azhaq-http", Local: true, Redo: true}
}

func (c *Collector) Inputs() []types.SeedType {
	return []types.SeedType{types.TypeURL, types.TypeHostname, types.TypeIPAddress}
}

func (c *Collector) Outputs() []string { return []string{"screenshot"} }

// Skip: only with -screenshots, and only front pages, and the pages the
// user named (types.GivenKey), whatever their path. A name taken from a
// front-page URL is that URL's own shot, not a guess on both schemes.
func (c *Collector) Skip(seed types.Seed) bool {
	if c.Dir == "" || c.Browser == nil {
		return true
	}
	switch seed.Type {
	case types.TypeHostname:
		if from := seed.Keys[types.FromURLKey]; from != "" {
			if u, err := url.Parse(from); err == nil && (u.Path == "" || u.Path == "/") && u.RawQuery == "" {
				return true
			}
		}
		return false
	case types.TypeIPAddress:
		return seed.Keys["from"] != "prefix"
	}
	u, err := url.Parse(seed.Keys["url"])
	if err != nil {
		return true
	}
	return (u.Path != "" && u.Path != "/" || u.RawQuery != "") && seed.Keys[types.GivenKey] == ""
}

// budgetLeft is how many requests the run may still send, or -1 without a cap.
func budgetLeft() int {
	if egress.MaxRequests() <= 0 {
		return -1
	}
	return int(max(egress.MaxRequests()-egress.Sent(), 0))
}

// notTaken says in the summary that the budget left no room for a page
// and no image was saved. need is what the page asked for, 0 when it
// never loaded.
func notTaken(raw string, need, left int) {
	if need == 0 {
		fetch.Note(fmt.Sprintf("screenshot of %s not taken: the budget was spent before the page loaded (raise -max-requests)", raw))
		return
	}
	fetch.Note(fmt.Sprintf("screenshot of %s not taken: the page needs about %d requests and %d were left (raise -max-requests)", raw, need, left))
}

var unsafeName = regexp.MustCompile(`[^a-zA-Z0-9.-]+`)

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	if seed.Type == types.TypeURL {
		raw, err := normalize.URL(seed.Keys["url"])
		if err != nil {
			return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
		}
		return c.shoot(ctx, []string{raw}, true, emit)
	}
	// A name or an address: the front page of each web port asked for
	// (443 and 80 without any), HTTPS first, as the HTTP collector tries it.
	h := normalize.Hostname(seed.Key())
	if ip := net.ParseIP(h); ip != nil && ip.To4() == nil {
		h = "[" + h + "]"
	}
	meta := types.RunMeta{Status: types.StatusOK}
	for _, tries := range c.guesses(h) {
		m, err := c.shoot(ctx, tries, false, emit)
		meta.EmitCount += m.EmitCount
		if err != nil || m.Status != types.StatusOK {
			m.EmitCount = meta.EmitCount
			return m, err
		}
	}
	return meta, nil
}

// guesses are the URLs to try for host, a group to a service: the first
// of a group that gives a picture stands for it.
func (c *Collector) guesses(host string) [][]string {
	var groups [][]string
	if len(c.Ports) == 0 {
		groups = [][]string{{"https://" + host + "/", "http://" + host + "/"}}
	}
	for _, p := range c.Ports {
		hp := net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(p))
		switch p {
		case 80:
			groups = append(groups, []string{"http://" + host + "/", "https://" + hp + "/"})
		case 443:
			groups = append(groups, []string{"https://" + host + "/", "http://" + hp + "/"})
		default:
			groups = append(groups, []string{"https://" + hp + "/", "http://" + hp + "/"})
		}
	}
	if c.Only == "" {
		return groups
	}
	var out [][]string
	for _, g := range groups {
		var keep []string
		for _, u := range g {
			if strings.HasPrefix(u, c.Only+"://") {
				keep = append(keep, u)
			}
		}
		if len(keep) > 0 {
			out = append(out, keep)
		}
	}
	return out
}

// shoot takes the first of tries that gives a picture; isURL says the user
// named the page, and one that gave none is then a failure.
func (c *Collector) shoot(ctx context.Context, tries []string, isURL bool, emit func(types.Observation) error) (types.RunMeta, error) {
	var p browser.Page
	var err error
	raw := ""
	for _, t := range tries {
		if _, done := c.shot.LoadOrStore(t, true); done {
			return types.RunMeta{Status: types.StatusOK}, nil // taken, or being taken, through another seed
		}
		raw = t
		left := budgetLeft()
		if err := egress.SpendUnpaced(ctx); err != nil {
			c.shot.Delete(t)
			if errors.Is(err, neterr.ErrBudget) {
				v, _ := c.need.Load(t)
				n, _ := v.(int)
				notTaken(t, n, left)
			}
			return types.RunMeta{Status: types.StatusCapped}, err
		}
		p, err = c.Browser.Load(ctx, t, true)
		if p.Capped {
			c.shot.Delete(t)
			c.need.Store(t, p.Asked)
			notTaken(t, p.Asked, left)
			return types.RunMeta{Status: types.StatusCapped}, neterr.ErrBudget
		}
		for _, s := range []struct {
			why  string
			urls []string
		}{{browser.Reason(), p.Blocked}, {browser.DownloadReason, p.Downloads}} {
			if len(s.urls) == 0 {
				continue
			}
			payload, _ := json.Marshal(map[string]any{"skipped": s.why, "urls": s.urls})
			if err := emit(types.Observation{Collector: Name, Source: t, Kind: "skipped", Payload: payload, Confidence: 0.9, ObservedAt: time.Now().UTC()}); err != nil {
				return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
			}
		}
		for _, o := range rendercol.WriteFacts(Name, t, p.Writes) {
			if err := emit(o); err != nil {
				return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
			}
		}
		if p.Left != "" {
			// Redirected outside the scope: what shows is Chrome's error,
			// not the target's page.
			return types.RunMeta{Status: types.StatusOK}, nil
		}
		if p.Skipped != "" {
			// It answered, and the user asked for other statuses: listed.
			// The HTTP collector asked for this page, so the summary's list of
			// what was left alone would not name it: a note says it.
			payload, _ := json.Marshal(map[string]any{"note": fmt.Sprintf("screenshot of %s not taken: it %s", t, p.Skipped)})
			return types.RunMeta{Status: types.StatusOK}, emit(types.Observation{Collector: Name, Source: t, Kind: "note", Payload: payload, Confidence: 0.9, ObservedAt: time.Now().UTC()})
		}
		if err == nil && len(p.Image) > 0 {
			break
		}
		c.shot.Delete(t) // another seed for the same page may try again
	}
	if len(p.Image) == 0 {
		if !isURL {
			return types.RunMeta{Status: types.StatusOK}, nil // no web service there
		}
		msg := "no screenshot"
		if err != nil {
			msg = err.Error()
		}
		return types.RunMeta{Status: types.StatusError, Error: msg}, err
	}
	u, _ := url.Parse(raw)
	base := baseName(u, raw)
	if err := os.MkdirAll(c.Dir, 0o755); err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	ext := ".png"
	if p.Format == "jpeg" {
		ext = ".jpg"
	}
	file := filepath.Join(c.Dir, base+ext)
	if err := os.WriteFile(file, p.Image, 0o644); err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	row := map[string]any{"url": raw, "file": file, "file_path": absPath(file), "file_name": base + ext, "format": p.Format, "title": p.Title, "final_url": p.URL,
		"bytes": len(p.Image), "probed_at": time.Now().UTC().Format(time.RFC3339)}
	if c.HTML {
		hf := filepath.Join(c.Dir, base+".html")
		if err := os.WriteFile(hf, []byte(p.HTML), 0o644); err != nil {
			return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
		}
		row["html_file"] = hf
	}
	addRecord(row, p, c.NoTech)
	var why []string
	if p.Partial {
		// Taken, and saved, but short of what the page draws: said in the
		// summary, which then exits 3.
		row["partial"], row["unloaded"], row["resources"] = true, p.Unloaded, p.Resources
		why = append(why, fmt.Sprintf("%d of %d images, styles and scripts were not loaded when it was taken (the pace, -max-requests or a slow server; -shot-timeout and -rate change it)", p.Unloaded, p.Resources))
	}
	if p.OffScope > 0 {
		// Chrome is held to the scope: what the page loads from outside it
		// (a CDN's styles, fonts, scripts) is not asked for, and the page
		// is drawn without it.
		row["partial"], row["blocked"], row["blocked_hosts"] = true, p.OffScope, p.OffScopeHosts
		why = append(why, fmt.Sprintf("%d requests to %s outside the scope were blocked, so it is drawn without those assets; %s", p.OffScope, strings.Join(p.OffScopeHosts, ", "), allowAdvice(u, p.OffScopeHosts)))
	}
	if len(why) > 0 {
		row["note"] = fmt.Sprintf("screenshot of %s is partial: %s", raw, strings.Join(why, "; "))
	}
	if h, ok := DHash(p.Image); ok {
		row["phash"], row["perception_hash"] = h, h
	}
	payload, _ := json.Marshal(row)
	return types.RunMeta{Status: types.StatusOK, EmitCount: 1}, emit(types.Observation{
		Collector: Name, Source: raw, Kind: "screenshot", Payload: payload, Confidence: 0.9, ObservedAt: time.Now().UTC(),
	})
}

// allowAdvice says how to let the page load the assets of hosts: -allow
// names them, and with any -allow the page's own host must be named too.
func allowAdvice(page *url.URL, hosts []string) string {
	var flags []string
	if !egress.HasScope() && page != nil && page.Hostname() != "" {
		flags = append(flags, "-allow "+page.Hostname()) // any -allow replaces the default scope, the page's site
	}
	for _, h := range hosts {
		flags = append(flags, "-allow "+h)
	}
	return strings.Join(flags, " ") + " loads them"
}

// PartialWhy says in a few words what a picture lacks of its page: the
// assets of hosts outside the scope that were blocked, and the images,
// styles and scripts that had not loaded. "" for a whole one.
func PartialWhy(unloaded, resources, blocked int, hosts []string) string {
	var parts []string
	if blocked > 0 {
		what := "assets"
		if blocked == 1 {
			what = "asset"
		}
		shown := hosts
		if len(shown) > 5 {
			shown = append(slices.Clone(hosts[:5]), "…")
		}
		parts = append(parts, fmt.Sprintf("%d off-scope %s blocked: %s", blocked, what, strings.Join(shown, ", ")))
	}
	if unloaded > 0 {
		parts = append(parts, fmt.Sprintf("%d of %d images, styles and scripts not loaded", unloaded, resources))
	}
	return strings.Join(parts, "; ")
}

// baseName is the file a page's picture is kept in, without its
// extension: scheme, host and port, and for a page that is not the front
// one its path and query, so that two pages of a host are two files.
func baseName(u *url.URL, raw string) string {
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	name := unsafeName.ReplaceAllString(u.Scheme+"_"+u.Hostname()+"_"+port, "_")
	if rest := u.RequestURI(); rest != "/" && rest != "" {
		sum := sha256.Sum256([]byte(raw))
		tail := strings.Trim(unsafeName.ReplaceAllString(rest, "_"), "_")
		name += "_" + tail[:min(len(tail), 80)] + "_" + hex.EncodeToString(sum[:4])
	}
	return name
}

// addRecord puts what Chrome saw of the page in the row: the answer, its
// headers, the TLS session, the technologies of the rendered page, the
// console and the requests.
func addRecord(row map[string]any, p browser.Page, noTech bool) {
	r := p.Record
	if r.Status != 0 {
		row["response_code"] = r.Status
	}
	if r.Reason != "" {
		row["response_reason"] = r.Reason
	}
	if r.Protocol != "" {
		row["protocol"] = r.Protocol
	}
	if r.ContentLength > 0 {
		row["content_length"] = r.ContentLength // bytes on the wire for the page's document
	}
	if len(r.Headers) > 0 {
		row["headers"] = r.Headers
	}
	if r.TLS != nil {
		row["tls"] = r.TLS
	}
	if len(r.Network) > 0 {
		row["network"] = r.Network
		if r.NetworkMore > 0 {
			row["network_more"] = r.NetworkMore
		}
	}
	if len(r.Console) > 0 {
		row["console"] = r.Console
	}
	if !noTech && p.HTML != "" {
		h := http.Header{}
		for _, kv := range r.Headers {
			h.Add(kv.Key, kv.Value)
		}
		var tech []map[string]string
		for _, t := range fingerprint.Tech(h, []byte(p.HTML)) {
			tech = append(tech, map[string]string{"value": t})
		}
		if len(tech) > 0 {
			row["technologies"] = tech
		}
	}
}

// HashPrefix marks a perceptual hash (a DCT hash of the picture); the
// 9×8 difference hash of earlier runs has none and is not comparable.
const HashPrefix = "p:"

// DHash is a 64-bit perceptual hash of an image, "p:" and 16 hex digits:
// the picture scaled to 32×32 grey, its low frequencies by a discrete
// cosine transform, each compared with their median. Pages that look
// alike have hashes a few bits apart; a sparse page (a login form on
// white) still differs from another, where a hash of brightness steps
// gave all of them the same few bits. The name is kept for its callers.
func DHash(data []byte) (string, bool) {
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return "", false
	}
	b := img.Bounds()
	if b.Dx() < 8 || b.Dy() < 8 {
		return "", false
	}
	h, err := goimagehash.PerceptionHash(img)
	if err != nil {
		return "", false
	}
	return fmt.Sprintf("%s%016x", HashPrefix, h.GetHash()), true
}

// Distance is the number of differing bits of two hashes, 64 when they
// are not of the same kind (an earlier run's hash has no prefix).
func Distance(a, b string) int {
	if !strings.HasPrefix(a, HashPrefix) || !strings.HasPrefix(b, HashPrefix) {
		return 64
	}
	x, err1 := strconv.ParseUint(a[len(HashPrefix):], 16, 64)
	y, err2 := strconv.ParseUint(b[len(HashPrefix):], 16, 64)
	if err1 != nil || err2 != nil {
		return 64
	}
	return bits.OnesCount64(x ^ y)
}

// NearBits is how many bits two perceptual hashes may differ and the
// pages still look alike.
const NearBits = 10

// Hash is the 64 bits of a hash DHash gave, false for an empty one, an
// earlier run's, or one that does not read.
func Hash(h string) (uint64, bool) {
	if !strings.HasPrefix(h, HashPrefix) {
		return 0, false
	}
	x, err := strconv.ParseUint(h[len(HashPrefix):], 16, 64)
	return x, err == nil
}

// Cluster puts hashes into groups of look-alikes: each joins the first
// group with a member at most near bits from it, or starts one. It gives
// each hash its group's number, in the order the groups began. A hash that
// does not read (ok false) is a group of its own.
func Cluster(hashes []uint64, ok []bool, near int) []int {
	out := make([]int, len(hashes))
	var groups [][]uint64 // the different hashes of each group
	for i, h := range hashes {
		g := -1
		if ok[i] {
			for gi, members := range groups {
				if slices.ContainsFunc(members, func(m uint64) bool { return bits.OnesCount64(h^m) <= near }) {
					g = gi
					break
				}
			}
		}
		switch {
		case g < 0 && ok[i]:
			g = len(groups)
			groups = append(groups, []uint64{h})
		case g < 0:
			g = len(groups)
			groups = append(groups, nil)
		case !slices.Contains(groups[g], h):
			groups[g] = append(groups[g], h)
		}
		out[i] = g
	}
	return out
}

// absPath is file as an absolute path, for a report written from another directory.
func absPath(file string) string {
	if a, err := filepath.Abs(file); err == nil {
		return a
	}
	return file
}
