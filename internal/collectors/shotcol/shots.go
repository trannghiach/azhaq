// Package shotcol takes a screenshot of each web service's front page
// (-screenshots DIR) with a Chrome installed on the machine, and a
// perceptual hash so look-alike pages (default installs, login portals,
// parked domains) can be grouped.
package shotcol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"math/bits"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/corona10/goimagehash"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/internal/browser"
	"github.com/trannghiach/azhaq/internal/collectors/rendercol"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/types"
)

const Name = "azhaq-shots"

type Collector struct {
	Dir     string
	Browser *browser.Browser

	shot sync.Map // pages already taken: a name and its URL are one page
	need sync.Map // URL → requests the page asked for when the budget cut it short
}

func (c *Collector) Name() string { return Name }

// Info: loads the page with its scripts and images, as a browser does.
func (c *Collector) Info() catalog.Info {
	return catalog.Info{Kind: catalog.Touch, After: "azhaq-http", Local: true}
}

func (c *Collector) Inputs() []types.SeedType {
	return []types.SeedType{types.TypeURL, types.TypeHostname, types.TypeIPAddress}
}

func (c *Collector) Outputs() []string { return []string{"screenshot"} }

// Skip: only with -screenshots, and only front pages.
func (c *Collector) Skip(seed types.Seed) bool {
	if c.Dir == "" || c.Browser == nil {
		return true
	}
	switch seed.Type {
	case types.TypeHostname:
		return false
	case types.TypeIPAddress:
		return seed.Keys["from"] != "prefix"
	}
	u, err := url.Parse(seed.Keys["url"])
	return err != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != ""
}

// budgetLeft is how many requests the run may still send, or -1 without a cap.
func budgetLeft() int {
	if fetch.MaxRequests <= 0 {
		return -1
	}
	return int(max(fetch.MaxRequests-fetch.Sent(), 0))
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
	var tries []string
	if seed.Type == types.TypeURL {
		raw, err := normalize.URL(seed.Keys["url"])
		if err != nil {
			return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
		}
		tries = []string{raw}
	} else {
		// A name or an address: its front page, HTTPS first, as the HTTP
		// collector tried it.
		h := normalize.Hostname(seed.Key())
		tries = []string{"https://" + h + "/", "http://" + h + "/"}
	}
	var p browser.Page
	var err error
	raw := ""
	for _, t := range tries {
		if _, done := c.shot.LoadOrStore(t, true); done {
			return types.RunMeta{Status: types.StatusOK}, nil // taken, or being taken, through another seed
		}
		raw = t
		left := budgetLeft()
		if err := fetch.Spend(ctx); err != nil {
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
		if err == nil && len(p.PNG) > 0 {
			break
		}
		c.shot.Delete(t) // another seed for the same page may try again
	}
	if len(p.PNG) == 0 {
		if seed.Type != types.TypeURL {
			return types.RunMeta{Status: types.StatusOK}, nil // no web service there
		}
		msg := "no screenshot"
		if err != nil {
			msg = err.Error()
		}
		return types.RunMeta{Status: types.StatusError, Error: msg}, err
	}
	u, _ := url.Parse(raw)
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	name := unsafeName.ReplaceAllString(u.Scheme+"_"+u.Hostname()+"_"+port, "_") + ".png"
	if err := os.MkdirAll(c.Dir, 0o755); err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	file := filepath.Join(c.Dir, name)
	if err := os.WriteFile(file, p.PNG, 0o644); err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	row := map[string]any{"url": raw, "file": file, "title": p.Title, "final_url": p.URL, "bytes": len(p.PNG)}
	if p.Partial {
		// Taken, and saved, but short of what the page draws: said in the
		// summary, which then exits 3.
		row["partial"], row["unloaded"], row["resources"] = true, p.Unloaded, p.Resources
		row["note"] = fmt.Sprintf("screenshot of %s is partial: %d of %d images, styles and scripts were not loaded when it was taken (the pace, -max-requests or a slow server)", raw, p.Unloaded, p.Resources)
	}
	if h, ok := DHash(p.PNG); ok {
		row["phash"] = h
	}
	payload, _ := json.Marshal(row)
	return types.RunMeta{Status: types.StatusOK, EmitCount: 1}, emit(types.Observation{
		Collector: Name, Source: raw, Kind: "screenshot", Payload: payload, Confidence: 0.9, ObservedAt: time.Now().UTC(),
	})
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
