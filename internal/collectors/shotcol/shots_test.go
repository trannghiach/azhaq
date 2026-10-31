package shotcol

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math/bits"
	"math/rand"
	"net/url"
	"slices"
	"testing"

	"github.com/trannghiach/azhaq/internal/browser"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/types"
)

func pngOf(t *testing.T, draw func(x, y int) uint8) []byte {
	img := image.NewGray(image.Rect(0, 0, 180, 120))
	for y := 0; y < 120; y++ {
		for x := 0; x < 180; x++ {
			img.SetGray(x, y, color.Gray{Y: draw(x, y)})
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// page is a white 1440×900 viewport with boxes drawn on it, as a sparse
// page is.
func page(t *testing.T, boxes ...[5]int) []byte {
	img := image.NewGray(image.Rect(0, 0, 1440, 900))
	for i := range img.Pix {
		img.Pix[i] = 255
	}
	for _, b := range boxes {
		for y := b[1]; y < b[3]; y++ {
			for x := b[0]; x < b[2]; x++ {
				img.SetGray(x, y, color.Gray{Y: uint8(b[4])})
			}
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// A login form, a default page and a dashboard are three pages, and two
// shots of one login form with a field's text changed are one.
func TestHashSeparatesSparsePages(t *testing.T) {
	login := page(t, [5]int{560, 220, 880, 520, 200}, [5]int{580, 300, 860, 330, 120}, [5]int{580, 350, 860, 380, 120}, [5]int{580, 420, 860, 460, 40})
	loginB := page(t, [5]int{560, 220, 880, 520, 190}, [5]int{580, 300, 860, 330, 120}, [5]int{580, 350, 860, 380, 120}, [5]int{580, 420, 860, 460, 50})
	nginx := page(t, [5]int{420, 60, 1020, 90, 30}, [5]int{420, 140, 1020, 150, 90}, [5]int{420, 180, 800, 190, 90})
	admin := page(t, [5]int{0, 0, 220, 900, 40}, [5]int{240, 0, 1440, 50, 110}, [5]int{260, 90, 460, 210, 100}, [5]int{480, 90, 680, 210, 150}, [5]int{700, 90, 900, 210, 70})
	h := map[string]string{}
	for name, data := range map[string][]byte{"login": login, "loginB": loginB, "nginx": nginx, "admin": admin} {
		v, ok := DHash(data)
		if !ok || len(v) != 18 || v[:2] != HashPrefix {
			t.Fatalf("%s: hash %q", name, v)
		}
		h[name] = v
	}
	if d := Distance(h["login"], h["loginB"]); d > 10 {
		t.Errorf("one login form twice: %d bits apart", d)
	}
	for _, pair := range [][2]string{{"login", "nginx"}, {"login", "admin"}, {"nginx", "admin"}} {
		if d := Distance(h[pair[0]], h[pair[1]]); d <= 10 {
			t.Errorf("%s and %s only %d bits apart", pair[0], pair[1], d)
		}
	}
	if d := Distance("0080800000000000", h["login"]); d != 64 {
		t.Errorf("an earlier run's hash is %d bits from this one's, want 64", d)
	}
	if _, ok := DHash([]byte("not a png")); ok {
		t.Error("garbage hashed")
	}
}

func TestNotTakenSaysWhatThePageNeeds(t *testing.T) {
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	notTaken("http://h/", 26, 8)
	notTaken("http://h/", 26, 8) // told once
	notTaken("http://g/", 0, 0)
	got := fetch.Notes()
	want := []string{
		"screenshot of http://h/ not taken: the page needs about 26 requests and 8 were left (raise -max-requests)",
		"screenshot of http://g/ not taken: the budget was spent before the page loaded (raise -max-requests)",
	}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("notes %q, want %q", got, want)
	}
}

func TestSkipKeepsWhatTheUserNamed(t *testing.T) {
	c := &Collector{Dir: "d", Browser: &browser.Browser{}}
	path := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": "http://h/a/b?x=1"}}
	if !c.Skip(path) {
		t.Error("a URL a run found, with a path, was shot")
	}
	path.Keys[types.GivenKey] = "1"
	if c.Skip(path) {
		t.Error("a URL the user gave, with a path, was skipped")
	}
}

func TestGuessesFollowThePorts(t *testing.T) {
	c := &Collector{}
	if g := c.guesses("h"); len(g) != 1 || g[0][0] != "https://h/" || g[0][1] != "http://h/" {
		t.Errorf("no ports: %v", g)
	}
	c = &Collector{Ports: []int{80, 443, 8080}, Only: "http"}
	g := c.guesses("[::1]")
	if len(g) != 3 || g[0][0] != "http://[::1]/" || g[2][0] != "http://[::1]:8080/" || len(g[1]) != 1 {
		t.Errorf("ports, http only: %v", g)
	}
}

func TestBaseNameKeepsPagesApart(t *testing.T) {
	a, _ := url.Parse("http://h:3000/")
	b, _ := url.Parse("http://h:3000/a?x=1")
	c, _ := url.Parse("http://h:3000/a?x=2")
	na, nb, nc := baseName(a, a.String()), baseName(b, b.String()), baseName(c, c.String())
	if na != "http_h_3000" || nb == na || nb == nc {
		t.Errorf("names %q %q %q", na, nb, nc)
	}
}

// Cluster gives what the plain loop gives: each hash joins the first group
// that has a member within near bits.
func TestClusterIsTheFirstNearGroup(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	var hashes []uint64
	var ok []bool
	for i := 0; i < 400; i++ {
		h := uint64(r.Int63())
		if i > 0 && r.Intn(3) > 0 {
			h = hashes[r.Intn(i)] ^ (1<<r.Intn(64) | 1<<r.Intn(64))
		}
		hashes, ok = append(hashes, h), append(ok, r.Intn(20) != 0)
	}
	var groups [][]int
	want := make([]int, len(hashes))
	for i := range hashes {
		g := -1
		for gi, members := range groups {
			if ok[i] && slices.ContainsFunc(members, func(m int) bool { return ok[m] && bits.OnesCount64(hashes[i]^hashes[m]) <= NearBits }) {
				g = gi
				break
			}
		}
		if g < 0 {
			g = len(groups)
			groups = append(groups, nil)
		}
		groups[g] = append(groups[g], i)
		want[i] = g
	}
	if got := Cluster(hashes, ok, NearBits); !slices.Equal(got, want) {
		t.Errorf("Cluster differs from the loop")
	}
	if h, good := Hash("p:00000000000000ff"); !good || h != 255 {
		t.Errorf("Hash: %d %v", h, good)
	}
	if _, good := Hash("1234"); good {
		t.Errorf("a hash of an earlier run read")
	}
}

// The name inside a front-page URL is that URL's shot: it is not also tried
// on both schemes. A name from a path URL still gets its front page.
func TestSkipLeavesTheNameOfAFrontPageURL(t *testing.T) {
	c := &Collector{Dir: "d", Browser: &browser.Browser{}}
	name := func(from string) types.Seed {
		return types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": "h.test", types.FromURLKey: from}}
	}
	if !c.Skip(name("http://h.test/")) {
		t.Error("the name of http://h.test/ was shot again on both schemes")
	}
	if c.Skip(name("http://h.test/a/b")) {
		t.Error("the front page of a name met in a path URL was skipped")
	}
	if c.Skip(types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": "h.test"}}) {
		t.Error("a name the user gave was skipped")
	}
}
