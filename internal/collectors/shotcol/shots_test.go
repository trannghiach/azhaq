package shotcol

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"

	"github.com/trannghiach/azhaq/internal/fetch"
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
