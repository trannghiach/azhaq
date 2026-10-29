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

func TestDHashGroupsLookAlikes(t *testing.T) {
	gradient := func(x, y int) uint8 { return uint8(x + y/4) }
	shifted := func(x, y int) uint8 { return uint8(x + y/4 + 3) } // same layout, a little brighter
	stripes := func(x, y int) uint8 {
		if (x/20)%2 == 0 {
			return 230
		}
		return 20
	}
	a, _ := DHash(pngOf(t, gradient))
	b, _ := DHash(pngOf(t, shifted))
	c, _ := DHash(pngOf(t, stripes))
	if d := Distance(a, b); d > 6 {
		t.Errorf("look-alikes %d bits apart", d)
	}
	if d := Distance(a, c); d < 16 {
		t.Errorf("different pages only %d bits apart", d)
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
