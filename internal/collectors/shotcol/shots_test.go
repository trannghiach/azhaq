package shotcol

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"
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
