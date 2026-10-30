package gallery

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	_ "image/png"
	"net/http"
	"os"
	"runtime"
	"sync"
)

const (
	thumbWidth    = 360
	thumbCacheMax = 192 << 20 // bytes of thumbnails kept
	maxPixels     = 64 << 20  // a picture larger than this is not decoded
)

type thumbCache struct {
	mu    sync.Mutex
	m     map[string][]byte
	bytes int
	sem   chan struct{}
	once  sync.Once
}

// readPicture is a page's picture file, found where the run named it or
// beside the workspace. Only a PNG or JPEG is given: the path in a
// workspace is not trusted to name anything else.
func (sh *Shot) readPicture() ([]byte, error) {
	for _, f := range sh.files {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		switch http.DetectContentType(raw) {
		case "image/png", "image/jpeg":
			return raw, nil
		}
	}
	return nil, os.ErrNotExist
}

// thumbnail is the page's picture scaled to thumbWidth, as a JPEG.
func (g *Gallery) thumbnail(sh *Shot) ([]byte, error) {
	c := &g.thumbs
	c.once.Do(func() { c.m = map[string][]byte{}; c.sem = make(chan struct{}, max(runtime.NumCPU(), 2)) })
	c.mu.Lock()
	if b, ok := c.m[sh.ID]; ok {
		c.mu.Unlock()
		return b, nil
	}
	c.mu.Unlock()
	c.sem <- struct{}{}
	defer func() { <-c.sem }()
	raw, err := sh.readPicture()
	if err != nil {
		return nil, err
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	if cfg.Width*cfg.Height > maxPixels || cfg.Width < 1 || cfg.Height < 1 {
		return nil, errors.New("picture too large")
	}
	img, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := jpeg.Encode(&out, scale(img, thumbWidth), &jpeg.Options{Quality: 72}); err != nil {
		return nil, err
	}
	b := out.Bytes()
	c.mu.Lock()
	if c.bytes+len(b) > thumbCacheMax {
		c.m, c.bytes = map[string][]byte{}, 0
	}
	c.m[sh.ID] = b
	c.bytes += len(b)
	c.mu.Unlock()
	return b, nil
}

// scale shrinks img to width w, each new pixel the mean of up to 3×3
// samples of the cell it covers; a picture already narrower is kept.
func scale(img image.Image, w int) *image.RGBA {
	b := img.Bounds()
	if b.Dx() < w {
		w = b.Dx()
	}
	h := max(b.Dy()*w/b.Dx(), 1)
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		y0, y1 := b.Min.Y+y*b.Dy()/h, b.Min.Y+max((y+1)*b.Dy()/h, y*b.Dy()/h+1)
		sy := max((y1-y0+2)/3, 1)
		for x := 0; x < w; x++ {
			x0, x1 := b.Min.X+x*b.Dx()/w, b.Min.X+max((x+1)*b.Dx()/w, x*b.Dx()/w+1)
			sx := max((x1-x0+2)/3, 1)
			var r, gr, bl, n uint32
			for yy := y0; yy < y1; yy += sy {
				for xx := x0; xx < x1; xx += sx {
					cr, cg, cb, _ := img.At(xx, yy).RGBA()
					r, gr, bl, n = r+cr>>8, gr+cg>>8, bl+cb>>8, n+1
				}
			}
			dst.SetRGBA(x, y, color.RGBA{uint8(r / n), uint8(gr / n), uint8(bl / n), 255})
		}
	}
	return dst
}
