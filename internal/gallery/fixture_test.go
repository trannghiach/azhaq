package gallery

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/collectors/shotcol"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// fixShot is what the fixture knows of a page, to check the API against.
type fixShot struct {
	URL, Title, Host string
	Status           int
	Tech             []string
	Partial          bool
	Body             string
	Hash             string
}

func (r fixShot) has(name string) bool {
	return slices.ContainsFunc(r.Tech, func(t string) bool { return strings.EqualFold(techName(t), name) })
}

var fixStatuses = []int{200, 200, 200, 200, 301, 302, 401, 403, 404, 500}
var fixTech = []string{"nginx:1.25.3", "Apache", "PHP", "React", "Express", "WordPress", "jQuery", "Node.js"}

// patternPNG is a small real picture: blocks of colour from one of
// patterns base pictures, a pixel off for each variant, so that pages of
// one pattern look alike by their perceptual hash.
func patternPNG(base, variant int) []byte {
	r := rand.New(rand.NewSource(int64(base) + 1))
	img := image.NewRGBA(image.Rect(0, 0, 96, 60))
	var cols [6][4]color.RGBA
	for y := range cols {
		for x := range cols[y] {
			cols[y][x] = color.RGBA{uint8(r.Intn(256)), uint8(r.Intn(256)), uint8(r.Intn(256)), 255}
		}
	}
	for y := 0; y < 60; y++ {
		for x := 0; x < 96; x++ {
			img.SetRGBA(x, y, cols[y/10][x/24])
		}
	}
	img.SetRGBA(variant%96, variant/96%60, color.RGBA{1, 2, 3, 255})
	var b bytes.Buffer
	_ = png.Encode(&b, img)
	return b.Bytes()
}

// makeWorkspace writes n synthetic screenshot rows to dir/name.db with
// their pictures, shaped as the screenshot collector writes them, and
// returns the rows. Every 7th page keeps its HTML.
func makeWorkspace(t testing.TB, dir, name string, n int) ([]fixShot, string) {
	t.Helper()
	dbPath := filepath.Join(dir, name)
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.BeginRun("r1", 4, 100); err != nil {
		t.Fatal(err)
	}
	rnd := rand.New(rand.NewSource(7))
	var out []fixShot
	now := time.Now().UTC()
	for i := 0; i < n; i++ {
		host := fmt.Sprintf("h%d.example.test", i%97)
		page := fmt.Sprintf("https://%s:%d/", host, 8000+i/97)
		fs := fixShot{URL: page, Host: fmt.Sprintf("%s:%d", host, 8000+i/97), Status: fixStatuses[rnd.Intn(len(fixStatuses))], Title: fmt.Sprintf("Portal %d", i%331)}
		if i%5 == 0 {
			fs.Title = "Sign in to Acme"
		}
		for _, k := range []int{rnd.Intn(len(fixTech)), rnd.Intn(len(fixTech))} {
			if len(fs.Tech) == 0 || fs.Tech[0] != fixTech[k] {
				fs.Tech = append(fs.Tech, fixTech[k])
			}
		}
		fs.Partial = i%11 == 3
		base := i % 40
		png := patternPNG(base, i)
		file := fmt.Sprintf("%s_%d.png", name, i)
		if err := os.WriteFile(filepath.Join(dir, file), png, 0o644); err != nil {
			t.Fatal(err)
		}
		fs.Hash, _ = shotcol.DHash(png)
		row := map[string]any{"url": page, "file": file, "file_path": filepath.Join(dir, file), "file_name": file, "format": "png", "title": fs.Title, "final_url": page,
			"bytes": len(png), "probed_at": now.Format(time.RFC3339), "response_code": fs.Status, "response_reason": "OK", "protocol": "h2",
			"headers": []map[string]string{{"key": "Server", "value": "nginx/1.25"}, {"key": "Set-Cookie", "value": fmt.Sprintf("sid=%d; HttpOnly", i)}},
			"tls":     map[string]any{"protocol": "TLS 1.3", "cipher": "AES_128_GCM", "subject_name": host, "issuer": "Test CA", "valid_from": "2026-01-01", "valid_to": "2027-01-01", "san_list": []string{host}},
			"network": []map[string]any{{"request_type": "Document", "method": "GET", "status_code": fs.Status, "url": page, "bytes": 1200}, {"request_type": "Script", "method": "GET", "status_code": 200, "url": page + "app.js", "bytes": 5000}},
			"console": []map[string]string{{"type": "error", "value": "Uncaught TypeError at " + page}},
			"phash":   fs.Hash, "perception_hash": fs.Hash}
		var tech []map[string]string
		for _, x := range fs.Tech {
			tech = append(tech, map[string]string{"value": x})
		}
		row["technologies"] = tech
		if fs.Partial {
			row["partial"], row["unloaded"], row["resources"], row["note"] = true, 2, 9, "screenshot of "+page+" is partial: 2 of 9 images were not loaded"
		}
		if i%22 == 3 { // drawn without the assets of a host outside the scope
			row["unloaded"], row["resources"] = nil, nil
			row["blocked"], row["blocked_hosts"] = 3, []string{"cdn.example.test"}
		}
		if i%7 == 0 {
			fs.Body = fmt.Sprintf("welcome marker%d to the %s", i, fs.Title)
			hf := filepath.Join(dir, fmt.Sprintf("%s_%d.html", name, i))
			if err := os.WriteFile(hf, []byte("<html><head><title>x</title><script>var hidden=1</script></head><body><h1>"+fs.Body+"</h1></body></html>"), 0o644); err != nil {
				t.Fatal(err)
			}
			row["html_file"] = hf
		}
		ent, err := st.UpsertEntity(types.TypeURL, page, now)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(row)
		if _, err := st.AddObservation(ent.ID, types.Observation{Collector: "azhaq-shots", Source: page, Kind: "screenshot", Payload: raw, Confidence: 0.9, ObservedAt: now.Add(time.Duration(i) * time.Millisecond)}); err != nil {
			t.Fatal(err)
		}
		out = append(out, fs)
	}
	return out, dbPath
}
