package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"image"
	"image/png"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// galleryWorkspace is a workspace with one screenshot row and its picture.
func galleryWorkspace(t *testing.T, dir, name string) string {
	t.Helper()
	img := image.NewGray(image.Rect(0, 0, 32, 20))
	var pic bytes.Buffer
	if err := png.Encode(&pic, img); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, name+".png")
	if err := os.WriteFile(file, pic.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dir, name+".db")
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	page := "http://" + name + ".example.test/"
	ent, err := st.UpsertEntity(types.TypeURL, page, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"url": page, "file": file, "file_path": file, "title": "T " + name, "response_code": 200})
	if _, err := st.AddObservation(ent.ID, types.Observation{Collector: "azhaq-shots", Source: page, Kind: "screenshot", Payload: raw, ObservedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	return db
}

// galleryUp waits for the gallery at addr to answer, and fails the test
// when it does not: a SIGINT sent before the gallery listens for it would
// end the whole test binary.
func galleryUp(t *testing.T, addr string, done chan error) []byte {
	t.Helper()
	for i := 0; i < 400; i++ {
		select {
		case err := <-done:
			t.Fatalf("the gallery ended before it served: %v", err)
		default:
		}
		if r, err := http.Get("http://" + addr + "/api/stats"); err == nil {
			body, _ := io.ReadAll(r.Body)
			r.Body.Close()
			return body
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the gallery did not answer in 20 s")
	return nil
}

func TestGalleryServesAndStops(t *testing.T) {
	dir := t.TempDir()
	a := galleryWorkspace(t, dir, "a")
	galleryWorkspace(t, filepath.Join(dir), "b")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	done := make(chan error, 1)
	go func() { done <- cmdGallery([]string{"-workspace", dir, "-listen", addr}) }()
	body := galleryUp(t, addr, done)
	var st struct{ Pages int }
	if json.Unmarshal(body, &st) != nil || st.Pages != 2 {
		t.Fatalf("stats %s", body)
	}
	_ = a
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("stopped with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the gallery did not stop")
	}
}

func TestGalleryRefusals(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "empty.db"))
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	var ue usageErr
	if err := cmdGallery([]string{"-db", filepath.Join(dir, "empty.db"), "extra"}); !errors.As(err, &ue) {
		t.Errorf("an argument: %v", err)
	}
	if err := cmdGallery([]string{"-db", filepath.Join(dir, "empty.db")}); err == nil || exitCode(err) != exitError {
		t.Errorf("a workspace with no screenshot: %v", err)
	}
	if err := cmdGallery([]string{"-db", filepath.Join(dir, "missing.db")}); err == nil {
		t.Errorf("a missing workspace opened")
	}
	if err := cmdGallery([]string{"-workspace", dir + "/nope"}); err == nil {
		t.Errorf("a missing directory")
	}
	if err := cmdGallery([]string{"-workspace", filepath.Join(dir, "empty.db")}); !errors.As(err, &ue) {
		t.Errorf("a file for -workspace: %v", err)
	}
	// A workspace whose pictures are gone is served and exits 3.
	db := galleryWorkspace(t, dir, "gone")
	if err := os.Remove(filepath.Join(dir, "gone.png")); err != nil {
		t.Fatal(err)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	done := make(chan error, 1)
	go func() { done <- cmdGallery([]string{"-db", db, "-listen", addr}) }()
	galleryUp(t, addr, done)
	_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
	select {
	case err := <-done:
		if exitCode(err) != exitPartial {
			t.Errorf("missing pictures: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the gallery did not stop")
	}
}
