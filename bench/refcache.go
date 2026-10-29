package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// The reference tools' answers do not change with Azhaq's commits and take
// about half the bench's time, so a run is kept for the rest of the UTC day
// and replayed: its stdout, its measure and the files it wrote (arjun -oJ,
// ffuf -o). -fresh runs them again. gowitness writes a directory of
// screenshots and is never replayed.
var uncached = []string{"gowitness"}

type cachedRun struct {
	Measure runMeasure        `json:"measure"`
	Files   map[string]string `json:"files"` // path written → name in the entry
}

// refKey names a run by the day, the tool binary, the target and the
// arguments, files among them by their content.
func refKey(target, dir, name string, args []string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00", time.Now().UTC().Format("2006-01-02"), filepath.Base(name), target)
	if fi, err := os.Stat(name); err == nil {
		fmt.Fprintf(h, "%d\x00%d\x00", fi.Size(), fi.ModTime().UnixNano())
	}
	outs := outputs(args)
	for i, a := range args {
		if p := argPath(dir, a); p != "" && !outs[i] {
			if f, err := os.Open(p); err == nil {
				_, _ = io.Copy(h, f)
				f.Close()
				h.Write([]byte{0})
				continue
			}
		}
		fmt.Fprintf(h, "%s\x00", a)
	}
	return hex.EncodeToString(h.Sum(nil))[:24]
}

// outputFlags name the file a tool writes its results to.
var outputFlags = []string{"-o", "-oJ", "-output", "--output"}

// outputs are the indexes of args that name a tool's output file: their
// old content is not part of the key, and they are always kept.
func outputs(args []string) map[int]bool {
	m := map[int]bool{}
	for i := 1; i < len(args); i++ {
		if slices.Contains(outputFlags, args[i-1]) {
			m[i] = true
		}
	}
	return m
}

// argPath is a as a regular file's path (relative ones from dir), or "".
func argPath(dir, a string) string {
	if a == "" || a[0] == '-' {
		return ""
	}
	if !filepath.IsAbs(a) {
		a = filepath.Join(dir, a)
	}
	if fi, err := os.Stat(a); err == nil && fi.Mode().IsRegular() {
		return a
	}
	return ""
}

func refCacheable(name string) bool {
	return !fresh && name != azhaq && !slices.Contains(uncached, filepath.Base(name))
}

func refDir(key string) string { return filepath.Join(work, "refcache", key) }

// replayRef returns a kept run, its files put back where it wrote them.
func replayRef(key string) ([]byte, runMeasure, bool) {
	d := refDir(key)
	raw, err := os.ReadFile(filepath.Join(d, "run.json"))
	if err != nil {
		return nil, runMeasure{}, false
	}
	var c cachedRun
	if json.Unmarshal(raw, &c) != nil {
		return nil, runMeasure{}, false
	}
	out, err := os.ReadFile(filepath.Join(d, "stdout"))
	if err != nil {
		return nil, runMeasure{}, false
	}
	for path, kept := range c.Files {
		body, err := os.ReadFile(filepath.Join(d, kept))
		if err != nil || os.MkdirAll(filepath.Dir(path), 0o755) != nil || os.WriteFile(path, body, 0o644) != nil {
			return nil, runMeasure{}, false
		}
	}
	c.Measure.Cached = true
	return out, c.Measure, true
}

// keepRef stores a run that succeeded, with the files among its arguments
// that it created.
func keepRef(key, dir string, args []string, before map[string]bool, out []byte, m runMeasure) {
	if m.Error != "" {
		return
	}
	d := refDir(key)
	if os.MkdirAll(d, 0o755) != nil {
		return
	}
	c := cachedRun{Measure: m, Files: map[string]string{}}
	outs := outputs(args)
	for i, a := range args {
		if p := argPath(dir, a); p != "" && (!before[p] || outs[i]) {
			body, err := os.ReadFile(p)
			if err != nil {
				return
			}
			kept := fmt.Sprintf("file%d", i)
			if os.WriteFile(filepath.Join(d, kept), body, 0o644) != nil {
				return
			}
			c.Files[p] = kept
		}
	}
	raw, _ := json.Marshal(c)
	if os.WriteFile(filepath.Join(d, "stdout"), out, 0o644) == nil {
		_ = os.WriteFile(filepath.Join(d, "run.json"), raw, 0o644)
	}
}

// existing lists the arguments that are files before a run.
func existing(dir string, args []string) map[string]bool {
	m := map[string]bool{}
	for _, a := range args {
		if p := argPath(dir, a); p != "" {
			m[p] = true
		}
	}
	return m
}
