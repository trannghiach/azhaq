// Package ledger keeps a tamper-evident record of every request and
// connection a run sends to a target: when, to what, and under which scope
// rule. Each line of the file holds the hash of the one before it, so an
// edited, removed or reordered line breaks the chain from there on. A run
// that ends closes the file with a seal line, so lines cut from the end
// show too.
package ledger

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Entry is one request or connection. Hash covers Prev and every other field.
type Entry struct {
	Seq       int64     `json:"seq"`
	Time      time.Time `json:"time"`
	Kind      string    `json:"kind"` // http, tcp, udp, chrome, or seal: the end of a run
	Method    string    `json:"method,omitempty"`
	Target    string    `json:"target"` // the URL (http, chrome) or ip:port (tcp)
	Host      string    `json:"host,omitempty"`
	VHost     string    `json:"vhost,omitempty"` // the Host header sent, when it is not the URL's
	Rule      string    `json:"rule,omitempty"`  // the scope rule that allowed it
	Collector string    `json:"collector,omitempty"`
	Prev      string    `json:"prev,omitempty"`
	Hash      string    `json:"hash,omitempty"`
}

// sum is the entry's hash: sha256 over Prev and the JSON of the entry
// without its Hash.
func (e Entry) sum() string {
	e.Hash = ""
	raw, _ := json.Marshal(e)
	h := sha256.New()
	h.Write([]byte(e.Prev))
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}

// Ledger appends entries to a file. It is safe for concurrent use.
type Ledger struct {
	// Match names the scope rule that allows host, "" when none does or the
	// run has no rules.
	Match func(host string) string

	mu       sync.Mutex
	f        *os.File
	path     string
	w        *bufio.Writer
	seq      int64
	prev     string
	lastSeal bool // the last line is a seal: nothing to seal again
	err      error
}

// Open appends to the file at path, creating it, and continues the chain
// of what it already holds.
func Open(path string) (*Ledger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	l := &Ledger{f: f, path: path, w: bufio.NewWriter(f)}
	last, err := lastLine(f)
	if err == nil && len(last) > 0 {
		var e Entry
		if err = json.Unmarshal(last, &e); err == nil {
			l.seq, l.prev, l.lastSeal = e.Seq, e.Hash, e.Kind == KindSeal
		}
	}
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("ledger %s: the last line is not an entry (%v): azhaq ledger -verify %s", path, err, path)
	}
	return l, nil
}

// lastLine is the final line of f, without its newline; none for an empty file.
func lastLine(f *os.File) ([]byte, error) {
	st, err := f.Stat()
	if err != nil || st.Size() == 0 {
		return nil, err
	}
	size := st.Size()
	for n := int64(4096); ; n *= 4 {
		n = min(n, size)
		buf := make([]byte, n)
		if _, err := f.ReadAt(buf, size-n); err != nil && err != io.EOF {
			return nil, err
		}
		if buf[len(buf)-1] != '\n' {
			return nil, errors.New("no newline at the end")
		}
		buf = buf[:len(buf)-1]
		if i := bytes.LastIndexByte(buf, '\n'); i >= 0 {
			return buf[i+1:], nil
		}
		if n == size {
			return buf, nil
		}
	}
}

// Record adds e to the chain: it takes its Seq, Prev and Hash, and its
// time unless e has one. The line is flushed before Record returns, so a
// crash loses nothing that was sent.
func (l *Ledger) Record(e Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	e.Time = e.Time.UTC()
	l.seq++
	e.Seq, e.Prev = l.seq, l.prev
	e.Hash = e.sum()
	raw, _ := json.Marshal(e)
	raw = append(raw, '\n')
	_, err := l.w.Write(raw)
	if err == nil {
		err = l.w.Flush()
	}
	l.note(err)
	l.prev, l.lastSeal = e.Hash, e.Kind == KindSeal
}

func (l *Ledger) note(err error) {
	if err != nil && l.err == nil {
		l.err = err
	}
}

// Count is how many lines the file holds, those of earlier runs and their
// seals included.
func (l *Ledger) Count() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seq
}

// Last is the hash of the last line written: after Close, the seal's.
func (l *Ledger) Last() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.prev
}

// Path is the file the ledger writes.
func (l *Ledger) Path() string { return l.path }

// KindSeal is the line a run ends the file with.
const KindSeal = "seal"

// Close seals the file, flushes and syncs it, and returns the first write
// error.
func (l *Ledger) Close() error {
	l.mu.Lock()
	if l.f == nil {
		l.mu.Unlock()
		return l.err
	}
	sealed := l.lastSeal
	l.mu.Unlock()
	if !sealed {
		l.Record(Entry{Kind: KindSeal})
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.note(l.w.Flush())
	l.note(l.f.Sync())
	l.note(l.f.Close())
	l.f = nil
	return l.err
}

// Read calls fn with each request and connection of the file in order,
// without checking the chain; seals are left out.
func Read(path string, fn func(e Entry) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<16)
	for line := 1; ; line++ {
		raw, err := r.ReadBytes('\n')
		if len(bytes.TrimSpace(raw)) > 0 {
			var e Entry
			if jerr := json.Unmarshal(raw, &e); jerr != nil {
				return fmt.Errorf("%s line %d: %w", path, line, jerr)
			}
			if e.Kind == KindSeal {
				continue
			}
			if ferr := fn(e); ferr != nil {
				return ferr
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// Check is what Verify found.
type Check struct {
	Entries  int    // requests and connections that are intact, seals not counted
	Seals    int    // runs that closed the file
	BadLine  int    // the first line that is not intact (1 is the first); 0 when none
	Unsealed int    // entries after the last seal: a run that did not end, or lines cut from the end
	Seal     string // the hash of the last seal
}

// Verify recomputes the chain of the file at path. err says what is wrong
// with c.BadLine, or why the file could not be read.
func Verify(path string) (c Check, err error) {
	return verifyChain(path, nil)
}

// verifyChain is Verify, calling onSeal with every seal line it finds
// intact, in order, so a caller can check more than only the last one.
func verifyChain(path string, onSeal func(Entry)) (c Check, err error) {
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<16)
	prev := ""
	var n int64
	for line := 1; ; line++ {
		raw, rerr := r.ReadBytes('\n')
		if len(raw) == 0 && rerr == io.EOF {
			return c, nil
		}
		if rerr != nil && rerr != io.EOF {
			return c, rerr
		}
		bad := func(format string, a ...any) (Check, error) {
			c.BadLine = line
			return c, fmt.Errorf("line %d: "+format, append([]any{line}, a...)...)
		}
		if rerr == io.EOF {
			return bad("cut short: no newline at the end")
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		var e Entry
		if jerr := dec.Decode(&e); jerr != nil {
			return bad("not an entry: %v", jerr)
		}
		switch {
		case e.Seq != n+1:
			return bad("seq %d, want %d (a line was removed, added or moved)", e.Seq, n+1)
		case e.Prev != prev:
			return bad("prev does not match the hash of the line before")
		case e.Hash != e.sum():
			return bad("hash does not match the content: the line was edited")
		}
		prev = e.Hash
		n++
		if e.Kind == KindSeal {
			c.Seals++
			c.Seal, c.Unsealed = e.Hash, 0
			if onSeal != nil {
				onSeal(e)
			}
		} else {
			c.Entries++
			c.Unsealed++
		}
	}
}

// VerifySeal is Verify, and also requires that one of want is the hash of
// one of the file's seals: proof that no line was removed with the rest
// re-chained from there, which recomputing the chain alone cannot show (a
// rebuilt chain is internally consistent too, it is just not the one the
// run wrote). matched is the member of want that was found, "" when
// Verify itself already failed or none of want was there.
func VerifySeal(path string, want []string) (c Check, matched string, err error) {
	have := map[string]bool{}
	for _, w := range want {
		have[w] = true
	}
	c, err = verifyChain(path, func(e Entry) {
		if matched == "" && have[e.Hash] {
			matched = e.Hash
		}
	})
	return c, matched, err
}

var active atomic.Pointer[Ledger]

// Use makes l the ledger the hooks write to; nil turns them off.
func Use(l *Ledger) { active.Store(l) }

// Active is the ledger in use, or nil.
func Active() *Ledger { return active.Load() }

func (l *Ledger) rule(host string) string {
	if l.Match == nil || host == "" {
		return ""
	}
	return l.Match(host)
}
