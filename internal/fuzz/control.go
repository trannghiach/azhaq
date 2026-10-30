package fuzz

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Control steers a run while it goes: a file that lines are appended to
// (azhaq fuzz -control FILE; echo 'rate 2' >> FILE), in place of ffuf's
// interactive console. A paused run lets the requests in flight finish.
type Control struct {
	mu      sync.Mutex
	gate    chan struct{} // closed: running
	eng     *engine
	Stop    func(reason string) // set by the caller: ends the run with this reason
	Env     ControlEnv
	Applied []string // each command taken, for the summary
}

// ControlEnv is what the commands reach that is not the engine's.
type ControlEnv struct {
	Set     *Set
	SetRate func(perSecond float64)
	Save    func(path string) error // savejson: the report so far
	Show    func() string           // show: the matches so far
	Prune   func()                  // after a filter changed: drop kept matches it now filters
	Log     func(string)            // what a command says back
}

func NewControl(env ControlEnv) *Control {
	c := &Control{gate: make(chan struct{}), Env: env}
	close(c.gate)
	return c
}

func (c *Control) attach(e *engine) {
	c.mu.Lock()
	c.eng = e
	c.mu.Unlock()
}

// wait blocks while the run is paused.
func (c *Control) wait(ctx context.Context) {
	for {
		c.mu.Lock()
		g := c.gate
		c.mu.Unlock()
		select {
		case <-g:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (c *Control) pause() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.gate:
		c.gate = make(chan struct{})
		return true
	default:
		return false
	}
}

func (c *Control) resume() {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.gate:
	default:
		close(c.gate)
	}
}

// Watch reads the lines added to path after now, every 250 ms, and applies
// them, until ctx ends. It creates no file.
func (c *Control) Watch(ctx context.Context, path string) {
	var off int64
	if st, err := os.Stat(path); err == nil {
		off = st.Size()
	}
	var partial string
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		if st, err := f.Stat(); err == nil && st.Size() < off {
			off = 0 // truncated: read it again
		}
		f.Seek(off, io.SeekStart)
		data, _ := io.ReadAll(bufio.NewReader(f))
		f.Close()
		off += int64(len(data))
		text := partial + string(data)
		lines := strings.Split(text, "\n")
		partial = lines[len(lines)-1]
		for _, l := range lines[:len(lines)-1] {
			if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
				c.Apply(l)
			}
		}
	}
}

// Apply runs one command and says what it did.
func (c *Control) Apply(line string) {
	say := func(f string, a ...any) {
		if c.Env.Log != nil {
			c.Env.Log(fmt.Sprintf(f, a...))
		}
	}
	args := strings.Fields(line)
	cmd := args[0]
	need := func(n int) bool {
		if len(args) != n+1 {
			say("control: %q wants %d value(s), ignored", line, n)
			return false
		}
		return true
	}
	switch cmd {
	case "pause":
		c.pause()
	case "resume":
		c.resume()
	case "stop":
		if c.Stop != nil {
			c.Stop("the control file said stop")
		}
	case "rate":
		if !need(1) {
			return
		}
		v, err := strconv.ParseFloat(args[1], 64)
		if err != nil || v < 0 {
			say("control: rate wants a number of requests a second (0: no pace), got %q, ignored", args[1])
			return
		}
		if c.Env.SetRate != nil {
			c.Env.SetRate(v)
		}
	case "show":
		if c.Env.Show != nil {
			say("%s", c.Env.Show())
		}
	case "savejson":
		if !need(1) {
			return
		}
		if c.Env.Save == nil {
			return
		}
		if err := c.Env.Save(args[1]); err != nil {
			say("control: savejson %s: %v", args[1], err)
			return
		}
	case "queueshow":
		say("control: queued directories: %s", strings.Join(c.queue(), ", "))
	case "queuedel":
		if !need(1) {
			return
		}
		n, err := strconv.Atoi(args[1])
		if err != nil || !c.queueDel(n) {
			say("control: queuedel wants the number queueshow gives, got %q, ignored", args[1])
			return
		}
	case "queueskip":
		c.mu.Lock()
		e := c.eng
		c.mu.Unlock()
		if e != nil {
			e.skipJob.Store(true)
		}
	default:
		kind, add := filterCommand(cmd)
		if kind == "" {
			say("control: unknown command %q: pause, resume, stop, rate N, fc|fs|fw|fl|fr|ft VALUE (afc… adds, none removes), show, savejson FILE, queueshow, queuedel N, queueskip", cmd)
			return
		}
		if !need(1) || c.Env.Set == nil {
			return
		}
		var err error
		switch {
		case args[1] == "none" && !add:
			c.Env.Set.RemoveFilter(kind)
		case add:
			err = c.Env.Set.AddFilter(kind, args[1])
		default:
			err = c.Env.Set.ReplaceFilter(kind, args[1])
		}
		if err != nil {
			say("control: %s: %v, ignored", cmd, err)
			return
		}
		if c.Env.Prune != nil {
			c.Env.Prune()
		}
	}
	c.mu.Lock()
	c.Applied = append(c.Applied, line)
	c.mu.Unlock()
	say("control: %s", line)
}

// filterCommand reads fc, afc, fs… of ffuf's console: the kind of filter
// and whether the value is added to the ones there.
func filterCommand(cmd string) (kind string, add bool) {
	if strings.HasPrefix(cmd, "a") {
		add, cmd = true, cmd[1:]
	}
	kinds := map[string]string{"fc": "status", "fs": "size", "fw": "word", "fl": "line", "fr": "regexp", "ft": "time"}
	return kinds[cmd], add
}

func (c *Control) queue() []string {
	c.mu.Lock()
	e := c.eng
	c.mu.Unlock()
	if e == nil {
		return nil
	}
	e.outMu.Lock()
	defer e.outMu.Unlock()
	out := make([]string, len(e.queue))
	for i, j := range e.queue {
		out[i] = fmt.Sprintf("%d %s", i+1, j.tmpl.URL)
	}
	return out
}

func (c *Control) queueDel(n int) bool {
	c.mu.Lock()
	e := c.eng
	c.mu.Unlock()
	if e == nil {
		return false
	}
	e.outMu.Lock()
	defer e.outMu.Unlock()
	if n < 1 || n > len(e.queue) {
		return false
	}
	e.queue = append(e.queue[:n-1], e.queue[n:]...)
	e.cfg.Progress.Queued.Store(int64(len(e.queue)))
	return true
}
