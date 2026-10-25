package timing

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Log collects named spans for one run. Safe for concurrent Start calls.
type Log struct {
	mu    sync.Mutex
	spans []Span
	// Notify, if set, is called after each span closes (not under the lock).
	Notify func(Span)
}

type Span struct {
	Name  string
	Label string
	Dur   time.Duration
}

type Stat struct {
	Name     string
	N        int
	Max      time.Duration
	MaxLabel string // what the slowest span was about (a URL, a domain)
	Sum      time.Duration
}

type ctxKey struct{}

func New() *Log { return &Log{} }

func With(ctx context.Context, l *Log) context.Context {
	if l == nil {
		return ctx
	}
	return context.WithValue(ctx, ctxKey{}, l)
}

func From(ctx context.Context) *Log {
	l, _ := ctx.Value(ctxKey{}).(*Log)
	return l
}

// Start begins a span. The returned func closes it once.
// With no Log on ctx this is a no-op, so it is safe at every call site.
func Start(ctx context.Context, name string, label ...string) func() {
	l := From(ctx)
	if l == nil || name == "" {
		return func() {}
	}
	lab := ""
	if len(label) > 0 {
		lab = label[0]
	}
	t0 := time.Now()
	var once sync.Once
	return func() {
		once.Do(func() {
			l.add(Span{Name: name, Label: lab, Dur: time.Since(t0)})
		})
	}
}

func (l *Log) add(s Span) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.spans = append(l.spans, s)
	n := l.Notify
	l.mu.Unlock()
	if n != nil {
		n(s)
	}
}

func (l *Log) Stats() []Stat {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	by := map[string]*Stat{}
	var order []string
	for _, s := range l.spans {
		st, ok := by[s.Name]
		if !ok {
			st = &Stat{Name: s.Name}
			by[s.Name] = st
			order = append(order, s.Name)
		}
		st.N++
		st.Sum += s.Dur
		if s.Dur > st.Max {
			st.Max = s.Dur
			st.MaxLabel = s.Label
		}
	}
	out := make([]Stat, 0, len(order))
	for _, name := range order {
		out = append(out, *by[name])
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Max != out[j].Max {
			return out[i].Max > out[j].Max
		}
		return out[i].Sum > out[j].Sum
	})
	return out
}

const slowMin = 25 * time.Millisecond

// Report is wall time plus the slowest span names (max ≥ 25ms).
func (l *Log) Report(wall time.Duration) string {
	var b strings.Builder
	fmt.Fprintf(&b, "took %s\n", wall.Round(time.Millisecond))
	if l == nil {
		return b.String()
	}
	var slow []Stat
	for _, s := range l.Stats() {
		if s.Max >= slowMin {
			slow = append(slow, s)
		}
	}
	if len(slow) == 0 {
		return b.String()
	}
	if len(slow) > 8 {
		slow = slow[:8]
	}
	width := 8
	for _, s := range slow {
		if len(s.Name) > width {
			width = len(s.Name)
		}
	}
	b.WriteString("slow\n")
	for _, s := range slow {
		fmt.Fprintf(&b, "  %-*s  %d × max %s", width, s.Name, s.N, s.Max.Round(time.Millisecond))
		if s.N > 1 && s.MaxLabel != "" {
			fmt.Fprintf(&b, "  (%s)", s.MaxLabel)
		}
		b.WriteByte('\n')
	}
	return b.String()
}
