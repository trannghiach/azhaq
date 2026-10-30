package subcol

import (
	"context"
	"math"
	"sync"
)

// Dependent names the sources whose answers are not independent samples of
// what the sources know: padding sources and the name history. A name only
// they gave is in the output but not in the coverage counts.
func Dependent() map[string]bool {
	dep := map[string]bool{historyName: true}
	for _, s := range allSources() {
		if s.verify {
			dep[s.name] = true
		}
	}
	return dep
}

// Chao1 estimates how many names the independent sources hold, from how many
// of them gave each name (found_by): S + f1²/(2·f2), where f1 names have one
// source and f2 two; with f2 = 0, S + f1(f1−1)/2. S counts the names with an
// independent source. keep, if set, restricts the names. ok is false with
// fewer than two independent sources in play: with one, nothing overlaps and
// there is nothing to estimate from.
func Chao1(foundBy map[string][]string, dependent map[string]bool, keep func(string) bool) (observed int, estimated float64, ok bool) {
	var f1, f2 int
	srcs := map[string]bool{}
	for name, by := range foundBy {
		if keep != nil && !keep(name) {
			continue
		}
		n := 0
		for _, s := range by {
			if !dependent[s] {
				n++
				srcs[s] = true
			}
		}
		switch {
		case n == 0:
			continue
		case n == 1:
			f1++
		case n == 2:
			f2++
		}
		observed++
	}
	if len(srcs) < 2 {
		return observed, float64(observed), false
	}
	estimated = float64(observed)
	if f2 > 0 {
		estimated += float64(f1*f1) / float64(2*f2)
	} else {
		estimated += float64(f1*(f1-1)) / 2
	}
	return observed, estimated, true
}

// coverage is the payload's "coverage".
func coverage(foundBy map[string][]string, dependent map[string]bool) map[string]any {
	s, est, ok := Chao1(foundBy, dependent, nil)
	if !ok || s == 0 {
		return nil
	}
	return map[string]any{
		"observed":  s,
		"estimated": int(est + 0.5),
		"share":     math.Round(float64(s)/est*100) / 100,
	}
}

// schnabel estimates the population a source samples at random from its
// rounds' name sets: Σ(C_t·M_t) / ΣR_t, with C_t the round's size, M_t the
// names seen before it and R_t how many of its names were among them. ok is
// false when no round repeated a name.
func schnabel(rounds [][]string) (float64, bool) {
	seen := map[string]bool{}
	var num, recaptured float64
	for _, round := range rounds {
		set := map[string]bool{}
		re := 0
		for _, n := range round {
			if set[n] {
				continue
			}
			set[n] = true
			if seen[n] {
				re++
			}
		}
		num += float64(len(set) * len(seen))
		recaptured += float64(re)
		for n := range set {
			seen[n] = true
		}
	}
	if recaptured == 0 {
		return 0, false
	}
	return num / recaptured, true
}

type roundsKey struct{}

// roundLog keeps a sampled source's rounds in memory for schnabel.
type roundLog struct {
	mu     sync.Mutex
	rounds [][]string
	stats  []roundStat
}

func (l *roundLog) statSnapshot() []roundStat {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]roundStat(nil), l.stats...)
}

func (l *roundLog) snapshot() [][]string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([][]string(nil), l.rounds...)
}

// recordRound adds one round's names to the log Run set up for the source.
func recordRound(ctx context.Context, names []string) {
	if l, ok := ctx.Value(roundsKey{}).(*roundLog); ok {
		l.mu.Lock()
		l.rounds = append(l.rounds, append([]string(nil), names...))
		l.mu.Unlock()
	}
}
