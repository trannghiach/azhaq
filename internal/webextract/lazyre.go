package webextract

import (
	"regexp"
	"sync"
)

// lazyRegexp compiles its pattern on first use: a command that never reads
// a page does not pay for the hundred patterns of this package (2.6 MB
// allocated at start).
type lazyRegexp struct {
	src  string
	once sync.Once
	re   *regexp.Regexp
}

func lazyRE(src string) *lazyRegexp { return &lazyRegexp{src: src} }

func (l *lazyRegexp) get() *regexp.Regexp {
	l.once.Do(func() { l.re = regexp.MustCompile(l.src) })
	return l.re
}

func (l *lazyRegexp) FindAllString(s string, n int) []string { return l.get().FindAllString(s, n) }
func (l *lazyRegexp) FindAllStringIndex(s string, n int) [][]int {
	return l.get().FindAllStringIndex(s, n)
}
func (l *lazyRegexp) FindAllStringSubmatch(s string, n int) [][]string {
	return l.get().FindAllStringSubmatch(s, n)
}
func (l *lazyRegexp) FindAllStringSubmatchIndex(s string, n int) [][]int {
	return l.get().FindAllStringSubmatchIndex(s, n)
}
func (l *lazyRegexp) FindStringIndex(s string) []int { return l.get().FindStringIndex(s) }
func (l *lazyRegexp) FindStringSubmatch(s string) []string {
	return l.get().FindStringSubmatch(s)
}
func (l *lazyRegexp) FindStringSubmatchIndex(s string) []int {
	return l.get().FindStringSubmatchIndex(s)
}
func (l *lazyRegexp) FindSubmatch(b []byte) [][]byte { return l.get().FindSubmatch(b) }
func (l *lazyRegexp) MatchString(s string) bool      { return l.get().MatchString(s) }
func (l *lazyRegexp) ReplaceAllString(s, repl string) string {
	return l.get().ReplaceAllString(s, repl)
}
func (l *lazyRegexp) ReplaceAllStringFunc(s string, f func(string) string) string {
	return l.get().ReplaceAllStringFunc(s, f)
}
