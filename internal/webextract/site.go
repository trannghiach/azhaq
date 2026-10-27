package webextract

import (
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Site is where a script names a route: the script, the line and column
// (bytes, from 1) and the code around it.
//
//	http://127.0.0.1:3001/main.js:1:48213  this.http.post(`${F$.hostServer}/rest/2fa/verify`,{…})
type Site struct {
	Script  string `json:"script"`           // the script's URL, or the page's for a script inside it
	Source  string `json:"source,omitempty"` // the original file, for code read from a source map
	Inline  bool   `json:"inline,omitempty"` // a script inside the page Script names
	Line    int    `json:"line"`
	Col     int    `json:"col"`
	Snippet string `json:"snippet"`
}

// String is the site as script:line:col and the snippet.
func (s Site) String() string {
	where := s.Script
	if s.Source != "" {
		where = s.Source // the lines are the original file's
	}
	line := where + ":" + strconv.Itoa(s.Line) + ":" + strconv.Itoa(s.Col)
	switch {
	case s.Source != "":
		line += " (source map of " + s.Script + ")"
	case s.Inline:
		line += " (inline)"
	}
	if s.Snippet != "" {
		line += "  " + s.Snippet
	}
	return line
}

// MaxSnippet caps the code kept around a route, in bytes.
const MaxSnippet = 120

// Locator turns byte offsets in a source into lines, columns and
// snippets. The line index is built on first use: most scripts name no
// route at all.
type Locator struct {
	src string
	nl  []int // offsets of '\n'
	ok  bool
}

func NewLocator(src string) *Locator { return &Locator{src: src} }

// LineCol is the line and column of off, both from 1.
func (l *Locator) LineCol(off int) (int, int) {
	if !l.ok {
		for i := 0; i < len(l.src); i++ {
			if l.src[i] == '\n' {
				l.nl = append(l.nl, i)
			}
		}
		l.ok = true
	}
	off = max(0, min(off, len(l.src)))
	n := sort.SearchInts(l.nl, off) // newlines before off
	start := 0
	if n > 0 {
		start = l.nl[n-1] + 1
	}
	return n + 1, off - start + 1
}

// Snippet is the code from start to end, with what surrounds it on the
// same line up to MaxSnippet bytes, cut between words; a longer span is
// cut with "…".
func (l *Locator) Snippet(start, end int) string {
	src := l.src
	start, end = l.clamp(start, end)
	if end-start >= MaxSnippet {
		return l.Span(start, end)
	}
	lineStart := strings.LastIndexByte(src[:start], '\n') + 1
	lineEnd := len(src)
	if i := strings.IndexByte(src[end:], '\n'); i >= 0 {
		lineEnd = end + i
	}
	room := MaxSnippet - (end - start)
	from := max(lineStart, start-room/2)
	to := min(lineEnd, end+(room-(start-from)))
	from = max(lineStart, to-MaxSnippet) // the line ended: give the room to what comes before
	for from < start && from > lineStart && isIdentByte(src[from-1]) && isIdentByte(src[from]) {
		from++
	}
	for to > end && to < lineEnd && isIdentByte(src[to-1]) && isIdentByte(src[to]) {
		to--
	}
	return tidy(src[runeStart(src, from):runeStart(src, to)])
}

// Span is the code from start to end as written, a call say, cut with
// "…" past MaxSnippet bytes.
func (l *Locator) Span(start, end int) string {
	start, end = l.clamp(start, end)
	if end-start > MaxSnippet {
		return tidy(l.src[start:runeStart(l.src, start+MaxSnippet-1)]) + "…"
	}
	return tidy(l.src[start:end])
}

func (l *Locator) clamp(start, end int) (int, int) {
	start, end = max(0, min(start, len(l.src))), max(0, min(end, len(l.src)))
	return start, max(start, end)
}

// runeStart moves i back to the first byte of the rune it falls in.
func runeStart(s string, i int) int {
	for i > 0 && i < len(s) && !utf8.RuneStart(s[i]) {
		i--
	}
	return i
}

// tidy folds runs of white space into one space.
func tidy(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// Site is where start..end of the source lies, for a script at scriptURL,
// with the code around it.
func (l *Locator) Site(scriptURL string, start, end int) Site {
	line, col := l.LineCol(start)
	return Site{Script: scriptURL, Line: line, Col: col, Snippet: l.Snippet(start, end)}
}

// CallSite is Site for a call: the snippet is the call itself.
func (l *Locator) CallSite(scriptURL string, start, end int) Site {
	line, col := l.LineCol(start)
	return Site{Script: scriptURL, Line: line, Col: col, Snippet: l.Span(start, end)}
}
