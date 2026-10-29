package fuzz

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// List is the words of one keyword.
type List struct {
	Keyword string
	Words   []string
}

// ReadList reads path ("-" is stdin), one word per line, empty lines and
// all (an empty word asks for the URL itself, as in ffuf). Lines starting
// with # are dropped with skipComments; a trailing " # note" goes too.
// A list of the keyword FUZZ also gets each word with each extension.
func ReadList(path, keyword string, exts []string, skipComments bool) (List, error) {
	f := os.Stdin
	if path != "-" {
		var err error
		if f, err = os.Open(path); err != nil {
			return List{}, err
		}
		defer f.Close()
	}
	l := List{Keyword: keyword}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16<<20)
	for sc.Scan() {
		text := sc.Text()
		if skipComments {
			if strings.HasPrefix(strings.TrimLeft(text, " "), "#") {
				continue
			}
			if i := strings.Index(text, " #"); i >= 0 {
				text = text[:i]
			}
		}
		l.Words = append(l.Words, text)
		if keyword == "FUZZ" {
			for _, e := range exts {
				l.Words = append(l.Words, text+e)
			}
		}
	}
	return l, sc.Err()
}

// ParseWordlist splits -w "FILE[:KEYWORD]"; the keyword is FUZZ without one.
func ParseWordlist(spec string) (path, keyword string) {
	if _, err := os.Stat(spec); err == nil {
		return spec, "FUZZ"
	}
	if i := strings.LastIndex(spec, ":"); i > 0 {
		return spec[:i], spec[i+1:]
	}
	return spec, "FUZZ"
}

// Mode is how several wordlists are combined.
type Mode string

const (
	Clusterbomb Mode = "clusterbomb"
	Pitchfork   Mode = "pitchfork"
)

// ParseMode checks a -mode value.
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case Clusterbomb, Pitchfork:
		return Mode(s), nil
	}
	return "", fmt.Errorf("-mode %q: clusterbomb or pitchfork", s)
}

// Total is how many inputs the lists give: every combination for
// clusterbomb; for pitchfork the longest list, the shorter ones starting
// over, as ffuf does.
func Total(mode Mode, lists []List) int {
	if len(lists) == 0 {
		return 0
	}
	n := 1
	if mode == Pitchfork {
		n = 0
	}
	for _, l := range lists {
		if mode == Pitchfork {
			n = max(n, len(l.Words))
		} else {
			n *= len(l.Words)
		}
	}
	return n
}

// At is the i-th input (0-based): in clusterbomb the first list varies
// fastest.
func At(mode Mode, lists []List, i int) map[string]string {
	in := make(map[string]string, len(lists))
	for _, l := range lists {
		if len(l.Words) == 0 {
			continue
		}
		if mode == Pitchfork {
			in[l.Keyword] = l.Words[i%len(l.Words)]
			continue
		}
		in[l.Keyword] = l.Words[i%len(l.Words)]
		i /= len(l.Words)
	}
	return in
}
