package fuzz

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
)

// List is the words of one keyword: Words, or Count words made by Gen
// (an input command's output).
type List struct {
	Keyword string
	Words   []string
	Count   int
	Gen     func(i int) string
	Command bool          // the words come from -input-cmd: output shows the position
	Failed  *atomic.Int64 // commands that failed
}

// Len is how many words the list has.
func (l List) Len() int {
	if l.Gen != nil {
		return l.Count
	}
	return len(l.Words)
}

// Word is the i-th word.
func (l List) Word(i int) string {
	if l.Gen != nil {
		return l.Gen(i)
	}
	return l.Words[i]
}

// ListOptions shape how a wordlist is read.
type ListOptions struct {
	Exts           []string // added to each word of the keyword FUZZ
	IgnoreComments bool     // -ic: drop # lines and a trailing " # note"
	DirSearch      bool     // -D: %EXT% in a line stands for each extension
	Chain          Chain    // -enc: applied to each word, extensions included
}

// ReadList reads path ("-" is stdin), one word per line, empty lines and
// all (an empty word asks for the URL itself, as in ffuf). Lines starting
// with # are dropped with IgnoreComments; a trailing " # note" goes too.
// A list of the keyword FUZZ also gets each word with each extension.
func ReadList(path, keyword string, o ListOptions) (List, error) {
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
		if o.DirSearch && len(o.Exts) > 0 && strings.Contains(strings.ToLower(text), "%ext%") {
			for _, e := range o.Exts {
				l.Words = append(l.Words, extToken.ReplaceAllLiteralString(text, e))
			}
			continue
		}
		if o.IgnoreComments {
			if strings.HasPrefix(strings.TrimLeft(text, " "), "#") {
				continue
			}
			if i := strings.Index(text, " #"); i >= 0 {
				text = text[:i]
			}
		}
		l.Words = append(l.Words, text)
		if keyword == "FUZZ" && !o.DirSearch {
			for _, e := range o.Exts {
				l.Words = append(l.Words, text+e)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return l, err
	}
	if len(o.Chain) > 0 {
		for i, w := range l.Words {
			enc, err := o.Chain.Apply(w)
			if err != nil {
				return l, fmt.Errorf("-enc on %q: %v", w, err)
			}
			l.Words[i] = enc
		}
	}
	return l, nil
}

var extToken = regexp.MustCompile(`(?i)%ext%`)

// CommandList is -input-cmd: for each number 0..n-1 the command is run with
// FFUF_NUM set to it, and what it prints is the word. It runs when the input
// is made, not before, so a run stopped early or resumed (-start) does not run
// what it does not reach. A command that fails gives an empty word, as in
// ffuf, and is counted in List.Failed.
func CommandList(shell, command, keyword string, n int, chain Chain) List {
	l := List{Keyword: keyword, Count: n, Command: true, Failed: new(atomic.Int64)}
	l.Gen = func(i int) string {
		cmd := exec.Command(shell, shellArg, command)
		cmd.Env = append(os.Environ(), "FFUF_NUM="+strconv.Itoa(i))
		out, err := cmd.Output()
		if err != nil {
			l.Failed.Add(1)
			return ""
		}
		w := string(out)
		if len(chain) > 0 {
			if w, err = chain.Apply(w); err != nil {
				l.Failed.Add(1)
				return ""
			}
		}
		return w
	}
	return l
}

// SplitWordlists makes "-w a.txt,b.txt" two wordlists; a file whose name has a
// comma in it stays one.
func SplitWordlists(specs []string) []string {
	var out []string
	for _, s := range specs {
		if _, err := os.Stat(s); err == nil || !strings.Contains(s, ",") {
			out = append(out, s)
			continue
		}
		out = append(out, strings.Split(s, ",")...)
	}
	return out
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
	// Sniper puts one wordlist in one place at a time: the places are marked
	// §like this§ in the URL, headers, body or method.
	Sniper Mode = "sniper"
)

// ParseMode checks a -mode value.
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case Clusterbomb, Pitchfork, Sniper:
		return Mode(s), nil
	}
	return "", fmt.Errorf("-mode %q: clusterbomb, pitchfork or sniper", s)
}

// Total is how many inputs the lists give: every combination for
// clusterbomb (and sniper, which has one list); for pitchfork the longest list, the shorter ones starting
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
			n = max(n, l.Len())
		} else {
			n *= l.Len()
		}
	}
	return n
}

// At is the i-th input (0-based): in clusterbomb the first list varies
// fastest.
func At(mode Mode, lists []List, i int) map[string]string {
	in := make(map[string]string, len(lists))
	for _, l := range lists {
		n := l.Len()
		if n == 0 {
			continue
		}
		if mode == Pitchfork {
			in[l.Keyword] = l.Word(i % n)
			continue
		}
		in[l.Keyword] = l.Word(i % n)
		i /= n
	}
	return in
}

const shellArg = "-c"
