package notify

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// The splitters are projectdiscovery/notify's (MIT), internal/runner/util.go:
// a line longer than the limit is sent in pieces of limit-3 bytes, each
// ending in "..." but the last. The one difference: a piece never ends in
// the middle of a character.
var ellipsis = []byte("...")

// backOff moves n down to the start of a character.
func backOff(data []byte, n int) int {
	m := n
	for m > 0 && m < len(data) && !utf8.RuneStart(data[m]) {
		m--
	}
	if m == 0 {
		return n // a limit smaller than one character: cut it
	}
	return m
}

func bulkSplitter(charLimit int) (bufio.SplitFunc, error) {
	if charLimit <= len(ellipsis) {
		return nil, fmt.Errorf("the character limit must be above %d", len(ellipsis))
	}
	return func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		var lineAdvance int
		var line []byte
		for {
			lineAdvance, line, err = bufio.ScanLines(data[advance:], atEOF)
			if err != nil || line == nil {
				if atEOF {
					break
				}
				if len(data) < charLimit {
					return 0, nil, nil // more data needed
				}
				if len(token) == 0 {
					// Even the first line is too much: send a piece of it.
					n := backOff(data, charLimit-len(ellipsis))
					token = append(token, data[:n]...)
					token = append(token, ellipsis...)
					return n, token, nil
				}
				break
			}
			if len(token)+len(line) > charLimit {
				if len(token) == 0 {
					n := backOff(line, charLimit-len(ellipsis))
					token = append(token, line[:n]...)
					token = append(token, ellipsis...)
					advance = n
					return
				}
				break
			}
			advance += lineAdvance
			token = append(token, line...)
			token = append(token, '\n')
		}
		if len(token) > 0 {
			token = token[:len(token)-1] // the trailing newline
		}
		return
	}, nil
}

func lineLengthSplitter(charLimit int) (bufio.SplitFunc, error) {
	if charLimit <= len(ellipsis) {
		return nil, fmt.Errorf("the character limit must be above %d", len(ellipsis))
	}
	return func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		var line []byte
		advance, line, err = bufio.ScanLines(data[advance:], atEOF)
		if !atEOF && (err != nil || line == nil) {
			if len(data) < charLimit {
				return 0, nil, nil
			}
			n := backOff(data, charLimit-len(ellipsis))
			token = append(token, data[:n]...)
			token = append(token, ellipsis...)
			return n, token, nil
		}
		if len(line) > charLimit {
			n := backOff(line, charLimit-len(ellipsis))
			token = append(token, line[:n]...)
			token = append(token, ellipsis...)
			return n, token, nil
		}
		return advance, line, err
	}, nil
}

// Messages reads r and calls send with each message notify would send: a
// line each, or with bulk as many lines as fit in charLimit bytes. Empty
// messages are skipped. It stops at the first error send returns.
func Messages(r io.Reader, charLimit int, bulk bool, send func(msg string) error) error {
	br := bufio.NewScanner(r)
	if charLimit > bufio.MaxScanTokenSize {
		br.Buffer(make([]byte, 0, charLimit), charLimit)
	}
	var split bufio.SplitFunc
	var err error
	if bulk {
		split, err = bulkSplitter(charLimit)
	} else {
		split, err = lineLengthSplitter(charLimit)
	}
	if err != nil {
		return err
	}
	br.Split(split)
	for br.Scan() {
		if msg := br.Text(); len(msg) > 0 {
			if err := send(msg); err != nil {
				return err
			}
		}
	}
	return br.Err()
}

// Split cuts msg into parts of at most limit runes for a service that
// takes no more, at a newline or a space when one is near the end, and
// labels them "(2/3) ". A message that fits is returned as it is. limit
// 0 means no limit.
func Split(msg string, limit int) []string {
	if limit <= 0 || utf8.RuneCountInString(msg) <= limit {
		return []string{msg}
	}
	body := limit - 12 // room for "(10/10) "
	if body < 20 {
		body = limit
	}
	runes := []rune(msg)
	var parts []string
	for len(runes) > 0 {
		end := min(body, len(runes))
		next := end
		if end < len(runes) {
			for r := 0; r < min(100, end-1); r++ {
				if c := runes[end-r]; c == '\n' || c == ' ' {
					end, next = end-r, end-r+1
					break
				}
			}
		}
		parts = append(parts, string(runes[:end]))
		runes = runes[min(next, len(runes)):]
	}
	if len(parts) == 1 {
		return parts
	}
	for i, p := range parts {
		parts[i] = fmt.Sprintf("(%d/%d) %s", i+1, len(parts), p)
	}
	return parts
}

// joinParts undoes Split, for tests.
func joinParts(parts []string) string {
	var b strings.Builder
	for i, p := range parts {
		_, p, _ = strings.Cut(p, ") ")
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(p)
	}
	return b.String()
}
