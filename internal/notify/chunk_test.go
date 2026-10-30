package notify

import (
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func msgs(t *testing.T, in string, cl int, bulk bool) []string {
	t.Helper()
	var out []string
	if err := Messages(strings.NewReader(in), cl, bulk, func(m string) error { out = append(out, m); return nil }); err != nil {
		t.Fatal(err)
	}
	return out
}

func eq(t *testing.T, got, want []string) {
	t.Helper()
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") || len(got) != len(want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestOneMessagePerLineSkipsEmptyOnes(t *testing.T) {
	eq(t, msgs(t, "a\n\nb\r\nc", 4000, false), []string{"a", "b", "c"})
}

func TestBulkPacksLinesUpToTheLimit(t *testing.T) {
	eq(t, msgs(t, "aaa\nbbb\nccc\nddd\n", 9, true), []string{"aaa\nbbb", "ccc\nddd"})
	eq(t, msgs(t, "aaa\nbbb\nccc\n", 11, true), []string{"aaa\nbbb\nccc"})
	eq(t, msgs(t, "a\nb\nc", 4000, true), []string{"a\nb\nc"})
}

// A line over the limit goes out in pieces of limit-3 characters, each
// but the last ending in "...": notify's rule, not a cut.
func TestLongLineIsSentInPieces(t *testing.T) {
	line := strings.Repeat("0123456789", 5) // 50
	eq(t, msgs(t, line, 23, false), []string{line[:20] + "...", line[20:40] + "...", line[40:]})
	eq(t, msgs(t, line+"\nxy\n", 23, true), []string{line[:20] + "...", line[20:40] + "...", line[40:] + "\nxy"})
}

func TestChunksNeverCutACharacter(t *testing.T) {
	in := strings.Repeat("é", 40)
	for _, m := range msgs(t, in, 15, false) {
		if !utf8.ValidString(m) || len(m) > 15 {
			t.Errorf("%q", m)
		}
	}
	if got := strings.ReplaceAll(strings.Join(msgs(t, in, 15, false), ""), "...", ""); got != in {
		t.Errorf("characters lost: %q", got)
	}
}

func TestLimitMustHoldTheEllipsis(t *testing.T) {
	if err := Messages(strings.NewReader("x"), 3, false, func(string) error { return nil }); err == nil {
		t.Error("-cl 3 cannot carry an ellipsis")
	}
}

func TestSplitLabelsAndKeepsTheLimit(t *testing.T) {
	text := strings.Repeat("alpha beta gamma\n", 500)
	parts := Split(text, 1000)
	if len(parts) < 8 {
		t.Fatalf("%d parts", len(parts))
	}
	for i, p := range parts {
		if utf8.RuneCountInString(p) > 1000 || !strings.HasPrefix(p, "("+itoa(i+1)+"/"+itoa(len(parts))+") ") {
			t.Errorf("part %d: %d characters, starts %q", i, utf8.RuneCountInString(p), p[:8])
		}
	}
	if got := Split("short", 1000); len(got) != 1 || got[0] != "short" {
		t.Errorf("%q", got)
	}
	if got := Split("anything", 0); len(got) != 1 {
		t.Errorf("no limit: %q", got)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestFormatMessage(t *testing.T) {
	now := time.Date(2026, 10, 30, 14, 5, 9, 0, time.FixedZone("", -5*3600))
	got := FormatMessage("{{count}} {{data}}", "[{{datetime}}] {{date}} {{time}} #{{count}}: {{data}}", 7, now)
	if want := "[10-30-2026 14:05:09-0500] 10-30-2026 14:05:09-0500 #7: {{count}} {{data}}"; got != want {
		t.Errorf("%q, want %q", got, want)
	}
	if SelectFormat("cli", "cfg") != "cli" || SelectFormat("", "cfg") != "cfg" || SelectFormat("", "") != "{{data}}" {
		t.Error("format precedence")
	}
}
