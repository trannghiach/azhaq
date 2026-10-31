package wappalyzer

import (
	"reflect"
	"regexp/syntax"
	"runtime"
	"testing"
)

// literalsViaSimplify is the prefilter read from the pattern with every
// repeat unrolled by Simplify, which is what the loader used to do.
func literalsViaSimplify(expr string) [][]string {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return nil
	}
	return selectiveLiterals(cover(re.Simplify()))
}

func TestPrefilterOfRepeatsIsWhatSimplifyGave(t *testing.T) {
	for _, pat := range []string{
		`jquery[.-]?v?(\d+\.\d+)`, `wp-content/themes/(\w+)/`, `abc\w+def`, `ab{2}c`, `ab{2,3}c`, `ab{2,}c`, `(?:ab){3}cd`,
		`a{0,5}bcd`, `(x|yz){2}foo`, `foo(bar|baz){1,3}qux`, `\bfoo\d{2,4}bar\b`, `ab+c+d`, `set-cookie: (?:a|b){1,250}xyz`,
	} {
		p, err := ParsePattern(pat)
		if err != nil {
			t.Fatal(pat, err)
		}
		if want := literalsViaSimplify(p.expr); !reflect.DeepEqual(p.literals, want) {
			t.Errorf("%s: prefilter %q, Simplify gave %q", pat, p.literals, want)
		}
	}
	client, err := New()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	check := func(ps []*ParsedPattern) {
		for _, p := range ps {
			if p == nil || p.expr == "" {
				continue
			}
			n++
			if want := literalsViaSimplify(p.expr); !reflect.DeepEqual(p.literals, want) {
				t.Errorf("%s: prefilter %q, Simplify gave %q", p.expr, p.literals, want)
			}
		}
	}
	for _, f := range client.fingerprints.Apps {
		check(f.html)
		check(f.script)
		check(f.scriptSrc)
	}
	if n < 1000 {
		t.Errorf("only %d patterns checked", n)
	}
}

// Loading read each pattern through Simplify, which writes out "x{1,250}"
// 250 times: 150 MB allocated and a collector at work for most of 0.5 s.
func TestLoadAllocatesLittle(t *testing.T) {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if _, err := New(); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	if mb := (after.TotalAlloc - before.TotalAlloc) >> 20; mb > 80 {
		t.Errorf("loading the fingerprints allocated %d MB", mb)
	}
}
