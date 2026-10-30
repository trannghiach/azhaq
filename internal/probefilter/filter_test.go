package probefilter

import (
	"regexp"
	"testing"
	"time"
)

func TestRanges(t *testing.T) {
	rs, err := ParseRanges("-mc", "200,301-302,4xx")
	if err != nil {
		t.Fatal(err)
	}
	for n, want := range map[int]bool{200: true, 201: false, 301: true, 302: true, 303: false, 404: true, 500: false} {
		if in(rs, n) != want {
			t.Errorf("%d: got %v", n, !want)
		}
	}
	if _, err := ParseRanges("-mc", "20x"); err == nil {
		t.Error("a bad number is an error")
	}
	if _, err := ParseRanges("-mc", "5-2"); err == nil {
		t.Error("a backwards span is an error")
	}
}

func TestTimeTest(t *testing.T) {
	for _, c := range []struct {
		expr string
		d    time.Duration
		want bool
	}{
		{"< 1", 500 * time.Millisecond, true},
		{"< 1", 2 * time.Second, false},
		{">= 500ms", 500 * time.Millisecond, true},
		{"!=2s", 2 * time.Second, false},
		{"= 3", 3 * time.Second, true},
	} {
		tt, err := ParseTime("-mrt", c.expr)
		if err != nil {
			t.Fatal(err)
		}
		if got := tt.Holds(c.d); got != c.want {
			t.Errorf("%q on %v: %v", c.expr, c.d, got)
		}
	}
	if _, err := ParseTime("-mrt", "5"); err == nil {
		t.Error("no operator is an error")
	}
}

func TestKeep(t *testing.T) {
	row := Row{Status: 200, Length: 100, Lines: 3, Words: 7, CDN: "cloudflare", Raw: "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\nWelcome ADMIN"}
	set := func(f func(*Set)) *Set { s := &Set{}; f(s); return s }
	re := func(p string) []*regexp.Regexp { r, _ := Regexes("-mr", []string{p}); return r }
	for name, c := range map[string]struct {
		s    *Set
		want bool
	}{
		"empty keeps":            {&Set{}, true},
		"match status":           {set(func(s *Set) { s.MatchStatus = []Range{{200, 200}} }), true},
		"match status misses":    {set(func(s *Set) { s.MatchStatus = []Range{{404, 404}} }), false},
		"filter status drops":    {set(func(s *Set) { s.FilterStatus = []Range{{200, 299}} }), false},
		"filter wins over match": {set(func(s *Set) { s.MatchStatus = []Range{{200, 200}}; s.FilterLength = []Range{{100, 100}} }), false},
		"string is case blind":   {set(func(s *Set) { s.MatchString = []string{"admin"} }), true},
		"any string matches":     {set(func(s *Set) { s.MatchString = []string{"nope", "welcome"} }), true},
		"filter string":          {set(func(s *Set) { s.FilterString = []string{"nginx"} }), false},
		"every match regex":      {set(func(s *Set) { s.MatchRegex = append(re("Welcome"), re("nope")...) }), false},
		"any filter regex":       {set(func(s *Set) { s.FilterRegex = append(re("nope"), re("^HTTP/1.1 200")...) }), false},
		"cdn match":              {set(func(s *Set) { s.MatchCDN = []string{"cloudflare"} }), true},
		"cdn filter":             {set(func(s *Set) { s.FilterCDN = []string{"cloudflare"} }), false},
		"all matchers must hold": {set(func(s *Set) { s.MatchStatus = []Range{{200, 200}}; s.MatchWords = []Range{{8, 8}} }), false},
	} {
		got, err := c.s.Keep(row)
		if err != nil || got != c.want {
			t.Errorf("%s: got %v, %v", name, got, err)
		}
	}
}

func TestExpr(t *testing.T) {
	vars := map[string]any{"status_code": 200, "title": "Admin Panel", "body": "hello <b>world</b>", "tech": []string{"nginx", "php"}, "words": 10}
	for src, want := range map[string]bool{
		`status_code == 200`:                             true,
		`status_code == 200 && contains(body, "world")`:  true,
		`status_code != 200 || contains(title, "Admin")`: true,
		`!contains(body, "xyz")`:                         true,
		`words > 5 && words <= 10`:                       true,
		`len(tech) == 2`:                                 true,
		`contains(to_lower(title), "admin panel")`:       true,
		`title =~ "^Admin"`:                              true,
		`regex("w[a-z]+d", body)`:                        true,
		`starts_with(title, "Login", "Admin")`:           true,
		`words / 2 == 5`:                                 true,
		`status_code == 404`:                             false,
		`md5("a") == "0cc175b9c0f1b6a831c399e269772661"`: true,
	} {
		e, err := Compile("-mdc", src)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		got, err := e.Eval(vars)
		if err != nil || got != want {
			t.Errorf("%s: got %v, %v", src, got, err)
		}
	}
	// A mistake is an error, not a silent false.
	for _, src := range []string{`status_code ==`, `contains(body`, `"open`, `status_code & 1`} {
		if _, err := Compile("-mdc", src); err == nil {
			t.Errorf("%s compiled", src)
		}
	}
	for _, src := range []string{`nope == 1`, `unknown(1)`, `words > "x"`, `1`} {
		e, err := Compile("-mdc", src)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		if _, err := e.Eval(vars); err == nil {
			t.Errorf("%s evaluated", src)
		}
	}
}
