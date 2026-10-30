package crawlscope

import "testing"

func TestFieldScopes(t *testing.T) {
	root := "http://www.azqlab.lan:8080/"
	cases := []struct {
		cfg  Config
		link string
		want bool
	}{
		{Config{}, "http://www.azqlab.lan:8080/a", true},
		{Config{}, "http://api.azqlab.lan:8080/a", false},
		{Config{Field: "rdn"}, "http://api.azqlab.lan:8080/a", true},
		{Config{Field: "rdn"}, "https://azqlab.lan/a", true},
		{Config{Field: "rdn"}, "http://evilazqlab.lan/a", false},
		{Config{Field: "fqdn"}, "http://api.azqlab.lan:8080/a", false},
		{Config{Field: "fqdn"}, "https://www.azqlab.lan/a", true},
		{Config{Field: "dn"}, "http://azqlab.example.org/a", true},
		{Config{Field: `^api\.`}, "http://api.other.lan/a", true},
		{Config{Field: "rdn", Out: []string{`/logout`}}, "http://api.azqlab.lan/logout", false},
		{Config{Field: "rdn", In: []string{`/v1/`}}, "http://api.azqlab.lan/v2/x", false},
		{Config{Field: "rdn", In: []string{`/v1/`}}, "http://api.azqlab.lan/v1/x", true},
		{Config{Any: true}, "http://elsewhere.test/x", true},
		{Config{Any: true, Out: []string{`elsewhere`}}, "http://elsewhere.test/x", false},
		{Config{Field: "rdn-origin"}, "http://api.azqlab.lan:8080/a", true},
	}
	for i, c := range cases {
		c.cfg.Roots = []string{root}
		if err := Set(c.cfg); err != nil {
			t.Fatal(err)
		}
		if got := Within(root, c.link); got != c.want {
			t.Errorf("case %d %+v: Within(%s) = %v, want %v", i, c.cfg.Field, c.link, got, c.want)
		}
	}
	Reset()
}

func TestAddressIsOnlyItself(t *testing.T) {
	root := "http://127.0.0.1:3001/"
	for _, f := range []string{"rdn", "rdn-origin", "fqdn"} {
		_ = Set(Config{Field: f, Roots: []string{root}})
		if !Within(root, "http://127.0.0.1:3001/x") || Within(root, "http://127.0.0.2:3001/x") {
			t.Errorf("%s: an address is only itself", f)
		}
	}
	_ = Set(Config{Field: "rdn", Roots: []string{root}})
	if !Within(root, "http://127.0.0.1:4200/x") {
		t.Error("rdn follows another port of the host, as katana does")
	}
	_ = Set(Config{Field: "rdn-origin", Roots: []string{root}})
	if Within(root, "http://127.0.0.1:4200/x") {
		t.Error("the default keeps an address to its port")
	}
	Reset()
}

func TestBadRegex(t *testing.T) {
	if Set(Config{In: []string{"("}}) == nil || Set(Config{Field: "("}) == nil {
		t.Error("a bad regex is an error")
	}
	Reset()
}
