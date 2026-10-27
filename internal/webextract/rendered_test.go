package webextract

import (
	"net/url"
	"reflect"
	"testing"
)

// Shaped like DVNA's lessons: Markdown in a div, turned into links by
// showdown once the page has loaded.
const dvnaLesson = `<!DOCTYPE html><html><head><title>Damn Vulnerable NodeJS Application</title>
<script src='/assets/jquery-3.2.1.min.js'></script></head><body>
<a href="/learn/vulnerability/a1_injection">A1: Injection</a>
<div class='markdown'>
**Vulnerable pages**
* [SQL Injection: User Search](/app/usersearch)
* [Command Injection: Network Connectivity Test](/app/ping "ping")
* [OWASP](https://www.owasp.org/index.php/Top_10-2017_A1-Injection)
* [Back](/learn/vulnerability/a1_injection)
http://example.com/app/accountView?id=' or '1'='1
</div>
<pre><code>[sample](/in/a/code/sample)</code></pre>
<script src='/assets/showdown.min.js'></script>
<script>var md = "[nor](/in/a/string)"; $('.markdown').each(function(){ $(this).html(converter.makeHtml($(this).html())) })</script>
</body></html>`

func TestReadUnrenderedMarkdown(t *testing.T) {
	base, _ := url.Parse("http://dvna.test/learn/vulnerability/a1_injection")
	links, un := ReadUnrendered([]byte(dvnaLesson), base)
	want := []string{
		"http://dvna.test/app/usersearch",
		"http://dvna.test/app/ping",
		"https://www.owasp.org/index.php/Top_10-2017_A1-Injection",
		"http://dvna.test/learn/vulnerability/a1_injection",
		"http://dvna.test/in/a/code/sample", // read: a Markdown converter would render it too
	}
	if !reflect.DeepEqual(links, want) {
		t.Errorf("links\n got %q\nwant %q", links, want)
	}
	if un.Markdown != 5 || un.Templates != 0 || un.Shell {
		t.Errorf("unrendered %+v", un)
	}
}

func TestReadUnrenderedShellsAndTemplates(t *testing.T) {
	base, _ := url.Parse("http://app.test/")
	for name, tc := range map[string]struct {
		page string
		want Unrendered
	}{
		"react shell": {`<html><head><title>App</title></head><body><noscript>You need to enable JavaScript to run this app.</noscript><div id="root"></div><script src="/static/js/main.js"></script></body></html>`,
			Unrendered{Shell: true}},
		"angular shell": {`<html><body><app-root></app-root><script src="main.js" type="module"></script></body></html>`,
			Unrendered{Shell: true}},
		"angularjs templates": {`<html><body ng-app="shop"><h1>{{ shop.name }}</h1><p>{{item.price | currency}}</p><a ng-href="/item/{{item.id}}">{{ item.title }}</a><script src="/app.js"></script>` + longText + `</body></html>`,
			Unrendered{Templates: 3}},
		"server-rendered": {`<html><body><div id="app"><h1>Welcome</h1><a href="/about">About</a>` + longText + `</div><script src="/js/site.js"></script></body></html>`,
			Unrendered{}},
		"template code shown, not filled": {`<html><body><pre>{{ name }}</pre><code>{{ x }}</code>` + longText + `</body></html>`,
			Unrendered{}},
		"no scripts": {`<html><body><div id="root"></div></body></html>`,
			Unrendered{}},
	} {
		if _, got := ReadUnrendered([]byte(tc.page), base); got != tc.want {
			t.Errorf("%s: %+v, want %+v", name, got, tc.want)
		}
	}
}

const longText = `<p>Gin and juice, a shop of fine spirits since 1998. Our story begins in a small distillery by the sea,
where the founders blended botanicals by hand and sold their first bottles to friends and neighbours.</p>`

func TestJSONLinksMarkdownAndNoise(t *testing.T) {
	base, _ := url.Parse("http://shop.test/api/x")
	body := []byte(`{"publisher":{"namespace":"/juice-shop/juice-shop"},"hint":"See [the docs](/docs/api) first.","path":"/rest/me","k":"/pQ"}`)
	got := JSONLinks(body, base)
	want := map[string]bool{"http://shop.test/docs/api": true, "http://shop.test/rest/me": true}
	if len(got) != len(want) {
		t.Fatalf("JSONLinks = %q", got)
	}
	for _, u := range got {
		if !want[u] {
			t.Errorf("unexpected %s", u)
		}
	}
}
