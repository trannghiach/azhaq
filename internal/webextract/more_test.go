package webextract

import (
	"net/url"
	"strings"
	"testing"
)

func TestTemplate(t *testing.T) {
	for in, want := range map[string]string{
		"https://ginandjuice.shop/catalog/product?productId=7":  "https://ginandjuice.shop/catalog/product?productId={n}",
		"https://a.test/users/42/orders":                        "https://a.test/users/{n}/orders",
		"https://a.test/search?q=gin&page=2":                    "https://a.test/search?page={n}&q={v}",
		"https://a.test/o/3f2504e0-4f89-11d3-9a0c-0305e82c3301": "https://a.test/o/{uuid}",
		"https://a.test/blob/0123456789abcdef0123":              "https://a.test/blob/{hex}",
		"https://a.test/blog/a-hairy-day":                       "https://a.test/blog/a-hairy-day",
		"https://a.test/2fa/enter":                              "https://a.test/2fa/enter",
	} {
		if got := Template(in); got != want {
			t.Errorf("Template(%s) = %s, want %s", in, got, want)
		}
	}
	if Templated("https://a.test/about") || !Templated("https://a.test/p?id=1") {
		t.Error("Templated")
	}
}

func TestJSONLinksUnescapes(t *testing.T) {
	base, _ := url.Parse("http://127.0.0.1:3001/api/Challenges")
	body := []byte(`{"data":[{"description":"Read our <a href=\"/ftp/legal.md\">legal</a>.","img":"/assets/x.png","name":"two words /x"}]}`)
	got := strings.Join(JSONLinks(body, base), " ")
	if !strings.Contains(got, "http://127.0.0.1:3001/ftp/legal.md") || strings.Contains(got, "%5C") {
		t.Fatalf("links %s", got)
	}
	if strings.Contains(got, "/x") && !strings.Contains(got, "/assets/x.png") {
		t.Fatalf("free text read as a path: %s", got)
	}
}

func TestScriptDrivenForm(t *testing.T) {
	base, _ := url.Parse("https://ginandjuice.shop/")
	page := []byte(`<div id="subscribe" class="form" data-method="post" data-action="/catalog/subscribe">
<div class="row"><input type=email name=email></div>
<input type="hidden" name="csrf" value="x"><button type=submit>Go</button></div>
<input name="outside">`)
	forms := Forms(page, base)
	if len(forms) != 1 {
		t.Fatalf("forms %+v", forms)
	}
	f := forms[0]
	if f.Method != "POST" || f.Action != "https://ginandjuice.shop/catalog/subscribe" || strings.Join(f.Fields, ",") != "email,csrf" {
		t.Fatalf("form %+v", f)
	}
}

func TestScriptRefsRelativeToScript(t *testing.T) {
	base, _ := url.Parse("https://app.test/static/js/main.js")
	got := ScriptRefs(`import("./chunk-AB12.js");e.u=()=>"/static/js/42.3f9c.chunk.js";const cdn="https://cdn.test/x.js";const lib="@scope/pkg.js"`, base)
	want := "https://app.test/static/js/chunk-AB12.js https://app.test/static/js/42.3f9c.chunk.js"
	if strings.Join(got, " ") != want {
		t.Fatalf("refs %v", got)
	}
}

func TestJSURLsDropsNumericPaths(t *testing.T) {
	base, _ := url.Parse("https://app.test/")
	got := strings.Join(JSURLs(`a("/160");b("/2/3");c("/2fa/enter")`, base), " ")
	if got != "https://app.test/2fa/enter" {
		t.Fatalf("%s", got)
	}
}
