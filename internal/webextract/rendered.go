package webextract

import (
	"bytes"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// Some pages leave their links for scripts to draw: Markdown a converter
// renders in the browser (DVNA's lessons: [User Search](/app/usersearch)),
// {{templates}} a framework fills, or an empty shell an app mounts into.
// What is written as text can be read without a browser; the rest is a
// reason to use one.

var (
	// mdLink: [text](/path), [text](https://…), [text](./x "title").
	mdLink = lazyRE(`\[[^\[\]\n]{1,300}\]\(\s*<?((?:https?://|\.{0,2}/)[^\s()<>"']*)>?(?:\s+"[^"\n]*")?\s*\)`)
	// tmplExpr is an expression a client-side template fills: {{ user.name }}.
	tmplExpr = lazyRE(`\{\{[^{}\n]{1,200}\}\}`)
	// mountIDs are the elements single-page apps render into.
	mountIDs = map[string]bool{"root": true, "app": true, "__next": true, "__nuxt": true, "___gatsby": true, "svelte": true, "app-root": true, "react-root": true}
)

// shellText is how much text a page may hold and still be an empty shell.
const shellText = 200

// Unrendered is what a page leaves for its scripts to render.
type Unrendered struct {
	Markdown  int  `json:"markdown,omitempty"`  // Markdown links in its text
	Templates int  `json:"templates,omitempty"` // {{ … }} expressions in its text
	Shell     bool `json:"shell,omitempty"`     // a mount point and scripts, and next to no text
}

// Any says the page leaves something to its scripts.
func (u Unrendered) Any() bool { return u.Markdown > 0 || u.Templates > 0 || u.Shell }

// ReadUnrendered reads what a page leaves for its scripts: the links in
// Markdown in its text, resolved against base, and what it holds unrendered.
// Text inside scripts and styles is not the page's.
func ReadUnrendered(body []byte, base *url.URL) ([]string, Unrendered) {
	var u Unrendered
	var links []string
	seen := map[string]bool{}
	z := html.NewTokenizer(bytes.NewReader(body))
	skip, code := 0, 0 // inside script, style, title, noscript; inside pre or code
	mount, scripts, text := false, 0, 0
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		switch tt {
		case html.StartTagToken, html.SelfClosingTagToken:
			tok := z.Token()
			tag := strings.ToLower(tok.Data)
			switch tag {
			case "script":
				scripts++
				if tt == html.StartTagToken {
					skip++
				}
			case "style", "title", "noscript", "template", "textarea":
				if tt == html.StartTagToken {
					skip++
				}
			case "pre", "code":
				if tt == html.StartTagToken {
					code++
				}
			case "app-root":
				mount = true
			}
			for _, a := range tok.Attr {
				switch strings.ToLower(a.Key) {
				case "id":
					mount = mount || mountIDs[strings.ToLower(a.Val)]
				case "ng-app", "ng-version", "data-reactroot", "data-v-app":
					mount = true
				}
			}
		case html.EndTagToken:
			switch strings.ToLower(z.Token().Data) {
			case "script", "style", "title", "noscript", "template", "textarea":
				skip = max(0, skip-1)
			case "pre", "code":
				code = max(0, code-1)
			}
		case html.TextToken:
			if skip > 0 {
				continue
			}
			t := string(z.Text())
			text += len(strings.TrimSpace(t))
			if code == 0 {
				u.Templates += len(tmplExpr.FindAllStringIndex(t, -1))
			}
			if !strings.Contains(t, "](") {
				continue
			}
			for _, link := range MarkdownLinks(t, base) {
				u.Markdown++
				if !seen[link] {
					seen[link] = true
					links = append(links, link)
				}
			}
		}
	}
	u.Shell = mount && scripts > 0 && text < shellText
	return links, u
}

// MarkdownLinks returns the targets of the Markdown links in text,
// resolved against base: URLs, and paths from the root or the page.
func MarkdownLinks(text string, base *url.URL) []string {
	if base == nil {
		return nil
	}
	var out []string
	for _, m := range mdLink.FindAllStringSubmatch(text, -1) {
		if u, ok := resolve(base, m[1]); ok && !JunkURL(u) {
			out = append(out, u)
		}
	}
	return out
}
