package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// A DVNA-like app: /login has a sign-in form and links to /register and
// /forgotpw, each with a POST form.
func dvnaSite(t *testing.T) (*httptest.Server, func() []string) {
	var mu sync.Mutex
	var posts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			posts = append(posts, r.URL.Path+" "+string(b))
			mu.Unlock()
			w.WriteHeader(200)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/login":
			fmt.Fprint(w, `<html><body><form action="/login" method="post"><input name="username"><input type="password" name="password"><button>Sign in</button></form>
<a href="/register">Register</a> <a href="/forgotpw">Forgot password</a></body></html>`)
		case "/register":
			fmt.Fprint(w, `<html><body><form action="/register" method="post"><input name="username"><input name="email" type="email"><input type="password" name="password"><input type="password" name="cpassword"></form></body></html>`)
		case "/forgotpw":
			fmt.Fprint(w, `<html><body><form action="/forgotpw" method="post"><input name="email" type="email"></form></body></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), posts...)
	}
}

// A POST form posts to the page it is on (an empty action or its own
// address): -submit-forms sends it, and says how many it sent.
func TestCrawlSubmitFormsSendsThePostForms(t *testing.T) {
	srv, posts := dvnaSite(t)
	db := filepath.Join(t.TempDir(), "w.db")
	_, errOut, err := captureBoth(t, func() error {
		return cmdCrawl([]string{"-u", srv.URL + "/login", "-allow", "127.0.0.1", "-submit-forms", "-db", db})
	})
	if err != nil && exitCode(err) != exitPartial {
		t.Fatal(err)
	}
	want := []string{
		"/forgotpw email=azhaq%40example.org",
		"/login username=azhaq&password=azhaqP4ssw0rd",
		"/register username=azhaq&email=azhaq%40example.org&password=azhaqP4ssw0rd&cpassword=azhaqP4ssw0rd",
	}
	got := posts()
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("posts %q, want %q", got, want)
	}
	if !strings.Contains(errOut, "3 POST forms were submitted") {
		t.Errorf("the summary does not count the submissions:\n%s", errOut)
	}
	ledger, err := os.ReadFile(db + ".ledger.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(ledger), `"method":"POST"`); n != 3 {
		t.Errorf("%d POSTs in the ledger, want 3:\n%s", n, ledger)
	}
}

func TestCrawlWithoutSubmitFormsSendsNoPost(t *testing.T) {
	srv, posts := dvnaSite(t)
	_, _, err := captureBoth(t, func() error {
		return cmdCrawl([]string{"-u", srv.URL + "/login", "-allow", "127.0.0.1", "-db", filepath.Join(t.TempDir(), "w.db")})
	})
	if err != nil && exitCode(err) != exitPartial {
		t.Fatal(err)
	}
	if p := posts(); len(p) != 0 {
		t.Errorf("posts without -submit-forms: %q", p)
	}
}

// A POST form that is not sent is named in the summary, with why; one
// whose address says delete is sent like any other: a name decides nothing.
func TestCrawlSubmitFormsNamesTheFormsItDoesNotSend(t *testing.T) {
	var mu sync.Mutex
	var posts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			mu.Lock()
			posts = append(posts, r.URL.Path)
			mu.Unlock()
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><form action="/delete/account" method="post"><input name="id" value="1"></form>
<form action="/up" method="post" enctype="multipart/form-data"><input type="file" name="f"></form>
<form action="http://elsewhere.test/in" method="post"><input name="q"></form>
<form action="/admin/wipe" method="post"><input name="id" value="1"></form></body></html>`)
	}))
	t.Cleanup(srv.Close)
	_, errOut, err := captureBoth(t, func() error {
		return cmdCrawl([]string{"-u", srv.URL + "/", "-allow", "127.0.0.1", "-submit-forms", "-deny-path", `^/admin/`, "-db", filepath.Join(t.TempDir(), "w.db")})
	})
	if err != nil && exitCode(err) != exitPartial {
		t.Fatal(err)
	}
	if len(posts) != 1 || posts[0] != "/delete/account" {
		t.Errorf("posts %q, want only /delete/account", posts)
	}
	for _, want := range []string{"/up was not submitted", "http://elsewhere.test/in was not submitted: it is outside the crawl's scope", "/admin/wipe was not submitted: -deny-path ^/admin/"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("the summary lacks %q:\n%s", want, errOut)
		}
	}
}
