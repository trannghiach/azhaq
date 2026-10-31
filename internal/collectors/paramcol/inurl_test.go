package paramcol

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/internal/fetch"
)

func ownWhy(t *testing.T, got map[string]any) map[string]any {
	t.Helper()
	why, _ := got["why"].(map[string]any)
	if why == nil {
		why = map[string]any{}
	}
	return why
}

// A parameter the input URL already carries is tested too: q changes the
// answer (a search page), utm_source does not and is not reported, and a
// name only in the list (security) that the page ignores stays out.
func TestParamInInputURLIsFound(t *testing.T) {
	fetch.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("q") {
			fmt.Fprint(w, "<html>"+strings.Repeat("a ", 100)+"</html>")
			return
		}
		fmt.Fprint(w, "<html>"+strings.Repeat("all products ", 500)+"</html>")
	}))
	defer srv.Close()
	words := []string{"security", "q", "page"}
	for i := range 300 {
		words = append(words, fmt.Sprintf("noise%d", i))
	}
	c := New(srv.Client(), Options{Words: words, Rate: 10000})
	why := ownWhy(t, runOn(t, c, srv.URL+"/rest/search?q=apple&utm_source=mail"))
	if why["q"] != "size" || len(why) != 1 {
		t.Errorf("found %v, want q alone, by size", why)
	}
}

// DVWA's ?id=1&Submit=Submit: removing Submit changes the answer a little
// (59 bytes), another value of id changes it too.
func TestParamInInputURLSmallChangeAndValue(t *testing.T) {
	fetch.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		body := "<html>" + strings.Repeat("sql injection form ", 100)
		if q.Get("Submit") != "" {
			body += strings.Repeat("User ID exists ", 4)
		}
		if q.Get("id") != "1" {
			body += " error"
			w.WriteHeader(http.StatusInternalServerError)
		}
		fmt.Fprint(w, body+"</html>")
	}))
	defer srv.Close()
	c := New(srv.Client(), Options{Words: []string{"security", "x"}, Rate: 10000})
	why := ownWhy(t, runOn(t, c, srv.URL+"/sqli/?id=1&Submit=Submit"))
	if why["Submit"] != "size" || why["id"] != "status" || len(why) != 2 {
		t.Errorf("found %v, want Submit by size and id by status", why)
	}
}

// A page that prints its query back changes in size with any name: the
// parameters of the URL it ignores are not found, and a real one is.
func TestParamInInputURLOnAnEchoingPage(t *testing.T) {
	fetch.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := "<html>you asked for " + r.URL.RawQuery + strings.Repeat(" pad", 50)
		if r.URL.Query().Has("mode") {
			body += strings.Repeat(" mode on", 40)
		}
		fmt.Fprint(w, body+"</html>")
	}))
	defer srv.Close()
	c := New(srv.Client(), Options{Words: []string{"x", "y"}, Rate: 10000})
	why := ownWhy(t, runOn(t, c, srv.URL+"/p?mode="+url.QueryEscape("fast")+"&ref=a-long-value-nothing-reads"))
	if why["mode"] != "size" || len(why) != 1 {
		t.Errorf("found %v, want mode alone", why)
	}
}

func TestEditQuery(t *testing.T) {
	v := "N"
	for _, c := range []struct {
		raw, name, to string
		val           *string
		want          string
	}{
		{"q=apple&x=1", "q", "~z", nil, "~z=apple&x=1"},
		{"q=apple&x=1&q=pear", "q", "~z", nil, "~z=apple&x=1&~z=pear"},
		{"q&x=1", "q", "~z", nil, "~z&x=1"},
		{"a%20b=1", "a b", "~z", nil, "~z=1"},
		{"q=apple&x=1", "x", "x", &v, "q=apple&x=N"},
	} {
		if got := editQuery(c.raw, c.name, c.to, c.val); got != c.want {
			t.Errorf("%s: %s, want %s", c.raw, got, c.want)
		}
	}
}
