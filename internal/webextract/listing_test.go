package webextract

import (
	"net/url"
	"testing"
)

func TestListingItem(t *testing.T) {
	for _, c := range []struct{ base, body, want string }{
		{"http://app/api/Challenges", `[{"id":1,"name":"a"},{"id":2}]`, "http://app/api/Challenges/1"},
		{"http://app/api/Challenges/?key=x", `{"status":"success","data":[{"id":7}]}`, "http://app/api/Challenges/7"},
		{"http://app/books/v1", `{"Books":[{"id":"b-12","title":"x"}]}`, "http://app/books/v1/b-12"},
		{"http://app/users/7", `{"orders":[{"id":5}]}`, ""},
		{"http://app/me", `{"id":3,"friends":[{"id":4}]}`, ""},
		{"http://app/api/tags", `["a","b"]`, ""},
		{"http://app/api/items", `[{"name":"no id"}]`, ""},
		{"http://app/api/items", `[{"id":"has space"},{"id":9}]`, "http://app/api/items/9"},
		{"http://app/api/items", `[{"id":1.5}]`, ""},
		{"http://app/feed.json", `[{"id":1}]`, ""},
		{"http://app/api/{id}/x", `[{"id":1}]`, ""},
		{"http://app/a", `{"x":[{"id":1}],"y":[{"id":2}]}`, ""},
	} {
		u, _ := url.Parse(c.base)
		if got := ListingItem([]byte(c.body), u); got != c.want {
			t.Errorf("%s %s: %q, want %q", c.base, c.body, got, c.want)
		}
	}
}
