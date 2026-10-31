package webextract

import (
	"strings"
	"testing"
)

// The names a request sends are read from the body wherever the script
// writes it: a variable, XMLHttpRequest's send, URLSearchParams, a FormData
// built with append, options kept in a variable.
func TestCallBodiesFromVariablesAndXHR(t *testing.T) {
	for _, c := range []struct {
		name, js, want string
	}{
		{"literal", `fetch("/api/u/" + id + "/level", {method: "PATCH", body: JSON.stringify({level: x})})`, "PATCH /api/u/{id}/level body level"},
		{"stringify with spacing args", `fetch("/api/u/" + id, {method: "PATCH", body: JSON.stringify({level: x, note}, null, 2)})`, "PATCH /api/u/{id} body level,note"},
		{"body variable", `const payload = {level: x, reason: r};
fetch("/api/u/" + id, {method: "PATCH", headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload)})`, "PATCH /api/u/{id} body level,reason"},
		{"options variable", `const opts = {method: "PATCH", body: JSON.stringify({level: x})};
fetch("/api/u/" + id, opts)`, "PATCH /api/u/{id} body level"},
		{"xhr send", `var xhr = new XMLHttpRequest(); xhr.open("PATCH", "/api/u/" + id); xhr.setRequestHeader("Content-Type", "application/json"); xhr.send(JSON.stringify({level: x}));`, "PATCH /api/u/{id} body level"},
		{"xhr send a variable", `const data = {level: x};
const req = new XMLHttpRequest(); req.open('PUT', '/api/u/' + id); req.send(JSON.stringify(data));`, "PUT /api/u/{id} body level"},
		{"URLSearchParams", `fetch("/api/u/" + id, {method: "POST", body: new URLSearchParams({level: x})})`, "POST /api/u/{id} body level"},
		{"FormData built by hand", `const fd = new FormData(); fd.append("level", x); fd.append('avatar', file);
fetch("/api/u/" + id, {method: "POST", body: fd})`, "POST /api/u/{id} body avatar,level"},
		{"axios variable", `const body = {level: x};
axios.patch("/api/u/" + id, body)`, "PATCH /api/u/{id} body level"},
		{"jquery data variable", `const data = {level: x};
$.ajax({url: "/api/u/" + id, type: "PATCH", data: JSON.stringify(data), contentType: "application/json"})`, "PATCH /api/u/{id} body level"},
		{"Object.assign", `fetch("/api/u/" + id, {method: "PATCH", body: JSON.stringify(Object.assign({}, base, {level: x}))})`, "PATCH /api/u/{id} body level"},
		{"a body known only at run time", `function save(u, data) { return fetch("/api/u/" + u, {method: "PATCH", body: JSON.stringify(data)}) }`, "PATCH /api/u/{id}"},
		{"a parameter's default is not what it holds", `function doRequest(url, opts = {method: "GET"}) { return fetch(url, opts) }
doRequest("/api/q", {method: "POST", body: JSON.stringify({a: 1})})`, "POST /api/q body a"},
	} {
		got := strings.Join(callLines(MergeCalls(Calls(c.js))), "|")
		if got != c.want {
			t.Errorf("%s:\n got  %q\n want %q", c.name, got, c.want)
		}
	}
}
