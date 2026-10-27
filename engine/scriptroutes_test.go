package engine_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/types"
)

func jsObs(page, payload string) types.StoredObservation {
	return types.StoredObservation{EntityID: page, Observation: types.Observation{Collector: "azhaq-js", Kind: "url", Payload: json.RawMessage(payload)}}
}

// A route found only in a script, with no GET call to go by, is not gone
// because a GET answered 404: scripts may POST to it (ginandjuice.shop's
// /logger). A link that answers 404 is gone, and so is a route a script
// itself GETs.
func TestScriptRoutesAreNotGone(t *testing.T) {
	ents := []types.Entity{
		{ID: "root", Type: types.TypeURL, Key: "https://shop.test/"},
		{ID: "log", Type: types.TypeURL, Key: "https://shop.test/logger"},
		{ID: "str", Type: types.TypeURL, Key: "https://shop.test/track"},
		{ID: "get", Type: types.TypeURL, Key: "https://shop.test/api/old"},
		{ID: "lnk", Type: types.TypeURL, Key: "https://shop.test/moved"},
		{ID: "both", Type: types.TypeURL, Key: "https://shop.test/both"},
	}
	site := `{"script":"https://shop.test/resources/js/searchLogger.js","line":21,"col":15,"snippet":"logQuery('/logger', config.params)"}`
	obs := []types.StoredObservation{
		httpObs("root", `{"status":200,"url":"https://shop.test/"}`),
		jsObs("root", `{"url":"https://shop.test/logger","via":"js","role":"page","found_in":[{"script":"https://shop.test/resources/js/searchLogger.js","line":21,"col":23,"snippet":"'/logger'"}]}`),
		jsObs("root", `{"url":"https://shop.test/logger","via":"js-call","role":"api","methods":["POST"],"ops":[{"method":"POST"}],"found_in":[`+site+`]}`),
		jsObs("root", `{"url":"https://shop.test/track","via":"js","role":"page"}`),
		jsObs("root", `{"url":"https://shop.test/api/old","via":"js-call","role":"api","methods":["GET"],"ops":[{"method":"GET"}]}`),
		jsObs("root", `{"url":"https://shop.test/both","via":"js","role":"page"}`),
		crawlObs("root", "url", `{"url":"https://shop.test/moved","via":"html"}`),
		crawlObs("root", "url", `{"url":"https://shop.test/both","via":"html"}`),
	}
	for _, id := range []string{"log", "str", "get", "lnk", "both"} {
		var key string
		for _, e := range ents {
			if e.ID == id {
				key = e.Key
			}
		}
		obs = append(obs, httpObs(id, `{"status":404,"url":"`+key+`"}`))
	}
	seeds := []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": "https://shop.test/"}}}
	got := map[string]engine.MapEntry{}
	for _, m := range engine.BuildMap(ents, seeds, obs, nil, false) {
		got[strings.TrimPrefix(m.Entity.Key, "https://shop.test")] = m
	}
	for path, want := range map[string]string{"/logger": "hint", "/track": "hint", "/api/old": "gone", "/moved": "gone", "/both": "gone"} {
		if m := got[path]; m.Coverage != want {
			t.Errorf("%s: %s (%s), want %s", path, m.Coverage, m.Proof, want)
		}
	}
	if p := got["/logger"].Proof; p != "GET answers 404; called with POST" {
		t.Errorf("/logger proof %q", p)
	}
	if p := got["/track"].Proof; p != "GET answers 404; found only in scripts, method unknown" {
		t.Errorf("/track proof %q", p)
	}
	found := got["/logger"].Found
	if len(found) != 2 || found[0].Snippet != "logQuery('/logger', config.params)" || found[1].Snippet != "'/logger'" {
		t.Errorf("/logger found in %+v (the call first)", found)
	}
}

// A version prefix named in a script is a route only when something
// answers there.
func TestVersionPrefixesNeedAnAnswer(t *testing.T) {
	ents := []types.Entity{
		{ID: "root", Type: types.TypeURL, Key: "https://app.test/"},
		{ID: "v3", Type: types.TypeURL, Key: "https://app.test/v3"},
		{ID: "v2", Type: types.TypeURL, Key: "https://app.test/api/v2"},
		{ID: "v1", Type: types.TypeURL, Key: "https://app.test/v1"},
		{ID: "v4", Type: types.TypeURL, Key: "https://app.test/v4"},
	}
	obs := []types.StoredObservation{
		httpObs("root", `{"status":200,"url":"https://app.test/"}`),
		jsObs("root", `{"url":"https://app.test/v3","via":"js","role":"page"}`),
		jsObs("root", `{"url":"https://app.test/api/v2","via":"js","role":"api"}`),
		jsObs("root", `{"url":"https://app.test/v1","via":"js","role":"page"}`),
		crawlObs("root", "url", `{"url":"https://app.test/v4","via":"html"}`),
		httpObs("v3", `{"status":200,"catchall":true,"url":"https://app.test/v3"}`),
		httpObs("v2", `{"status":404,"url":"https://app.test/api/v2"}`),
		httpObs("v1", `{"status":200,"url":"https://app.test/v1","title":"API v1"}`),
		httpObs("v4", `{"status":404,"url":"https://app.test/v4"}`),
	}
	seeds := []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": "https://app.test/"}}}
	got := map[string]string{}
	for _, m := range engine.BuildMap(ents, seeds, obs, nil, false) {
		got[strings.TrimPrefix(m.Entity.Key, "https://app.test")] = m.Coverage
	}
	if _, ok := got["/v3"]; ok {
		t.Error("/v3, the SPA shell, is in the map")
	}
	if _, ok := got["/api/v2"]; ok {
		t.Error("/api/v2, a 404, is in the map")
	}
	if got["/v1"] != "visited" {
		t.Errorf("/v1 answered and is %q", got["/v1"])
	}
	if got["/v4"] != "gone" {
		t.Errorf("/v4, a link, is %q", got["/v4"])
	}
}

func TestBrowserHint(t *testing.T) {
	seeds := []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": "http://dvna.test/"}}}
	lesson := "http://dvna.test/learn/vulnerability/a1_injection"
	ents := []types.Entity{
		{ID: "root", Type: types.TypeURL, Key: "http://dvna.test/"},
		{ID: "l1", Type: types.TypeURL, Key: lesson},
		{ID: "x", Type: types.TypeURL, Key: "http://other.test/"},
	}
	base := []types.StoredObservation{
		httpObs("root", `{"status":200,"url":"http://dvna.test/"}`),
		httpObs("l1", `{"status":200,"url":"`+lesson+`"}`),
	}
	unrendered := func(id, u, what string) types.StoredObservation {
		return crawlObs(id, "meta", `{"url":"`+u+`","unrendered":`+what+`}`)
	}
	hint := func(obs []types.StoredObservation) string {
		return engine.BrowserHint(engine.BuildMap(ents, seeds, obs, nil, false), obs)
	}

	if h := hint(append(base, unrendered("l1", lesson, `{"markdown":12}`))); !strings.HasPrefix(h, "azhaq run -url http://dvna.test/ -browser") ||
		!strings.Contains(h, "/learn/vulnerability/a1_injection") || !strings.Contains(h, "Markdown") {
		t.Errorf("Markdown page: %q", h)
	}
	if h := hint(append(base, unrendered("root", "http://dvna.test/", `{"shell":true}`))); !strings.Contains(h, "an empty page its scripts draw") {
		t.Errorf("empty shell, thin map: %q", h)
	}
	if h := hint(append(base, unrendered("l1", lesson, `{"templates":2}`))); h != "" {
		t.Errorf("two template expressions: %q", h)
	}
	if h := hint(base); h != "" {
		t.Errorf("a server-built site: %q", h)
	}
	if h := hint(append(base, unrendered("x", "http://other.test/", `{"markdown":3}`))); h != "" {
		t.Errorf("a fan-out page: %q", h)
	}
	withChrome := append(base, unrendered("l1", lesson, `{"markdown":12}`),
		types.StoredObservation{EntityID: "root", Observation: types.Observation{Collector: "azhaq-render", Kind: "url", Payload: json.RawMessage(`{"url":"http://dvna.test/app","via":"browser"}`)}})
	if h := hint(withChrome); h != "" {
		t.Errorf("a run with -browser: %q", h)
	}

	// An app whose scripts gave up their routes: the shell is no reason.
	for i := 0; i < 12; i++ {
		k := "http://dvna.test/api/r" + string(rune('a'+i))
		ents = append(ents, types.Entity{ID: k, Type: types.TypeURL, Key: k})
	}
	if h := hint(append(base, unrendered("root", "http://dvna.test/", `{"shell":true}`))); h != "" {
		t.Errorf("empty shell, rich map: %q", h)
	}
}
