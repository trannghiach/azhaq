package engine_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/types"
)

func urlObs(collector, payload string) types.StoredObservation {
	return types.StoredObservation{EntityID: "page", Observation: types.Observation{Collector: collector, Kind: "url", Payload: json.RawMessage(payload)}}
}

func evidenceRows(t *testing.T, keys []string, obs []types.StoredObservation) map[string]engine.MapEntry {
	t.Helper()
	var ents []types.Entity
	for i, k := range keys {
		ents = append(ents, types.Entity{ID: string(rune('a' + i)), Type: types.TypeURL, Key: k})
	}
	seeds := []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": "https://shop.test/"}}}
	got := map[string]engine.MapEntry{}
	for _, m := range engine.BuildMap(ents, seeds, obs, nil, false) {
		got[m.Entity.Key] = m
	}
	return got
}

func TestEvidenceLevelOrder(t *testing.T) {
	want := []string{"answered", "browser", "described", "called", "linked", "archived", "guessed", "given"}
	if !slices.Equal(engine.EvidenceLevels, want) {
		t.Fatalf("levels %v", engine.EvidenceLevels)
	}
	for i := 1; i < len(want); i++ {
		if engine.EvidenceRank(want[i-1]) >= engine.EvidenceRank(want[i]) {
			t.Errorf("%s does not rank above %s", want[i-1], want[i])
		}
	}
	if engine.EvidenceRank("") <= engine.EvidenceRank("given") {
		t.Error("no level ranks below given")
	}
}

// Each row has the strongest level any of its sources reaches.
func TestEvidenceStrongestSource(t *testing.T) {
	const h = "https://shop.test"
	keys := []string{h + "/answered", h + "/described", h + "/called", h + "/linked", h + "/archived", h + "/guessed", h + "/gone", h + "/script-string"}
	obs := []types.StoredObservation{
		httpObs("a", `{"status":200,"url":"`+h+`/answered"}`),
		urlObs("azhaq-js", `{"url":"`+h+`/answered","via":"js-call","role":"api"}`),
		urlObs("azhaq-openapi", `{"url":"`+h+`/described","via":"openapi","methods":["GET"]}`),
		urlObs("azhaq-crawl", `{"url":"`+h+`/described","via":"html"}`),
		urlObs("azhaq-js", `{"url":"`+h+`/called","via":"js-call","methods":["POST"]}`),
		urlObs("azhaq-urls", `{"url":"`+h+`/called","via":"archive"}`),
		urlObs("azhaq-crawl", `{"url":"`+h+`/linked","via":"html"}`),
		urlObs("azhaq-urls", `{"url":"`+h+`/linked","via":"archive"}`),
		urlObs("azhaq-urls", `{"url":"`+h+`/archived","via":"archive"}`),
		urlObs("azhaq-dirs", `{"url":"`+h+`/guessed","via":"dirs","status":404}`),
		// The server says it is not there: a script naming it is all there is.
		httpObs("g", `{"status":404,"url":"`+h+`/gone"}`),
		urlObs("azhaq-js", `{"url":"`+h+`/gone","via":"js"}`),
		urlObs("azhaq-js", `{"url":"`+h+`/script-string","via":"js"}`),
	}
	got := evidenceRows(t, keys, obs)
	for k, want := range map[string]string{
		"answered": "answered", "described": "described", "called": "called", "linked": "linked",
		"archived": "archived", "guessed": "guessed", "gone": "linked", "script-string": "linked",
	} {
		if m := got[h+"/"+k]; m.Evidence != want {
			t.Errorf("%s: evidence %q, want %q (from %v)", k, m.Evidence, want, m.EvidenceFrom)
		}
	}
	if m := got[h+"/answered"]; !slices.Equal(m.EvidenceFrom, []string{"azhaq-http", "azhaq-js"}) {
		t.Errorf("answered from %v", m.EvidenceFrom)
	}
	if m := got[h+"/called"]; !slices.Equal(m.EvidenceFrom, []string{"azhaq-js", "azhaq-urls"}) {
		t.Errorf("called from %v", m.EvidenceFrom)
	}
}

// A wordlist hit that answered is answered; a form's action is linked.
func TestEvidenceWordlistAndForm(t *testing.T) {
	const h = "https://shop.test"
	obs := []types.StoredObservation{
		urlObs("azhaq-dirs", `{"url":"`+h+`/admin","via":"dirs","status":403}`),
		{EntityID: "page", Observation: types.Observation{Collector: "azhaq-crawl", Kind: "form", Payload: json.RawMessage(`{"method":"GET","action":"` + h + `/search","fields":["q"]}`)}},
	}
	got := evidenceRows(t, []string{h + "/admin", h + "/search"}, obs)
	if got[h+"/admin"].Evidence != "answered" || got[h+"/search"].Evidence != "linked" {
		t.Errorf("admin %q, search %q", got[h+"/admin"].Evidence, got[h+"/search"].Evidence)
	}
}

// Rows of one template fold into the strongest level of its instances.
func TestEvidenceTemplateTakesStrongest(t *testing.T) {
	const h = "https://shop.test"
	keys := []string{h + "/p?id=1", h + "/p?id=2", h + "/p?id=3"}
	build := func(third string) engine.MapEntry {
		obs := []types.StoredObservation{
			urlObs("azhaq-urls", `{"url":"`+h+`/p?id=1","via":"archive"}`),
			urlObs("azhaq-crawl", `{"url":"`+h+`/p?id=2","via":"html"}`),
			urlObs("azhaq-js", `{"url":"`+h+`/p?id=3","via":"js-call"}`),
		}
		if third != "" {
			obs = append(obs, httpObs("c", `{"status":200,"url":"`+h+`/p?id=3"}`))
		}
		rows := engine.GroupURLTemplates(listRows(t, keys, obs))
		for _, r := range rows {
			if r.Count == 3 {
				return r
			}
		}
		t.Fatalf("no folded row in %v", rows)
		return engine.MapEntry{}
	}
	if g := build(""); g.Evidence != "called" || !slices.Equal(g.EvidenceFrom, []string{"azhaq-crawl", "azhaq-js", "azhaq-urls"}) {
		t.Errorf("folded row: %q from %v", g.Evidence, g.EvidenceFrom)
	}
	if g := build("fetched"); g.Evidence != "answered" {
		t.Errorf("one instance answered: %q", g.Evidence)
	}
}

// A folded row takes the strongest level even when the best-ranked
// instance is the weakest.
func TestEvidenceTemplateOrderDoesNotMatter(t *testing.T) {
	a := engine.MapEntry{Template: "/p?id={n}", Evidence: "archived", EvidenceFrom: []string{"azhaq-urls"}}
	b := engine.MapEntry{Template: "/p?id={n}", Evidence: "described", EvidenceFrom: []string{"azhaq-openapi"}}
	for _, rows := range [][]engine.MapEntry{{a, b}, {b, a}} {
		for i := range rows {
			rows[i].Entity.Type = types.TypeURL
		}
		got := engine.GroupURLTemplates(rows)
		if len(got) != 1 || got[0].Evidence != "described" || !slices.Equal(got[0].EvidenceFrom, []string{"azhaq-openapi", "azhaq-urls"}) {
			t.Errorf("%+v", got)
		}
	}
}

func listRows(t *testing.T, keys []string, obs []types.StoredObservation) []engine.MapEntry {
	t.Helper()
	var ents []types.Entity
	for i, k := range keys {
		ents = append(ents, types.Entity{ID: string(rune('a' + i)), Type: types.TypeURL, Key: k})
	}
	seeds := []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": "https://shop.test/"}}}
	return engine.BuildMap(ents, seeds, obs, nil, false)
}

func TestEvidenceTagOnTextRows(t *testing.T) {
	const h = "https://shop.test"
	obs := []types.StoredObservation{
		httpObs("a", `{"status":200,"url":"`+h+`/ok"}`),
		urlObs("azhaq-urls", `{"url":"`+h+`/old","via":"archive"}`),
	}
	got := evidenceRows(t, []string{h + "/ok", h + "/old"}, obs)
	if l := got[h+"/ok"].Line(); strings.Contains(l, "[") {
		t.Errorf("an answered row has no tag: %s", l)
	}
	if l := got[h+"/old"].Line(); !strings.HasSuffix(l, "[archived]") {
		t.Errorf("archived row: %s", l)
	}
}

// Chrome's own request is its own level, apart from a script's call.
func TestEvidenceBrowserIsApartFromCalled(t *testing.T) {
	const h = "https://shop.test"
	obs := []types.StoredObservation{
		urlObs("azhaq-render", `{"url":"`+h+`/seen","via":"browser","seen":"request","role":"api"}`),
		urlObs("azhaq-render", `{"url":"`+h+`/sent","via":"browser","seen":"write","role":"api","methods":["POST"]}`),
		urlObs("azhaq-render", `{"url":"`+h+`/anchor","via":"browser","seen":"link","role":"page"}`),
		urlObs("azhaq-js", `{"url":"`+h+`/script","via":"js-call","role":"api","methods":["GET"]}`),
		urlObs("azhaq-render", `{"url":"`+h+`/both","via":"browser","seen":"request","role":"api"}`),
		urlObs("azhaq-js", `{"url":"`+h+`/both","via":"js-call","role":"api","methods":["GET"]}`),
	}
	got := evidenceRows(t, []string{h + "/seen", h + "/sent", h + "/anchor", h + "/script", h + "/both"}, obs)
	for k, want := range map[string]string{"seen": "browser", "sent": "browser", "anchor": "linked", "script": "called", "both": "browser"} {
		if m := got[h+"/"+k]; m.Evidence != want {
			t.Errorf("%s: evidence %q, want %q", k, m.Evidence, want)
		}
	}
	if l := got[h+"/seen"].Line(); !strings.HasSuffix(l, "[browser]") {
		t.Errorf("text row %q", l)
	}
}

// A 5xx the plain request got from a route that takes names says so; one
// that carried the names, or from a route that takes none, does not.
func TestAnswerWithoutInput(t *testing.T) {
	const h = "https://shop.test"
	call := func(path, query string) types.StoredObservation {
		return urlObs("azhaq-js", `{"url":"`+h+path+`","via":"js-call","role":"api","methods":["GET"],"params":["`+query+`"],"ops":[{"method":"GET","query":["`+query+`"],"source":"js-call"}]}`)
	}
	obs := []types.StoredObservation{
		call("/needs-email", "email"),
		httpObs("a", `{"status":500,"url":"`+h+`/needs-email"}`),
		call("/takes-q", "q"),
		httpObs("b", `{"status":500,"url":"`+h+`/takes-q?q=x"}`),
		httpObs("c", `{"status":500,"url":"`+h+`/takes-nothing"}`),
		call("/fine", "id"),
		httpObs("d", `{"status":200,"url":"`+h+`/fine"}`),
	}
	got := evidenceRows(t, []string{h + "/needs-email", h + "/takes-q?q=x", h + "/takes-nothing", h + "/fine"}, obs)
	for k, want := range map[string]string{"/needs-email": "500 without input", "/takes-q?q=x": "", "/takes-nothing": "", "/fine": ""} {
		if m := got[h+k]; m.Answer != want {
			t.Errorf("%s: answer %q, want %q", k, m.Answer, want)
		}
	}
	if l := got[h+"/needs-email"].Line(); !strings.Contains(l, "500 without input") {
		t.Errorf("text row %q", l)
	}
}

// A URL the user named that nothing answered or names is known by their
// word alone; one nobody named has no level to claim.
func TestEvidenceGivenSeed(t *testing.T) {
	obs := []types.StoredObservation{
		{EntityID: "a", Observation: types.Observation{Collector: "azhaq-http", Kind: "error", Payload: json.RawMessage(`{"url":"https://shop.test/","error":"connection refused"}`)}},
	}
	got := evidenceRows(t, []string{"https://shop.test/", "https://shop.test/other"}, obs)
	if m := got["https://shop.test/"]; m.Evidence != "given" || m.Coverage != "error" || !strings.HasSuffix(m.Line(), "[given]") {
		t.Errorf("the seed: %q %q %q", m.Evidence, m.Coverage, m.Line())
	}
	if m := got["https://shop.test/other"]; m.Evidence != "" {
		t.Errorf("a URL nobody named: %q", m.Evidence)
	}
}
