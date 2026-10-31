package engine_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/types"
)

func httpObs(id, payload string) types.StoredObservation {
	return types.StoredObservation{EntityID: id, Observation: types.Observation{Collector: "azhaq-http", Kind: "application", Payload: json.RawMessage(payload)}}
}

func crawlObs(id, kind, payload string) types.StoredObservation {
	return types.StoredObservation{EntityID: id, Observation: types.Observation{Collector: "azhaq-crawl", Kind: kind, Payload: json.RawMessage(payload)}}
}

func TestMapCatchAllAndForbidden(t *testing.T) {
	ents := []types.Entity{
		{ID: "r", Type: types.TypeURL, Key: "https://shop.test/"},
		{ID: "a", Type: types.TypeURL, Key: "https://shop.test/admin"},
		{ID: "g", Type: types.TypeURL, Key: "https://shop.test/.git/HEAD"},
		{ID: "u", Type: types.TypeURL, Key: "https://shop.test/api/Users"},
	}
	obs := []types.StoredObservation{
		httpObs("r", `{"status":200,"url":"https://shop.test/"}`),
		httpObs("a", `{"status":403,"url":"https://shop.test/admin"}`),
		httpObs("g", `{"status":200,"catchall":true,"url":"https://shop.test/.git/HEAD"}`),
		httpObs("u", `{"status":401,"url":"https://shop.test/api/Users"}`),
	}
	seeds := []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": "https://shop.test/"}}}
	got := map[string]engine.MapEntry{}
	for _, m := range engine.BuildMap(ents, seeds, obs, nil, false) {
		got[m.Entity.Key] = m
	}
	if m := got["https://shop.test/.git/HEAD"]; m.Coverage != "catchall" {
		t.Errorf(".git/HEAD %+v", m)
	}
	if m := got["https://shop.test/admin"]; m.Role != "forbidden" || m.Coverage != "visited" {
		t.Errorf("403 %+v", m)
	}
	if m := got["https://shop.test/api/Users"]; m.Role != "auth" {
		t.Errorf("401 %+v", m)
	}
}

func TestMapTemplatesAndForms(t *testing.T) {
	var ents []types.Entity
	var obs []types.StoredObservation
	stock := `{"method":"POST","action":"https://shop.test/catalog/product/stock","fields":["productId","storeId"]}`
	news := `{"method":"POST","action":"https://shop.test/catalog/subscribe","fields":["email","csrf"]}`
	ents = append(ents, types.Entity{ID: "root", Type: types.TypeURL, Key: "https://shop.test/"})
	obs = append(obs, httpObs("root", `{"status":200,"url":"https://shop.test/"}`), crawlObs("root", "form", news))
	for _, id := range []string{"1", "2", "3"} {
		key := "https://shop.test/catalog/product?productId=" + id
		ents = append(ents, types.Entity{ID: id, Type: types.TypeURL, Key: key})
		obs = append(obs, httpObs(id, `{"status":200,"url":"`+key+`"}`), crawlObs(id, "form", stock), crawlObs(id, "form", news))
	}
	ents = append(ents, types.Entity{ID: "op", Type: types.TypeURL, Key: "https://shop.test/users/v1/{username}"})
	obs = append(obs, types.StoredObservation{EntityID: "spec", Observation: types.Observation{
		Collector: "azhaq-openapi", Kind: "url",
		Payload: json.RawMessage(`{"url":"https://shop.test/users/v1/{username}","methods":["GET","DELETE"],"params":["username"]}`),
	}})
	seeds := []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": "https://shop.test/"}}}

	rows := engine.GroupTemplates(engine.BuildMap(ents, seeds, obs, nil, false))
	var out []string
	for _, r := range rows {
		out = append(out, r.Line())
		for _, d := range r.Details() {
			out = append(out, "    "+d)
		}
	}
	text := strings.Join(out, "\n")
	if n := strings.Count(text, "catalog/product?productId="); n != 1 || !strings.Contains(text, "productId={n}") || !strings.Contains(text, "(3 urls)") {
		t.Errorf("product pages not one template row:\n%s", text)
	}
	if n := strings.Count(text, "form POST /catalog/subscribe"); n != 1 {
		t.Errorf("footer form printed %d times:\n%s", n, text)
	}
	if !strings.Contains(text, "form POST /catalog/product/stock  productId storeId") {
		t.Errorf("stock form missing:\n%s", text)
	}
	if !strings.Contains(text, "/users/v1/{username}  target  hint  api  GET,DELETE") || !strings.Contains(text, "params username") {
		t.Errorf("API operation row:\n%s", text)
	}
}

// A row's body is every operation's body fields: an API description puts
// them on its operations only, a script's call on both.
func TestMapBodyFromEveryOperation(t *testing.T) {
	key := "https://shop.test/b2b/v2/orders"
	ents := []types.Entity{{ID: "o", Type: types.TypeURL, Key: key}}
	obs := []types.StoredObservation{
		{EntityID: "spec", Observation: types.Observation{Collector: "azhaq-openapi", Kind: "url", Payload: json.RawMessage(
			`{"url":"` + key + `","via":"openapi","methods":["POST"],"params":["cid","orderLines","orderLinesData"],
			  "ops":[{"method":"POST","body":["cid","orderLines","orderLinesData"],"body_type":"application/json"}]}`)}},
		{EntityID: "main.js", Observation: types.Observation{Collector: "azhaq-js", Kind: "url", Payload: json.RawMessage(
			`{"url":"` + key + `","via":"js-call","methods":["POST"],"body":["cid","coupon"],"ops":[{"method":"POST","body":["cid","coupon"]}]}`)}},
	}
	seeds := []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": "https://shop.test/"}}}
	rows := engine.BuildMap(ents, seeds, obs, nil, false)
	if len(rows) != 1 {
		t.Fatalf("rows %+v", rows)
	}
	if got := strings.Join(rows[0].Body, ","); got != "cid,coupon,orderLines,orderLinesData" {
		t.Errorf("body %q, ops %+v", got, rows[0].Ops)
	}
}

// The same write sent from every page Chrome renders is one operation;
// another method, or other names, another.
func TestMapOpsOnce(t *testing.T) {
	key := "https://shop.test/api/track"
	ents := []types.Entity{{ID: "t", Type: types.TypeURL, Key: key}}
	write := func(page, body string) types.StoredObservation {
		return types.StoredObservation{EntityID: page, Observation: types.Observation{Collector: "azhaq-render", Kind: "url", Payload: json.RawMessage(
			`{"url":"` + key + `","via":"browser","methods":["POST"],"ops":[{"method":"POST","body":` + body + `,"source":"browser"}]}`)}}
	}
	obs := []types.StoredObservation{write("a", `["event"]`), write("b", `["event"]`), write("c", `["event","user"]`)}
	rows := engine.BuildMap(ents, []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": "https://shop.test/"}}}, obs, nil, false)
	if len(rows) != 1 || len(rows[0].Ops) != 2 || rows[0].Coverage != "hint" {
		t.Errorf("rows %+v", rows)
	}
}

// A template row says how many of its URLs were found and not asked.
func TestGroupTemplatesCountsTheUrlsNotAsked(t *testing.T) {
	ents := []types.Entity{{ID: "root", Type: types.TypeURL, Key: "https://shop.test/"}}
	obs := []types.StoredObservation{httpObs("root", `{"status":200,"url":"https://shop.test/"}`)}
	for _, id := range []string{"1", "2", "3", "4", "5"} {
		key := "https://shop.test/item?id=" + id
		ents = append(ents, types.Entity{ID: id, Type: types.TypeURL, Key: key})
		if id <= "2" {
			obs = append(obs, httpObs(id, `{"status":200,"url":"`+key+`"}`))
		}
	}
	seeds := []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": "https://shop.test/"}}}
	var row engine.MapEntry
	for _, r := range engine.GroupTemplates(engine.BuildMap(ents, seeds, obs, nil, false)) {
		if r.Template != "" {
			row = r
		}
	}
	if row.Count != 5 || row.NotAsked != 3 || !strings.Contains(row.Line(), "(5 urls, 3 not asked)") {
		t.Errorf("%d urls, %d not asked: %s", row.Count, row.NotAsked, row.Line())
	}
}
