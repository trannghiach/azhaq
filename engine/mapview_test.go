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
