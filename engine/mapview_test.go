package engine_test

import (
	"encoding/json"
	"slices"
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

// A scan a limit stopped is followed by the one that finishes it: the map
// shows the open ports of the newest row, and not the range's summary row,
// which lists none.
func TestMapShowsTheNewestScansOpenPorts(t *testing.T) {
	ents := []types.Entity{{ID: "p", Type: types.TypePrefix, Key: "127.0.0.1/32"}}
	row := func(payload string) types.StoredObservation {
		return types.StoredObservation{EntityID: "p", Observation: types.Observation{Collector: "azhaq-ports", Kind: "ports", Payload: json.RawMessage(payload)}}
	}
	obs := []types.StoredObservation{
		row(`{"ip":"127.0.0.1","open":[22],"partial":true,"asked_ports":"22,80"}`),
		row(`{"ip":"127.0.0.1","open":[22,443],"partial":true,"asked_ports":"22,80,443,8080"}`),
		row(`{"ip":"127.0.0.1","open":[22,443,9000]}`),
		row(`{"range":true,"prefix":"127.0.0.1/32","open":[]}`),
	}
	got := engine.BuildMap(ents, nil, obs, nil, false)
	if len(got) != 1 || !strings.Contains(got[0].Proof, "open=[22 443 9000]") {
		t.Errorf("proof %q", got[0].Proof)
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

// Pages of one route that differ in which ID-like names they carry are
// one template row, with every name in its params; a word that names a
// page stays a row of its own.
func TestGroupTemplatesFoldsShapesOfOneRoute(t *testing.T) {
	ents := []types.Entity{{ID: "root", Type: types.TypeURL, Key: "https://shop.test/"}}
	obs := []types.StoredObservation{httpObs("root", `{"status":200,"url":"https://shop.test/"}`)}
	for i, key := range []string{
		"https://shop.test/catalog/product?productId=1",
		"https://shop.test/catalog/product?productId=2",
		"https://shop.test/catalog/product?productId=3&storeId=1",
		"https://shop.test/catalog/product?productId=4&storeId=2",
		"https://shop.test/catalog?category=Gin",
		"https://shop.test/catalog?category=Juice",
		"https://shop.test/catalog?category=Gin&page=2",
	} {
		id := string(rune('a' + i))
		ents = append(ents, types.Entity{ID: id, Type: types.TypeURL, Key: key})
		obs = append(obs, httpObs(id, `{"status":200,"url":"`+key+`"}`))
	}
	seeds := []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": "https://shop.test/"}}}
	var product *engine.MapEntry
	var lines []string
	rows := engine.GroupTemplates(engine.BuildMap(ents, seeds, obs, nil, false))
	for i, r := range rows {
		lines = append(lines, r.Line())
		if strings.Contains(r.Entity.Key, "/catalog/product") {
			product = &rows[i]
		}
	}
	text := strings.Join(lines, "\n")
	if n := strings.Count(text, "/catalog/product?productId="); n != 1 || product == nil || product.Count != 4 ||
		!slices.Contains(product.Params, "productId") || !slices.Contains(product.Params, "storeId") {
		t.Errorf("product pages are not one row of 4 urls with both names:\n%s", text)
	}
	if n := strings.Count(text, "/catalog?category="); n != 3 {
		t.Errorf("a category is a page of its own: %d rows\n%s", n, text)
	}
}

// A tool that writes one row per port (naabu) leaves one open port in each
// row; the address lists them all, and with an azhaq scan beside them the
// union of that scan's ports and the imported ones, naming both.
func TestMapJoinsThePortsOfImportedRows(t *testing.T) {
	ents := []types.Entity{{ID: "a", Type: types.TypeIPAddress, Key: "127.0.0.1"}}
	naabu := func(port string) types.StoredObservation {
		return types.StoredObservation{EntityID: "a", Observation: types.Observation{Collector: "naabu", Kind: "ports", Payload: json.RawMessage(
			`{"host":"127.0.0.1","ip":"127.0.0.1","open":["` + port + `"],"via":"naabu"}`)}}
	}
	own := func(payload string) types.StoredObservation {
		return types.StoredObservation{EntityID: "a", Observation: types.Observation{Collector: "azhaq-ports", Kind: "ports", Payload: json.RawMessage(payload)}}
	}
	got := engine.BuildMap(ents, nil, []types.StoredObservation{naabu("5002"), naabu("3001")}, nil, false)
	if len(got) != 1 || got[0].Proof != "open=[3001 5002] via=naabu" {
		t.Errorf("imported rows: %+v", got)
	}
	got = engine.BuildMap(ents, nil, []types.StoredObservation{
		own(`{"ip":"127.0.0.1","open":[22],"partial":true}`),
		own(`{"ip":"127.0.0.1","open":[22,443]}`),
		naabu("3001"), naabu("443"),
	}, nil, false)
	if len(got) != 1 || got[0].Proof != "open=[22 443 3001] via=azhaq,naabu" {
		t.Errorf("both: %+v", got)
	}
}
