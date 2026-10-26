package webextract

import (
	"reflect"
	"strings"
	"testing"
)

// From OWASP Juice Shop's main.js (Angular, minified).
const juiceServices = "var F$={hostServer:\".\"};" +
	"class A{http=p$1(oD);hostServer=F$.hostServer;host=this.hostServer+`/api/Cards`;" +
	"get(){return this.http.get(this.host).pipe(X$1(t=>t.data))}" +
	"save(t){return this.http.post(this.host+`/`,t)}" +
	"del(e){return this.http.delete(`${this.host}/${e}`)}}" +
	"class B{hostServer=F$.hostServer;" +
	"search(t){return this.http.get(`${this.hostServer}/rest/products/search?q=${t}`)}" +
	"verify(t,e){return this.http.post(`${F$.hostServer}/rest/2fa/verify`,{tmpToken:t,totpToken:e})}" +
	"change(e){return this.http.get(this.hostServer+`/rest/user/change-password?current=`+e.current+`&new=`+e.new+`&repeat=`+e.repeat)}" +
	"whoami(t){return this.http.get(this.hostServer+`/rest/user/whoami`+t)}" +
	"deluxe(e,t){return this.http.post(this.hostServer+`/rest/deluxe-membership`,{paymentMode:e,paymentId:t})}" +
	"repeat(e){return this.http.get(this.hostServer+`/rest/repeat-notification`,{params:{challenge:e},responseType:`text`})}" +
	"lang(){return this.http.get(`${this.hostServer}/rest/languages`)}}" +
	"class C{hostServer=F$.hostServer;host=this.hostServer+`/rest/web3`;" +
	"submitKey(t){let r=this.host+`/submitKey`,n={privateKey:t};return this.http.post(r,n)}}" +
	"m.get(\"key\");cache.delete(e);"

func TestCalls(t *testing.T) {
	got := map[string]Call{}
	for _, c := range MergeCalls(Calls(juiceServices)) {
		got[c.Method+" "+c.Path] = c
	}
	want := map[string]Call{
		"GET /api/Cards":                 {Method: "GET", Path: "/api/Cards"},
		"POST /api/Cards/":               {Method: "POST", Path: "/api/Cards/"},
		"DELETE /api/Cards/{id}":         {Method: "DELETE", Path: "/api/Cards/{id}"},
		"GET /rest/products/search":      {Method: "GET", Path: "/rest/products/search", Query: []string{"q"}},
		"POST /rest/2fa/verify":          {Method: "POST", Path: "/rest/2fa/verify", Body: []string{"tmpToken", "totpToken"}},
		"GET /rest/user/change-password": {Method: "GET", Path: "/rest/user/change-password", Query: []string{"current", "new", "repeat"}},
		"GET /rest/user/whoami":          {Method: "GET", Path: "/rest/user/whoami"},
		"POST /rest/deluxe-membership":   {Method: "POST", Path: "/rest/deluxe-membership", Body: []string{"paymentId", "paymentMode"}},
		"GET /rest/repeat-notification":  {Method: "GET", Path: "/rest/repeat-notification", Query: []string{"challenge"}},
		"GET /rest/languages":            {Method: "GET", Path: "/rest/languages"},
		"POST /rest/web3/submitKey":      {Method: "POST", Path: "/rest/web3/submitKey", Body: []string{"privateKey"}},
	}
	for k, w := range want {
		g, ok := got[k]
		if !ok {
			t.Errorf("missing %s", k)
			continue
		}
		if !reflect.DeepEqual(g, w) {
			t.Errorf("%s: %+v, want %+v", k, g, w)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected %s", k)
		}
	}
}

func TestCallsFetchAndXHR(t *testing.T) {
	js := `const API_BASE="/api/v2";fetch(API_BASE+"/orders",{method:"POST",body:JSON.stringify({sku:s,qty:n})});` +
		`x.open("PUT","/api/profile/"+id);fetch("/health")`
	var lines []string
	for _, c := range MergeCalls(Calls(js)) {
		lines = append(lines, c.Method+" "+c.Path+" "+strings.Join(c.Body, ","))
	}
	want := []string{"PUT /api/profile/{id} ", "POST /api/v2/orders qty,sku", "GET /health "}
	if !reflect.DeepEqual(lines, want) {
		t.Fatalf("%q", lines)
	}
}
