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

func TestPageCallsKeepRelativePaths(t *testing.T) {
	got := PageCalls(`function check(h){ xmlHttp.open("GET","util/serverStatusCheckService.jsp?HostName=" + h); $.get("data") }`)
	if len(got) != 1 || got[0].Path != "util/serverStatusCheckService.jsp" || len(got[0].Query) != 1 || got[0].Query[0] != "HostName" {
		t.Fatalf("PageCalls = %+v", got)
	}
	if c := Calls(`xmlHttp.open("GET","util/status.jsp")`); len(c) != 0 {
		t.Fatalf("Calls kept a relative path from a script file: %+v", c)
	}
}

// Shaped like ginandjuice.shop's /resources/js/searchLogger.js: the path
// is named where the helper is called, the method inside the helper.
const searchLogger = `async function logQuery(url, params) {
    try {
        // don't hold up the page
        await fetch(url, {method: "post", keepalive: true, body: JSON.stringify(params)});
    } catch(e) {
        console.error("Failed storing query");
    }
}

async function searchLogger() {
    let config = {params: deparam(new URL(location).searchParams.toString())};

    if(config.transport_url) {
        let script = document.createElement('script');
        script.src = config.transport_url;
        document.body.appendChild(script);
    }

    if(config.params && config.params.search) {
        await logQuery('/logger', config.params);
    }
}

window.addEventListener("load", searchLogger);`

func TestCallsThroughAWrapper(t *testing.T) {
	got := Calls(searchLogger)
	if len(got) != 1 || got[0].Method != "POST" || got[0].Path != "/logger" {
		t.Fatalf("Calls = %+v", got)
	}
	if at := searchLogger[got[0].At:got[0].End]; at != "logQuery('/logger', config.params)" {
		t.Errorf("call site %q", at)
	}
}

func TestCallsThroughWrapperShapes(t *testing.T) {
	js := `const API = "/api/v2";
	function apiPost(path, data) { return fetch(API + path, {method: "POST", body: JSON.stringify(data)}) }
	const send = async (url, opts) => { const r = await fetch(url, opts); return r.json() };
	function remove(id, u) { $.ajax({url: u, type: "DELETE"}) }
	class Store { load(url, method) { return axios({url, method}) } }
	function track(e) { return fetch(e) }
	function hop(u) { return apiPost(u, {}) }
	apiPost("/orders", {sku: s, qty: n});
	send("/api/session", {method: "PUT", body: JSON.stringify({token: t})});
	send("/api/profile");
	send("/api/opaque", options);
	remove(7, "/api/items/" + id);
	this.store.load("/api/reports", "PATCH");
	track("/tracked");
	hop("/two/levels");
	notAWrapper("/plain/call");`
	var lines []string
	for _, c := range MergeCalls(Calls(js)) {
		lines = append(lines, c.Method+" "+c.Path+" "+strings.Join(c.Body, ","))
	}
	want := []string{
		"DELETE /api/items/{id} ",
		" /api/opaque ", // the options are a variable: the method is not known
		"GET /api/profile ",
		"PATCH /api/reports ",
		"PUT /api/session token",
		"POST /api/v2/orders qty,sku", // and not POST /api/v2, the helper alone
		"GET /tracked ",
	}
	if !reflect.DeepEqual(lines, want) {
		t.Fatalf("got  %q\nwant %q", lines, want)
	}
}

func TestCallsAjaxAndAxios(t *testing.T) {
	js := `$.ajax({url: "/api/login", type: "POST", data: {user: u, pass: p}});
	jQuery.ajax("/api/feed", {dataType: "json"});
	axios({method: "put", url: "/api/me", data: {name: n}});
	axios.request({url: "/api/search", params: {q: q}});
	$("#x").ajaxComplete(f);`
	var lines []string
	for _, c := range MergeCalls(Calls(js)) {
		lines = append(lines, c.Method+" "+c.Path+" "+strings.Join(c.Body, ",")+" "+strings.Join(c.Query, ","))
	}
	want := []string{"GET /api/feed  ", "POST /api/login pass,user ", "PUT /api/me name ", "GET /api/search  q"}
	if !reflect.DeepEqual(lines, want) {
		t.Fatalf("got  %q\nwant %q", lines, want)
	}
}

func TestCallsWrapperNamesAreTrusted(t *testing.T) {
	// A short name declared twice is a minifier's: two modules, two
	// functions, and the call cannot be told apart.
	twice := `function abc(e){return fetch(e,{method:"POST"})}function abc(e){return e}abc("/x/y");`
	if got := Calls(twice); len(got) != 0 {
		t.Errorf("ambiguous short name followed: %+v", got)
	}
	once := `function abc(e){return fetch(e,{method:"POST"})}abc("/x/y");`
	if got := Calls(once); len(got) != 1 || got[0].Method != "POST" || got[0].Path != "/x/y" {
		t.Errorf("short name declared once: %+v", got)
	}
	// A request whose URL is not the helper's parameter makes no helper.
	if got := Calls(`function go(a){var url=a.b;fetch(url,{method:"POST"})}go("/x/y")`); len(got) != 0 {
		t.Errorf("non-parameter URL followed: %+v", got)
	}
}

func TestPageCallsLeaveClientsWithABase(t *testing.T) {
	got := PageCalls(`api.get("users/list"); fetch("httpStatus/check.jsp")`)
	if len(got) != 1 || got[0].Path != "httpStatus/check.jsp" {
		t.Fatalf("PageCalls = %+v", got)
	}
}
