package webextract

import (
	"reflect"
	"testing"
)

func TestChunkURLs(t *testing.T) {
	cases := []struct {
		name, script string
		want         []string
	}{
		{"webpack 5, hash table",
			`n.p="/app/",n.u=e=>"static/js/"+e+"."+{12:"a1b2",45:"c3d4"}[e]+".chunk.js",n.miniCssF=e=>{}`,
			[]string{"/app/static/js/12.a1b2.chunk.js", "/app/static/js/45.c3d4.chunk.js"}},
		{"webpack 5, one hash (crAPI)",
			`n.u=e=>"static/js/"+e+".7db48f2d.chunk.js",n.miniCssF=e=>{};n.p="/";Promise.all([n.e(742),n.e(31)]).then(n.bind(n,742))`,
			[]string{"/static/js/31.7db48f2d.chunk.js", "/static/js/742.7db48f2d.chunk.js"}},
		{"webpack 5, named chunks",
			`r.u=function(e){return"js/"+({7:"admin",9:"vendors"}[e]||e)+"."+{7:"aa",9:"bb",11:"cc"}[e]+".js"}`,
			[]string{"/js/admin.aa.js", "/js/vendors.bb.js", "/js/11.cc.js"}},
		{"webpack 4",
			`function c(e){return a.p+"static/js/"+({}[e]||e)+"."+{0:"9f8e",1:"7d6c"}[e]+".chunk.js"}a.p="/static-root/"`,
			[]string{"/static-root/static/js/0.9f8e.chunk.js", "/static-root/static/js/1.7d6c.chunk.js"}},
		{"no loader", `fetch("/api/x")`, nil},
	}
	for _, c := range cases {
		if got := ChunkURLs(c.script); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %q\nwant %q", c.name, got, c.want)
		}
	}
}
