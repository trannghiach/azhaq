package webextract

import "testing"

func socketMap(ss []Socket) map[string]Socket {
	out := map[string]Socket{}
	for _, s := range ss {
		out[s.URL] = s
	}
	return out
}

func TestWebSockets(t *testing.T) {
	js := `var a=new WebSocket("wss://"+location.host+"/ws/notifications");` +
		`var b=new WebSocket(("https:"===location.protocol?"wss:":"ws:")+"//"+location.host+"/live/feed");` +
		`const STREAM="ws://stream.example.com:8080/v1/ticks";var c=new WebSocket(STREAM);` +
		`var d=new SockJS("/stomp");` +
		`var cfg={rt:"wss://rt.example.com/socket"};`
	got := socketMap(WebSockets(js))
	if s, ok := got["/ws/notifications"]; !ok || s.Scheme != "wss" || s.SocketIO {
		t.Errorf("notifications %+v", s)
	}
	if s, ok := got["/live/feed"]; !ok || s.Scheme != "" {
		t.Errorf("either scheme %+v", s)
	}
	if _, ok := got["ws://stream.example.com:8080/v1/ticks"]; !ok {
		t.Errorf("constant: %+v", got)
	}
	if _, ok := got["/stomp"]; !ok {
		t.Errorf("SockJS: %+v", got)
	}
	if _, ok := got["wss://rt.example.com/socket"]; !ok {
		t.Errorf("literal: %+v", got)
	}
	if len(got) != 5 {
		t.Errorf("got %+v", got)
	}
}

// socket.io: the app's call with a namespace and a path; in a chunk
// without the library, only with socket.io's options. The library's
// default path stands when the app's call is not readable (Juice Shop
// calls it by a minified name).
func TestSocketIO(t *testing.T) {
	app := `var io2=io("/chat",{path:"/realtime/socket.io"});var x=io("click");var y=io(e,{timeout:5e3});`
	got := WebSockets(app)
	if len(got) != 1 || got[0].URL != "/realtime/socket.io" || got[0].Namespace != "/chat" || !got[0].SocketIO {
		t.Fatalf("app chunk: %+v", got)
	}
	if !InSocket(got, len(`var io2=io("/`)) {
		t.Error("the namespace is part of the call")
	}
	lib := "t.path=t.path||`/socket.io`,this.opts=t;" +
		"this._socket=Xa(window.location.origin,{path:window.location.pathname+`socket.io`})"
	got = WebSockets(lib)
	if len(got) != 1 || got[0].URL != "/socket.io" || !got[0].Default || got[0].Namespace != "" {
		t.Fatalf("library default: %+v", got)
	}
	named := "t.path=t.path||`/socket.io`;const s=io(`https://api.example.com/admin`,{transports:[`websocket`]});const r=io();"
	m := socketMap(WebSockets(named))
	if s := m["https://api.example.com/socket.io"]; s.Namespace != "/admin" || !s.SocketIO {
		t.Errorf("absolute: %+v", m)
	}
	if s := m["/socket.io"]; s.Default || s.Namespace != "/" {
		t.Errorf("io(): %+v", m)
	}
	if len(m) != 2 {
		t.Errorf("got %+v", m)
	}
	if !SocketPath("/realtime/socket.io/") || !SocketPath("/engine.io") || SocketPath("/socket") {
		t.Error("SocketPath")
	}
}
