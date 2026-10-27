package webextract

import (
	"regexp"
	"strings"
)

// Socket is a WebSocket endpoint a script opens: new WebSocket(url), a
// socket.io client's io(url, {path}), or a ws:// URL it names. It is not
// a page: a GET there says nothing.
//
//	new WebSocket("wss://"+location.host+"/ws/notifications")  → wss, /ws/notifications
//	io("/chat",{path:"/realtime/socket.io"})                     → /realtime/socket.io, namespace /chat
type Socket struct {
	URL        string // ws://host/path, http(s)://host/path, or a path on the page's host
	Scheme     string // ws or wss when the script says so for a path; "" leaves it to the page
	Namespace  string // socket.io's namespace; "" when unknown or not socket.io
	SocketIO   bool   // a socket.io endpoint: its handshake goes to URL
	Default    bool   // socket.io's default path, read from the library: an app's own io() call says better
	Start, End int    // the call or the string
}

var (
	wsNew = regexp.MustCompile(`\bnew\s+(?:WebSocket|SockJS|ReconnectingWebSocket)\s*\(`)
	// wsLiteral is a ws:// URL with a host.
	wsLiteral = regexp.MustCompile(`["'\x60](wss?://[A-Za-z0-9.-]+(?::\d+)?(?:/[A-Za-z0-9._~%!$&()*+,;=:@/-]*)?)["'\x60]`)
	// ioName is a socket.io client call by name; ioESM the same imported
	// by a bundler: (0,r.io)(…).
	ioName = regexp.MustCompile(`(?:^|[^\w$.])(?:io(?:\s*\.\s*connect)?|socketIOClient)\s*\(`)
	ioESM  = regexp.MustCompile(`\.\s*io\s*\)\s*\(`)
	// ioLib is socket.io's default path, as its client library sets it.
	ioLib  = regexp.MustCompile(`["'\x60]/socket\.io/?["'\x60]`)
	strLit = regexp.MustCompile(`"([^"\\\n]{0,200})"|'([^'\\\n]{0,200})'|\x60([^\x60\\$]{0,200})\x60`)
)

// maxSockets caps the endpoints read from one script.
const maxSockets = 64

// WebSockets lists the WebSocket endpoints a script opens.
func WebSockets(script string) []Socket {
	var out []Socket
	seen := map[string]bool{}
	var spans [][2]int
	add := func(s Socket) {
		k := s.URL + "\x00" + s.Scheme + "\x00" + s.Namespace
		spans = append(spans, [2]int{s.Start, s.End})
		if seen[k] || len(out) >= maxSockets {
			return
		}
		seen[k] = true
		out = append(out, s)
	}
	for _, m := range wsNew.FindAllStringIndex(script, -1) {
		args := callArgs(script, m[1]-1)
		if len(args) == 0 {
			continue
		}
		end := closeParen(script, m[1]-1) + 1
		if s, ok := socketTarget(script, m[0], args[0]); ok {
			s.Start, s.End = m[0], end
			add(s)
		}
	}
	lib := ioLib.FindStringIndex(script)
	named := lib != nil || strings.Contains(script, "socket.io-client")
	var calls [][]int
	if named {
		calls = ioName.FindAllStringIndex(script, -1)
	} else if strings.Contains(script, "io") {
		for _, m := range ioName.FindAllStringIndex(script, -1) {
			if strings.Contains(script[m[0]:m[1]], "connect") || strings.Contains(script[m[0]:m[1]], "socketIOClient") {
				calls = append(calls, m) // a name no minifier gives
			}
		}
	}
	calls = append(calls, ioESM.FindAllStringIndex(script, -1)...)
	explicit := false
	for _, m := range calls {
		args := callArgs(script, m[1]-1)
		end := closeParen(script, m[1]-1) + 1
		call := script[m[0]:m[1]]
		bare := !strings.Contains(call, "connect") && !strings.Contains(call, "socketIOClient") && !ioESM.MatchString(call)
		if s, ok := ioTarget(script, m[0], args, bare); ok {
			s.Start, s.End = m[0], end
			add(s)
			explicit = true
		}
	}
	for _, m := range wsLiteral.FindAllStringSubmatchIndex(script, -1) {
		if inSpans(spans, m[0]) {
			continue
		}
		add(Socket{URL: script[m[2]:m[3]], Start: m[0], End: m[1]})
	}
	if lib != nil && !explicit {
		add(Socket{URL: "/socket.io", SocketIO: true, Default: true, Start: lib[0], End: lib[1]})
	}
	return out
}

// InSocket says whether a string at i is part of a socket's call: its
// URL or namespace, not a page.
func InSocket(socks []Socket, i int) bool {
	for _, s := range socks {
		if !s.Default && i >= s.Start && i < s.End {
			return true
		}
	}
	return false
}

// SocketPath says whether p is where socket.io or engine.io takes its
// handshake: /socket.io, /realtime/socket.io/.
func SocketPath(p string) bool {
	p = strings.TrimSuffix(strings.ToLower(p), "/")
	return strings.HasSuffix(p, "/socket.io") || strings.HasSuffix(p, "/engine.io")
}

func inSpans(spans [][2]int, i int) bool {
	for _, sp := range spans {
		if i >= sp[0] && i < sp[1] {
			return true
		}
	}
	return false
}

// socketTarget reads the URL given to new WebSocket: worked out where the
// script spells it, else from the strings in the argument.
func socketTarget(script string, pos int, arg string) (Socket, bool) {
	ev := evaluator{src: script}
	if v, ok := ev.eval(arg, pos, 0); ok {
		if s, ok := socketURL(v); ok {
			return s, true
		}
	}
	// ("https:"===location.protocol?"wss:":"ws:")+"//"+location.host+"/ws"
	var s Socket
	ws, wss := false, false
	for _, m := range strLit.FindAllStringSubmatch(arg, -1) {
		lit := m[1] + m[2] + m[3]
		switch {
		case strings.HasPrefix(lit, "wss:"):
			wss = true
		case strings.HasPrefix(lit, "ws:"):
			ws = true
		}
		if t, ok := socketURL(lit); ok && (t.Scheme == "" || strings.Contains(t.URL, "://")) {
			if strings.Contains(t.URL, "://") {
				return t, true
			}
			s.URL = t.URL
		}
	}
	if s.URL == "" {
		return Socket{}, false
	}
	if wss != ws {
		s.Scheme = map[bool]string{true: "wss", false: "ws"}[wss]
	}
	return s, true
}

// socketURL makes a Socket of a URL a script built: the page's host where
// it reads location.host, "" for what is not a URL.
func socketURL(v string) (Socket, bool) {
	scheme, rest, ok := strings.Cut(v, "://")
	if !ok {
		if strings.HasPrefix(v, "/") && len(v) > 1 && !strings.HasPrefix(v, "//") && pathChars.MatchString(v) {
			return Socket{URL: v}, true
		}
		return Socket{}, false
	}
	switch scheme {
	case "ws", "wss", "http", "https":
	default:
		return Socket{}, false
	}
	host, path, _ := strings.Cut(rest, "/")
	path = "/" + path
	if strings.HasPrefix(host, "{") || host == "" {
		// "wss://"+location.host+"/ws": the page's own host.
		if path == "/" || !pathChars.MatchString(path) {
			return Socket{}, false
		}
		s := Socket{URL: path}
		if scheme == "ws" || scheme == "wss" {
			s.Scheme = scheme
		}
		return s, true
	}
	if strings.ContainsAny(host, "{}") {
		return Socket{}, false
	}
	return Socket{URL: scheme + "://" + host + path}, true
}

// ioTarget reads a socket.io client call: io(), io("/chat"),
// io("https://api.example.com/admin",{path:"/rt/socket.io"}). A call by
// the bare name io, which a minifier may give any function, must pass a
// namespace, a URL or socket.io's options.
func ioTarget(script string, pos int, args []string, bare bool) (Socket, bool) {
	host, path, ns := "", "/socket.io", "/"
	opts := ""
	ev := evaluator{src: script}
	switch first := strings.TrimSpace(firstArg(args)); {
	case first == "":
	case strings.HasPrefix(first, "{"):
		opts = first
	default:
		if len(args) > 1 {
			opts = strings.TrimSpace(args[1])
		}
		v, ok := ev.eval(first, pos, 0)
		t, good := socketURL(v)
		switch {
		case ok && good && strings.HasPrefix(v, "/"):
			ns = v
		case ok && good && strings.Contains(t.URL, "://"):
			i := strings.Index(t.URL, "://")
			h, rest, _ := strings.Cut(t.URL[i+3:], "/")
			host, ns = t.URL[:i+3]+h, "/"+rest
		case ok && good:
			ns = t.URL // location.origin+"/admin": the page's host
		case ok:
			return Socket{}, false // io("click"): some other io
		case bare && !strings.HasPrefix(opts, "{"):
			return Socket{}, false
		default:
			ns = "" // a run-time value: the origin, most often
		}
	}
	if !strings.HasPrefix(opts, "{") {
		opts = ""
	}
	if opts != "" {
		props := objectProps(opts)
		if !hasAny(props, []string{"path", "transports", "query", "auth", "reconnection", "forceNew", "withCredentials", "extraHeaders", "timeout", "autoConnect"}) {
			return Socket{}, false
		}
		if p := strings.TrimSpace(propOf(props, "path")); p != "" {
			if v, ok := ev.eval(p, pos, 0); ok && strings.HasPrefix(v, "/") && pathChars.MatchString(v) {
				path = v
			}
		}
	}
	return Socket{URL: host + path, Namespace: ns, SocketIO: true}, true
}

func firstArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}
