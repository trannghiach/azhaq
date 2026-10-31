package webextract

import "testing"

func TestErrorText(t *testing.T) {
	for _, c := range []struct {
		name, body, kind string
	}{
		{"sqlite", `{"error":{"message":"SQLITE_ERROR: near \"'\": syntax error","code":"SQLITE_ERROR"}}`, ErrSQL},
		{"mysql", `<b>Warning</b>: You have an error in your SQL syntax; check the manual`, ErrSQL},
		{"postgres", `ERROR: syntax error at or near "'" LINE 1`, ErrSQL},
		{"node trace", "<pre>TypeError: x is undefined<br>\n    at Object.handler (/app/routes/user.js:12:3)\n    at Layer.handle</pre>", ErrStack},
		{"python trace", "Traceback (most recent call last):\n  File \"app.py\", line 3", ErrStack},
		{"java trace", "java.lang.NullPointerException\n\tat com.shop.UserController.get(UserController.java:42)", ErrStack},
		{"django debug", `<title>Django Version: 4.2</title>`, ErrDebug},
		{"werkzeug", `<title>Werkzeug Debugger</title>`, ErrDebug},
		{"sql wins over a trace", "SQLSTATE[42000]: Syntax error\n    at foo (/a.js:1:2)", ErrSQL},
		{"plain", `<html><title>Error</title><body>Internal Server Error</body></html>`, ""},
		{"json error", `{"status":"error","message":"Unexpected path: /rest/x"}`, ""},
	} {
		if kind, sample := ErrorText([]byte(c.body)); kind != c.kind || (kind != "" && sample == "") {
			t.Errorf("%s: %q %q, want %q", c.name, kind, sample, c.kind)
		}
	}
}
