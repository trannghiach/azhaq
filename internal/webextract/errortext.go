package webextract

import "strings"

// What a failed answer's body gives away, strongest first.
const (
	ErrSQL   = "sql"   // the text of a database's error
	ErrDebug = "debug" // a framework's debug page
	ErrStack = "stack" // a stack trace
)

var errorTexts = []struct {
	kind string
	re   *lazyRegexp
}{
	{ErrSQL, lazyRE(`(?i)(SQLITE_(?:ERROR|CONSTRAINT)\w*[^\n<]{0,80}|SQLSTATE\[\w+\][^\n<]{0,80}|SequelizeDatabaseError[^\n<]{0,80}|\bORA-\d{5}[^\n<]{0,60}|PG::\w+Error[^\n<]{0,60}|psycopg2\.\w+Error[^\n<]{0,60}|org\.postgresql\.util\.PSQLException[^\n<]{0,60}|java\.sql\.SQL\w*Exception[^\n<]{0,60}|You have an error in your SQL syntax[^\n<]{0,60}|syntax error at or near[^\n<]{0,40}|unclosed quotation mark[^\n<]{0,40}|quoted string not properly terminated|near "[^"\n]{0,40}": syntax error|PDOException[^\n<]{0,60}|mysqli?_\w+\(\)[^\n<]{0,40}|Microsoft OLE DB Provider for SQL Server[^\n<]{0,40}|MySQLSyntaxErrorException[^\n<]{0,40})`)},
	{ErrDebug, lazyRE(`(Whoops, looks like something went wrong|Werkzeug Debugger|The debugger caught an exception|You're seeing this error because you have <code>DEBUG = True|Server Error in '/[^']*' Application|ActionController::\w+Error|Symfony\\Component\\\w+|<title>Django Version|Xdebug|APP_DEBUG|Laravel\s*Exception)`)},
	{ErrStack, lazyRE(`(Traceback \(most recent call last\)|\n\s*at [\w$.<>\[\] ]+ \([^)\n]*:\d+:\d+\)|\bat [\w$.]+\([\w$]+\.java:\d+\)|\bat [\w.]+\([^)\n]*\) in [^\n<]*:line \d+|goroutine \d+ \[running\]|Stack trace:\s*#0|\.rb:\d+:in [` + "`" + `']|Fatal error: Uncaught|on line <b>\d+</b>|<ul id="stacktrace">)`)},
}

// ErrorText says what the body of a failed answer shows besides the failure:
// an SQL error's text, a framework's debug page or a stack trace, with the
// text that says so (up to 100 bytes); "" when it is a plain error page.
func ErrorText(body []byte) (kind, sample string) {
	if len(body) > 64<<10 {
		body = body[:64<<10]
	}
	s := string(body)
	for _, e := range errorTexts {
		if m := e.re.FindStringIndex(s); m != nil {
			t := strings.Join(strings.Fields(s[m[0]:m[1]]), " ")
			if len(t) > 100 {
				t = t[:100]
			}
			return e.kind, t
		}
	}
	return "", ""
}
