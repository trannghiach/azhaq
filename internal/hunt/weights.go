package hunt

import "strings"

// Every weight the ranking uses is here. A row's score is the sum of its
// signals, each counted once at its highest weight. The scale: 100 is a
// proved access-control hole, 60-90 a way in with no work (takeover,
// secret, readable credential file), 30-50 a place a tester starts,
// below 15 a hint that decides ties.
var weights = map[string]int{
	"takeover":        60, // strong findings: see takeoverStrong
	"secret":          40, // by severity: see secretWeight
	"sourcemap":       45,
	"exposed-file":    55, // by extension: see fileExt
	"listing":         55,
	"api-description": 35,
	"graphql":         40, // 45 when the schema was read or an IDE answers
	"object-id":       35, // 15 when the route has no GET: a write alone
	"unauth-write":    25, // 10 when no GET showed that it answers
	"upload":          35,
	"state-change":    30,
	"password-in-url": 30, // a GET form with a password field: it lands in logs and history
	"param-command":   40,
	"param-url":       35,
	"param-file":      35,
	"param-debug":     35,
	"param-redirect":  30,
	"param-query":     40,
	"param-callback":  15,
	"input":           8,
	"gated":           15, // 401/403: a session is needed, a target for azhaq roles
	"server-error":    20, // a 5xx: the input reached code that failed
	"new":             5,  // a bonus; a row with only this never ranks
}

const (
	takeoverStrong  = 90
	graphqlStrong   = 45
	unauthWriteDry  = 10
	objectWriteOnly = 15
	// refused or not requested files weigh this much of a served one
	fileUnseen = 85
)

// secretWeight is by the scanner's severity.
var secretWeight = map[string]int{"high": 70, "medium": 40, "info": 15}

// verdictWeight is what the roles verdicts that say one session reached
// another's data are worth, scaled by confidence (confidenceScale). They
// sit above everything else: they are shown, not guessed. The strings are
// roles.go's and roles_writes.go's; a test in cmd/azhaq holds them equal.
var verdictWeight = map[string]int{
	"anyone writes another role's object": 110,
	"writes another role's object":        105,
	"anyone reads sensitive fields":       100,
	"reads another role's object":         95,
}

// confidenceScale is in percent; a verdict without a confidence is whole.
var confidenceScale = map[string]int{"proved": 100, "likely": 85, "guess": 60}

// pathWord is a word that says what a route is for. Each class is its
// own signal, so a path that is both admin and configuration scores both.
type pathWord struct {
	signal string
	w      int
}

// pathWords are matched as whole words of a path or of a host's labels
// (_debug and debug.php are "debug"; "administration" is its own word; a
// plural counts as its singular).
var pathWords = map[string]pathWord{}

func init() {
	for _, c := range []struct {
		signal string
		w      int
		words  string
	}{
		{"path-admin", 40, "admin administrator administration internal console actuator manager"},
		{"path-debug", 50, "debug phpinfo metrics"},
		{"path-config", 40, "config configuration setup backup"},
		{"path-env", 30, "staging dev test"},
		// also seen by the api-description and graphql signals, so little here
		{"path-doc", 15, "swagger graphiql api-docs"},
		// what a request makes the server do with its input
		{"path-function", 35, "redirect upload exec ping eval download proxy shell cmd sql import"},
		// people, credentials and the things a user owns
		{"path-data", 35, "user account password credential secret token session authentication"},
		{"path-data", 25, "profile customer member basket cart order payment card invoice wallet address"},
	} {
		for _, word := range strings.Fields(c.words) {
			pathWords[word] = pathWord{c.signal, c.w}
		}
	}
}

// guardedWords are the classes whose 401 or 403 says a surface is there
// and guarded, which is worth a look; for the others a refusal says nothing.
var guardedWords = map[string]bool{"path-admin": true, "path-config": true, "path-data": true}

// fileExt are the endings of files that hold backups or secrets.
var fileExt = []struct {
	ext string
	w   int
}{
	{".kdbx", 70}, {".pem", 70}, {".key", 70}, {".env", 70}, {".sql", 65}, {".db", 65},
	{".bak", 55}, {".old", 55}, {".orig", 55}, {".swp", 55}, {".zip", 50}, {".tar.gz", 50},
}

// gitWeight is a repository's directory served over HTTP.
const gitWeight = 70
