package webextract

import (
	"math"
	"sort"
	"strings"
)

// Secret is a credential or key a script carries.
type Secret struct {
	Kind     string `json:"kind"`
	Severity string `json:"severity"` // high: works on its own; medium: needs a pair or context; info: public by design
	Value    string `json:"value"`
	Name     string `json:"name,omitempty"` // the property or variable it was assigned to
}

// secretPatterns are tried only on a script that holds one of a pattern's
// literals: a regular expression over a megabyte of script is slow, and
// nearly every script holds none of these.
var secretPatterns = []struct {
	kind, severity string
	has            []string
	re             *lazyRegexp
}{
	{"aws-access-key-id", "medium", []string{"AKIA", "ASIA", "ABIA", "ACCA", "A3T"}, lazyRE(`\b((?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16})\b`)},
	{"google-api-key", "medium", []string{"AIza"}, lazyRE(`\b(AIza[0-9A-Za-z_-]{35})\b`)},
	{"github-token", "high", []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}, lazyRE(`\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,})\b`)},
	{"github-token", "high", []string{"github_pat_"}, lazyRE(`\b(github_pat_[A-Za-z0-9_]{60,})\b`)},
	{"gitlab-token", "high", []string{"glpat-"}, lazyRE(`\b(glpat-[A-Za-z0-9_-]{20})\b`)},
	{"slack-token", "high", []string{"xox"}, lazyRE(`\b(xox[baprs]-[0-9A-Za-z-]{10,})\b`)},
	{"slack-webhook", "high", []string{"hooks.slack.com"}, lazyRE(`(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,})`)},
	{"discord-webhook", "high", []string{"/api/webhooks/"}, lazyRE(`(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{50,})`)},
	{"stripe-secret-key", "high", []string{"_live_"}, lazyRE(`\b((?:sk|rk)_live_[0-9a-zA-Z]{24,})\b`)},
	{"stripe-publishable-key", "info", []string{"pk_live_"}, lazyRE(`\b(pk_live_[0-9a-zA-Z]{24,})\b`)},
	{"sendgrid-key", "high", []string{"SG."}, lazyRE(`\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b`)},
	{"mailgun-key", "high", []string{"key-"}, lazyRE(`\b(key-[0-9a-f]{32})\b`)},
	{"twilio-key", "medium", []string{"SK"}, lazyRE(`\b(SK[0-9a-f]{32})\b`)},
	{"openai-key", "high", []string{"T3BlbkFJ"}, lazyRE(`\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,})\b`)},
	{"anthropic-key", "high", []string{"sk-ant-"}, lazyRE(`\b(sk-ant-[A-Za-z0-9_-]{80,})\b`)},
	{"private-key", "high", []string{"-----BEGIN "}, lazyRE(`(-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----)`)},
	{"jwt", "info", []string{"eyJ"}, lazyRE(`\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`)},
}

// holdsAny says whether s holds one of the literals.
func holdsAny(s string, lits []string) bool {
	for _, l := range lits {
		if strings.Contains(s, l) {
			return true
		}
	}
	return false
}

// envPrefixes start the names of the build variables a bundler inlines.
var envPrefixes = []string{"REACT_APP_", "NEXT_PUBLIC_", "VUE_APP_", "VITE_", "NUXT_ENV_", "GATSBY_"}

var (
	// awsSecretNear is a 40-character secret key next to an access key id.
	awsSecret = lazyRE(`["'` + "`" + `]([A-Za-z0-9/+]{40})["'` + "`" + `]`)
	// envVar is a build-time variable a bundler inlined.
	envVar = lazyRE(`["']?((?:REACT_APP|NEXT_PUBLIC|VUE_APP|VITE|NUXT_ENV|GATSBY)_[A-Z0-9_]+)["']?\s*:\s*["']([^"'\n]{4,200})["']`)
	// assigned is a value given to a name that sounds secret.
	assigned = lazyRE(`(?i)["']?([a-z0-9_.-]*(?:secret|token|passw(?:or)?d|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?key)[a-z0-9_.-]*)["']?\s*[:=]\s*["']([^"'\s]{8,200})["']`)
)

// Secrets lists the credentials in a script, each value once.
func Secrets(script string) []Secret {
	seen := map[string]bool{}
	var out []Secret
	add := func(s Secret) {
		if !seen[s.Value] {
			seen[s.Value] = true
			out = append(out, s)
		}
	}
	for _, p := range secretPatterns {
		if !holdsAny(script, p.has) {
			continue
		}
		for _, m := range p.re.FindAllStringSubmatchIndex(script, 64) {
			v := script[m[2]:m[3]]
			s := Secret{Kind: p.kind, Severity: p.severity, Value: v}
			if p.kind == "aws-access-key-id" {
				// A secret key within a few lines makes the pair usable.
				win := script[max(0, m[0]-300):min(len(script), m[1]+300)]
				if sk := awsSecret.FindStringSubmatch(win); sk != nil && entropy(sk[1]) > 4 {
					add(Secret{Kind: "aws-secret-access-key", Severity: "high", Value: sk[1]})
					s.Severity = "high"
				}
			}
			add(s)
		}
	}
	if holdsAny(script, envPrefixes) {
		for _, m := range envVar.FindAllStringSubmatch(script, 64) {
			add(Secret{Kind: "build-variable", Severity: "info", Name: m[1], Value: m[2]})
		}
	}
	for _, m := range assignedIn(script, 64) {
		name, v := m[1], m[2]
		if seen[v] || notSecret(v) || entropy(v) < 3.2 || strings.Contains(v, "/") && !strings.ContainsAny(v, "+=") ||
			notSecretName.MatchString(name) || oddChars(v) {
			continue
		}
		add(Secret{Kind: "generic-secret", Severity: "medium", Name: name, Value: v})
	}
	sort.SliceStable(out, func(i, j int) bool { return rank(out[i].Severity) < rank(out[j].Severity) })
	return out
}

// assignedWords are what makes a name sound secret (assigned's pattern,
// lower case, without its optional separators).
var assignedWords = []string{"secret", "token", "passw", "apikey", "api_key", "api-key", "accesskey", "access_key", "access-key",
	"privatekey", "private_key", "private-key", "authkey", "auth_key", "auth-key"}

// assignedIn is assigned's matches, found in the stretches of script around
// the words that make a name sound secret rather than in all of it.
func assignedIn(script string, n int) [][]string {
	low := asciiLower(script)
	var spans [][2]int
	for _, w := range assignedWords {
		for from := 0; ; {
			i := strings.Index(low[from:], w)
			if i < 0 {
				break
			}
			i += from
			from = i + len(w)
			start, end := max(0, i-assignedBefore), min(len(script), i+len(w)+assignedAfter)
			spans = append(spans, [2]int{start, end})
		}
	}
	if len(spans) == 0 {
		return nil
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i][0] < spans[j][0] })
	merged := spans[:1]
	for _, sp := range spans[1:] {
		if last := &merged[len(merged)-1]; sp[0] <= last[1] {
			last[1] = max(last[1], sp[1])
		} else {
			merged = append(merged, sp)
		}
	}
	var out [][]string
	for _, sp := range merged {
		for _, m := range assigned.FindAllStringSubmatch(script[sp[0]:sp[1]], n-len(out)) {
			out = append(out, m)
		}
		if len(out) >= n {
			break
		}
	}
	return out
}

// asciiLower lower-cases A-Z only, so that offsets in the result are the
// script's.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// assignedBefore and assignedAfter bound a name's text before its secret
// word and the value after it.
const (
	assignedBefore = 128
	assignedAfter  = 320
)

func rank(sev string) int {
	switch sev {
	case "high":
		return 0
	case "medium":
		return 1
	}
	return 2
}

// placeholder catches values that only look like secrets: field names,
// templates, translation keys.
var placeholderRE = lazyRE(`(?i)^(true|false|null|undefined|password|secret|token|example|changeme|your[_-]|xxx|\*+|\$\{|\{\{|%s|<.*>|[a-z]+(\.[a-z]+){1,}$|[A-Z_]+$)`)

func notSecret(v string) bool {
	return placeholderRE.MatchString(v)
}

// notSecretName: names with "token" in them that hold a parser's tables
// (Lezer's tokenData, tokenPrec), not a credential.
var notSecretName = lazyRE(`(?i)token(data|prec|izers?|types?|s|ize|ized|ization|count|length|index)$`)

// oddChars: keys and tokens are letters, digits and a few separators; a
// value full of other punctuation is encoded data.
func oddChars(v string) bool {
	odd := 0
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', strings.ContainsRune("_-+/=.:@~", r):
		default:
			odd++
		}
	}
	return odd*10 > len(v)
}

// entropy is the Shannon entropy of s in bits per character.
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	for _, r := range s {
		counts[r]++
	}
	var h float64
	n := float64(len([]rune(s)))
	for _, c := range counts {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// Redact keeps the start and end of a value: enough to recognise it in a
// report without repeating it.
func Redact(v string) string {
	if len(v) <= 12 {
		return strings.Repeat("•", len(v))
	}
	return v[:6] + "…" + v[len(v)-4:]
}
