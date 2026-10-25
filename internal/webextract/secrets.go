package webextract

import (
	"math"
	"regexp"
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

var secretPatterns = []struct {
	kind, severity string
	re             *regexp.Regexp
}{
	{"aws-access-key-id", "medium", regexp.MustCompile(`\b((?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16})\b`)},
	{"google-api-key", "medium", regexp.MustCompile(`\b(AIza[0-9A-Za-z_-]{35})\b`)},
	{"github-token", "high", regexp.MustCompile(`\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,})\b`)},
	{"github-token", "high", regexp.MustCompile(`\b(github_pat_[A-Za-z0-9_]{60,})\b`)},
	{"gitlab-token", "high", regexp.MustCompile(`\b(glpat-[A-Za-z0-9_-]{20})\b`)},
	{"slack-token", "high", regexp.MustCompile(`\b(xox[baprs]-[0-9A-Za-z-]{10,})\b`)},
	{"slack-webhook", "high", regexp.MustCompile(`(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,})`)},
	{"discord-webhook", "high", regexp.MustCompile(`(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{50,})`)},
	{"stripe-secret-key", "high", regexp.MustCompile(`\b((?:sk|rk)_live_[0-9a-zA-Z]{24,})\b`)},
	{"stripe-publishable-key", "info", regexp.MustCompile(`\b(pk_live_[0-9a-zA-Z]{24,})\b`)},
	{"sendgrid-key", "high", regexp.MustCompile(`\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b`)},
	{"mailgun-key", "high", regexp.MustCompile(`\b(key-[0-9a-f]{32})\b`)},
	{"twilio-key", "medium", regexp.MustCompile(`\b(SK[0-9a-f]{32})\b`)},
	{"openai-key", "high", regexp.MustCompile(`\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,})\b`)},
	{"anthropic-key", "high", regexp.MustCompile(`\b(sk-ant-[A-Za-z0-9_-]{80,})\b`)},
	{"private-key", "high", regexp.MustCompile(`(-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----)`)},
	{"jwt", "info", regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`)},
}

var (
	// awsSecretNear is a 40-character secret key next to an access key id.
	awsSecret = regexp.MustCompile(`["'` + "`" + `]([A-Za-z0-9/+]{40})["'` + "`" + `]`)
	// envVar is a build-time variable a bundler inlined.
	envVar = regexp.MustCompile(`["']?((?:REACT_APP|NEXT_PUBLIC|VUE_APP|VITE|NUXT_ENV|GATSBY)_[A-Z0-9_]+)["']?\s*:\s*["']([^"'\n]{4,200})["']`)
	// assigned is a value given to a name that sounds secret.
	assigned = regexp.MustCompile(`(?i)["']?([a-z0-9_.-]*(?:secret|token|passw(?:or)?d|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?key)[a-z0-9_.-]*)["']?\s*[:=]\s*["']([^"'\s]{8,200})["']`)
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
	for _, m := range envVar.FindAllStringSubmatch(script, 64) {
		add(Secret{Kind: "build-variable", Severity: "info", Name: m[1], Value: m[2]})
	}
	for _, m := range assigned.FindAllStringSubmatch(script, 64) {
		name, v := m[1], m[2]
		if seen[v] || notSecret(v) || entropy(v) < 3.2 || strings.Contains(v, "/") && !strings.ContainsAny(v, "+=") {
			continue
		}
		add(Secret{Kind: "generic-secret", Severity: "medium", Name: name, Value: v})
	}
	sort.SliceStable(out, func(i, j int) bool { return rank(out[i].Severity) < rank(out[j].Severity) })
	return out
}

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
var placeholderRE = regexp.MustCompile(`(?i)^(true|false|null|undefined|password|secret|token|example|changeme|your[_-]|xxx|\*+|\$\{|\{\{|%s|<.*>|[a-z]+(\.[a-z]+){1,}$|[A-Z_]+$)`)

func notSecret(v string) bool {
	return placeholderRE.MatchString(v)
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
