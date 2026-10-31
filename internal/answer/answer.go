// Package answer tells an error a server sent with a 200 status from data:
// a quota page, a JSON error object, a challenge page. A source that gets
// one has not answered "no names"; it has not answered.
package answer

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strings"
)

// MaxBody is the longest body looked at: an error is a few lines or a page
// of HTML, a data answer is longer or a list.
const MaxBody = 32 << 10

// Screen reads the start of body and says why the answer is an error, ""
// when it is data (or too long to be an error). The reader it returns
// holds the same bytes again and closes body.
func Screen(body io.ReadCloser) (io.ReadCloser, string) {
	prefix, err := io.ReadAll(io.LimitReader(body, MaxBody+1))
	var rest io.Reader = body
	if err != nil {
		rest = failing{err}
	}
	again := struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(prefix), rest), body}
	if err != nil || len(prefix) > MaxBody {
		return again, ""
	}
	return again, Reason(prefix)
}

type failing struct{ err error }

func (f failing) Read([]byte) (int, error) { return 0, f.err }

// Reason says why a whole 200 answer is an error, in the words the server
// used; "" when it looks like data or like an empty answer.
func Reason(body []byte) string {
	b := bytes.TrimSpace(body)
	if len(b) == 0 || len(b) > MaxBody {
		return ""
	}
	var why string
	switch b[0] {
	case '{':
		why = jsonReason(b)
	case '<':
		why = htmlReason(b)
	case '[':
		return "" // a list is data
	default:
		why = textReason(b)
	}
	if why == "" || emptyAnswer.MatchString(why) {
		return ""
	}
	return clip(why)
}

// emptyAnswer is how a server says it holds nothing: not a failure.
var emptyAnswer = regexp.MustCompile(`(?i)\bno (captures|results?|records?|data|matches|subdomains|urls|entries|hosts)\b|\bnot found\b|\bnothing found\b`)

// quota is what a refusal says: a quota, a limit, a block.
var quota = regexp.MustCompile(`(?i)api count exceeded|quota|rate.?limit|too many (requests|queries)|(limit|usage|credits?)\b.{0,20}\b(exceeded|reached|used up)|exceeded|try again (later|in)|temporarily (unavailable|blocked|disabled)|access denied|forbidden|unauthori[sz]ed|invalid (api|access)?.?(key|token)|missing (api )?(key|token)|banned|blocked|captcha|are you (a )?(human|robot)|verify you are|service unavailable|bad gateway|gateway time-?out|internal server error|maintenance`)

var errorTitle = regexp.MustCompile(`(?i)\b(error|forbidden|denied|blocked|captcha|too many requests|rate.?limit|just a moment|attention required|unavailable|bad gateway|gateway time-?out|timed out|verify you are|are you (a )?(human|robot)|maintenance|suspended|limit exceeded)\b|^\s*(4\d\d|5\d\d)\b`)

var (
	titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	tagRE   = regexp.MustCompile(`(?s)<script.*?</script>|<style.*?</style>|<[^>]*>`)
	spaceRE = regexp.MustCompile(`\s+`)
)

// textReason: a short plain answer that starts with "error", or that is a
// quota or refusal message (hackertarget's "API count exceeded", "error
// check your search parameter").
func textReason(b []byte) string {
	if len(b) > 512 || bytes.Count(b, []byte("\n")) > 2 {
		return ""
	}
	s := spaceRE.ReplaceAllString(string(b), " ")
	if strings.HasPrefix(strings.ToLower(s), "error") || quota.MatchString(s) {
		return s
	}
	return ""
}

// htmlReason: a page whose title is an error or a challenge, or a short
// page whose text is a refusal. A data page of an HTML source has neither.
func htmlReason(b []byte) string {
	if m := titleRE.FindSubmatch(b); m != nil {
		if t := strings.TrimSpace(spaceRE.ReplaceAllString(string(m[1]), " ")); t != "" && errorTitle.MatchString(t) {
			return "an HTML page titled " + `"` + clip(t) + `"`
		}
	}
	if len(b) <= 2048 {
		text := strings.TrimSpace(spaceRE.ReplaceAllString(tagRE.ReplaceAllString(string(b), " "), " "))
		if text != "" && (quota.MatchString(text) || strings.HasPrefix(strings.ToLower(text), "error")) {
			return text
		}
	}
	return ""
}

// errorKeys are the keys that carry an error in a JSON object.
var errorKeys = []string{"error", "errors", "err", "error_message", "errormessage", "fault", "exception"}

// wordKeys carry the words of a message.
var wordKeys = []string{"message", "msg", "detail", "description", "reason", "error_description"}

// jsonReason: an object with an error in it and no data beside it, or
// that is only a message. A line of newline-delimited JSON is read as one
// object.
func jsonReason(b []byte) string {
	var obj map[string]json.RawMessage
	if err := json.NewDecoder(bytes.NewReader(b)).Decode(&obj); err != nil {
		return ""
	}
	low := make(map[string]json.RawMessage, len(obj))
	for k, v := range obj {
		low[strings.ToLower(k)] = v
	}
	for _, k := range errorKeys {
		if v, ok := low[k]; ok && present(v) {
			return valueText(v)
		}
	}
	message := ""
	for _, k := range wordKeys {
		if v, ok := low[k]; ok && present(v) {
			message = valueText(v)
			break
		}
	}
	if v, ok := low["success"]; ok && string(bytes.TrimSpace(v)) == "false" {
		return orElse(message, "success is false")
	}
	if v, ok := low["ok"]; ok && string(bytes.TrimSpace(v)) == "false" {
		return orElse(message, "ok is false")
	}
	for _, k := range []string{"status", "code", "statuscode", "status_code"} {
		v, ok := low[k]
		if !ok {
			continue
		}
		var s string
		var n float64
		switch {
		case json.Unmarshal(v, &s) == nil:
			switch strings.ToLower(s) {
			case "error", "fail", "failed", "failure", "err", "denied", "forbidden", "limited":
				return orElse(message, s)
			}
		case json.Unmarshal(v, &n) == nil && n >= 400 && n < 600 && message != "":
			return message
		}
	}
	// Only a message (and a code): there is nothing else to be data.
	if message != "" && len(low) <= 3 {
		only := true
		for k := range low {
			switch k {
			case "message", "msg", "detail", "description", "reason", "status", "code", "statuscode", "status_code", "error_description":
			default:
				only = false
			}
		}
		if only {
			return message
		}
	}
	return ""
}

// present says a JSON value is a real one: not null, false, 0, "" or empty.
func present(v json.RawMessage) bool {
	switch s := string(bytes.TrimSpace(v)); s {
	case "", "null", "false", "0", `""`, "[]", "{}":
		return false
	}
	return true
}

// valueText is a JSON value as words: a string as is, an object by its
// message, anything else as JSON.
func valueText(v json.RawMessage) string {
	var s string
	if json.Unmarshal(v, &s) == nil {
		return s
	}
	var o map[string]json.RawMessage
	if json.Unmarshal(v, &o) == nil {
		low := make(map[string]json.RawMessage, len(o))
		for k, ov := range o {
			low[strings.ToLower(k)] = ov
		}
		for _, k := range append(wordKeys[:len(wordKeys):len(wordKeys)], "code", "type") {
			var t string
			if json.Unmarshal(low[k], &t) == nil && t != "" {
				return t
			}
		}
	}
	var l []json.RawMessage
	if json.Unmarshal(v, &l) == nil && len(l) > 0 {
		return valueText(l[0])
	}
	return string(bytes.TrimSpace(v))
}

func orElse(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func clip(s string) string {
	s = strings.TrimSpace(spaceRE.ReplaceAllString(s, " "))
	if len(s) > 160 {
		s = strings.ToValidUTF8(s[:160], "") + "…"
	}
	return s
}
