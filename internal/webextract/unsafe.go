package webextract

import (
	"net/url"
	"strings"
	"unicode"
)

// stateVerbs start the names of endpoints that do something when called:
// a GET to /rest/saveLoginIp records an address, /createdb resets a
// database, /logout ends the session.
var stateVerbs = map[string]bool{
	"logout": true, "logoff": true, "signout": true,
	"delete": true, "del": true, "remove": true, "destroy": true, "drop": true, "purge": true, "erase": true, "wipe": true, "truncate": true,
	"reset": true, "reinit": true, "init": true, "initialize": true, "setup": true, "install": true, "uninstall": true,
	"create": true, "createdb": true, "add": true, "save": true, "update": true, "change": true,
	"clear": true, "flush": true, "kill": true, "shutdown": true, "restart": true, "reboot": true,
	"revoke": true, "unsubscribe": true, "cancel": true, "approve": true, "reject": true,
	"disable": true, "enable": true, "activate": true, "deactivate": true, "send": true, "vote": true,
	"sync": true, "refresh": true, "trigger": true, "run": true, "execute": true, "exec": true, "start": true, "stop": true,
	"import": true, "generate": true, "rebuild": true, "restore": true, "migrate": true, "populate": true,
	"deploy": true, "publish": true, "unpublish": true, "lock": true, "unlock": true, "ban": true, "unban": true,
	"block": true, "unblock": true, "invite": true, "transfer": true, "pay": true, "checkout": true, "confirm": true,
	"erasure": true,
	// Written as one word: DVNA's /resetpw, Juice Shop's /dataerasure.
	"resetpw": true, "resetpwd": true, "resetpass": true, "resetpassword": true, "dataerasure": true,
	"deleteaccount": true, "deleteuser": true, "deleteme": true,
}

// oneTime: a query key holding a token a request may spend (a reset or
// confirmation link: /resetpw?login=user&token=ee11cb…).
func oneTime(k string) bool {
	k = strings.ToLower(k)
	if strings.Contains(k, "csrf") || strings.Contains(k, "page") || strings.Contains(k, "next") || strings.Contains(k, "continuation") {
		return false
	}
	return k == "token" || strings.HasSuffix(k, "_token") || strings.HasSuffix(k, "-token") || k == "resettoken" ||
		k == "reset_key" || k == "otp" || k == "magic"
}

// actionKeys are query keys whose value names what the request does.
var actionKeys = map[string]bool{"action": true, "cmd": true, "do": true, "op": true, "operation": true, "task": true, "mode": true}

// StateChanging names the word that makes a URL look like it changes
// something when requested, or "". Static files never do.
func StateChanging(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if c := ClassifyURL(raw); c == "script" || c == "asset" {
		return ""
	}
	segs := strings.Split(u.Path, "/")
	for i, seg := range segs {
		if i < len(segs)-1 && sectionWords[strings.ToLower(seg)] && !apiPath(segs[:i]) {
			continue // DVWA's /vulnerabilities/exec/ is a page with a form
		}
		if w := verbOf(seg); w != "" && !AllowedWords[w] {
			return w
		}
	}
	for k, vs := range u.Query() {
		if oneTime(k) {
			return k + "=" // spent by the request, or by the next one
		}
		for _, v := range vs {
			if toggles[strings.ToLower(v)] && !filterKeys[strings.ToLower(k)] {
				return k + "=" + v // DVWA's security.php?phpids=on turns a filter on
			}
			if !actionKeys[strings.ToLower(k)] {
				continue
			}
			if w := verbOf(v); w != "" && !AllowedWords[w] {
				return w
			}
		}
	}
	return ""
}

// sectionWords name a section of a site when they are a directory of
// their own (/exec/, /import/, /checkout/): the page there shows a form,
// and the form's POST does the work. /exec, /import_paste and
// /api/jobs/run/ stay left alone.
var sectionWords = map[string]bool{"exec": true, "execute": true, "run": true, "import": true, "create": true, "add": true,
	"generate": true, "send": true, "start": true, "checkout": true}

// apiPath says the segments before a word are an API's (/api/, /rest/,
// /v2/): a directory there is an endpoint, not a page.
func apiPath(segs []string) bool {
	for _, s := range segs {
		s = strings.ToLower(s)
		if s == "api" || s == "rest" || s == "graphql" || len(s) > 1 && s[0] == 'v' && strings.Trim(s[1:], "0123456789") == "" {
			return true
		}
	}
	return false
}

// AllowedWords are the words the user lets be requested (-get-words exec):
// a URL they name is asked like any other; the rest stay left alone.
var AllowedWords = map[string]bool{}

// toggles are query values that switch something: unless the key filters
// or shapes what is read, the request sets it.
var toggles = map[string]bool{"on": true, "off": true, "enable": true, "disable": true, "enabled": true, "disabled": true,
	"activate": true, "deactivate": true}

// filterKeys pick or shape what a page shows: ?status=enabled lists the
// enabled users, ?safe=off a search's unfiltered results.
var filterKeys = map[string]bool{"status": true, "state": true, "filter": true, "filters": true, "safe": true, "safesearch": true,
	"exact": true, "autoplay": true, "active": true, "visible": true, "show": true, "view": true, "include": true, "expand": true,
	"q": true, "query": true, "search": true, "type": true, "sort": true, "order": true}

// verbOf is the state-changing verb a path segment starts with:
// saveLoginIp, reset-password, log_out.
func verbOf(seg string) string {
	words := splitWords(seg)
	if len(words) == 0 {
		return ""
	}
	if len(words) > 1 {
		if j := words[0] + words[1]; j == "logout" || j == "logoff" || j == "signout" {
			return j
		}
	}
	if stateVerbs[words[0]] {
		return words[0]
	}
	return ""
}

// splitWords splits on separators and camelCase, lower-cased:
// saveLoginIp → save login ip.
func splitWords(s string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	rs := []rune(s)
	for i, r := range rs {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			flush()
		case unicode.IsUpper(r) && i > 0 && unicode.IsLower(rs[i-1]):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return out
}
