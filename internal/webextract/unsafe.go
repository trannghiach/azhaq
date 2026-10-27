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
	for _, seg := range strings.Split(u.Path, "/") {
		if w := verbOf(seg); w != "" {
			return w
		}
	}
	for k, vs := range u.Query() {
		for _, v := range vs {
			if toggles[strings.ToLower(v)] {
				return k + "=" + v // DVWA's security.php?phpids=on turns a filter on
			}
			if !actionKeys[strings.ToLower(k)] {
				continue
			}
			if w := verbOf(v); w != "" {
				return w
			}
		}
	}
	return ""
}

// toggles are query values that switch something: whatever the key, the
// request sets it.
var toggles = map[string]bool{"on": true, "off": true, "enable": true, "disable": true, "enabled": true, "disabled": true,
	"activate": true, "deactivate": true}

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
