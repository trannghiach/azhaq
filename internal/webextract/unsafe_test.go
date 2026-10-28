package webextract

import "testing"

func TestStateChanging(t *testing.T) {
	for raw, want := range map[string]string{
		"http://app/rest/saveLoginIp":               "save",
		"http://app/createdb":                       "createdb",
		"http://app/logout":                         "logout",
		"http://app/account/log-out":                "logout",
		"http://app/rest/user/reset-password":       "reset",
		"http://app/rest/2fa/disable":               "disable",
		"http://app/admin.php?action=delete&id=4":   "delete",
		"http://app/users/v1/name/delete":           "delete",
		"http://app/api/Users":                      "",
		"http://app/rest/user/whoami":               "",
		"http://app/changelog":                      "",
		"http://app/updates":                        "",
		"http://app/addresses":                      "",
		"http://app/settings":                       "",
		"http://app/profile/edit":                   "",
		"http://app/static/js/delete-dialog.js":     "",
		"http://app/search?q=delete":                "",
		"http://app/rest/products/search?q=":        "",
		"http://app/rest/user/change-password?new=": "change",
		"http://app/api/SecurityQuestions":          "",
		"http://app/api/jobs/run":                   "run",
		"http://dvwa/security.php?phpids=on":        "phpids=on",
		"http://app/settings?darkmode=OFF":          "darkmode=OFF",
		"http://app/list?showall=true":              "",
		"http://app/admin/users?status=enabled":     "",
		"http://app/search?q=shoes&exact=on&page=2": "",
		"http://app/search?safe=off":                "",
		"http://app/api/jobs/42/execute":            "execute",
		"http://dvwa/vulnerabilities/exec/":         "",
		"http://dvwa/vulnerabilities/exec/x.php":    "",
		"http://app/exec":                           "exec",
		"http://app/import_paste":                   "import",
		"http://app/admin/auth/user/add/":           "",
		"http://app/api/jobs/run/":                  "run",
		"http://app/v2/jobs/start/":                 "start",
		"http://app/logout/":                        "logout",
		"http://app/account/delete/":                "delete",
		"http://app/api/cache/refresh":              "refresh",
		"http://app/runtime":                        "",
		"http://app/started":                        "",
		"http://app/blockchain":                     "",
		"http://app/bank/transfer":                  "transfer",
	} {
		if got := StateChanging(raw); got != want {
			t.Errorf("%s: %q, want %q", raw, got, want)
		}
	}
}

func TestAllowedWords(t *testing.T) {
	AllowedWords["exec"] = true
	defer delete(AllowedWords, "exec")
	if w := StateChanging("http://dvwa/exec"); w != "" {
		t.Errorf("an allowed word left alone: %q", w)
	}
	if w := StateChanging("http://app/logout"); w != "logout" {
		t.Errorf("logout requested: %q", w)
	}
}
