package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

// rolesRow is azhaq roles on Juice Shop: anonymous against a user the
// bench registers, once with the user's token and once signing in through
// the login page with Chrome (-role-login).
type rolesRow struct {
	Rows         int      `json:"rows"`
	Expected     []string `json:"expected"`
	Found        []string `json:"found"`
	Seconds      float64  `json:"seconds"`
	LoginFail    string   `json:"login_error,omitempty"`
	ChromeRows   int      `json:"chrome_rows"`
	ChromeFound  []string `json:"chrome_found"`
	ChromeSecs   float64  `json:"chrome_seconds"`
	ChromeFailed string   `json:"chrome_error,omitempty"`
}

// Endpoints any logged-in user may read and an anonymous visitor may not;
// /api/Users lists every account, the broken access control Juice Shop
// teaches.
var rolesExpected = []string{"/api/Users", "/rest/user/authentication-details"}

func benchRoles(target, dir string) *rolesRow {
	row := &rolesRow{Expected: rolesExpected}
	email, password, token, err := juiceUser(target)
	if err != nil {
		row.LoginFail = err.Error()
		addCheck("roles: Juice Shop anonymous → user", false, "could not register a user: %v", err)
		return row
	}
	out, m := run("roles", 10*time.Minute, dir, azhaq, "roles", "-dir", filepath.Join(dir, "roles-"+time.Now().Format("150405")),
		"-jsonl", "-role", "anon", "-role", "user=Authorization: Bearer "+token, "--", "-url", target)
	row.Seconds = m.Seconds
	row.Rows, row.Found = juiceRoleRows(out, target)
	addCheck("roles: Juice Shop anonymous → user", len(row.Found) == len(rolesExpected) && row.Rows >= 5,
		"%d endpoints differ; 401 → 200 on %d/%d of %s", row.Rows, len(row.Found), len(rolesExpected), strings.Join(rolesExpected, ", "))

	// The same, signing in on the login page (an Angular form behind a
	// welcome dialog) instead of being handed a token.
	out, m = run("roles-login", 10*time.Minute, dir, azhaq, "roles", "-dir", filepath.Join(dir, "roles-login-"+time.Now().Format("150405")),
		"-jsonl", "-login", target+"#/login", "-role", "anon", "-role-login", "user="+email+":"+password, "--", "-url", target)
	row.ChromeSecs = m.Seconds
	row.ChromeRows, row.ChromeFound = juiceRoleRows(out, target)
	if m.Error != "" {
		row.ChromeFailed = m.Error
	}
	addCheck("roles: Juice Shop anonymous → user, signed in with Chrome", len(row.ChromeFound) == len(rolesExpected),
		"%d endpoints differ; 401 → 200 on %d/%d (with a token: %d endpoints) %s", row.ChromeRows, len(row.ChromeFound), len(rolesExpected), row.Rows, row.ChromeFailed)
	return row
}

// juiceRoleRows counts the rows of azhaq roles -jsonl and keeps the
// expected endpoints that went from 401 to 200.
func juiceRoleRows(out []byte, target string) (int, []string) {
	origin := strings.TrimSuffix(target, "/")
	changed := map[string]bool{}
	n := 0
	for _, l := range lines(out) {
		var r struct {
			URL    string         `json:"url"`
			Status map[string]int `json:"status"`
		}
		if json.Unmarshal([]byte(l), &r) != nil {
			continue
		}
		n++
		if r.Status["anon"] == http.StatusUnauthorized && r.Status["user"] == http.StatusOK {
			changed[strings.TrimPrefix(r.URL, origin)] = true
		}
	}
	var found []string
	for _, e := range rolesExpected {
		if changed[e] {
			found = append(found, e)
		}
	}
	return n, found
}

// juiceUser registers a throwaway account on the local Juice Shop and
// returns it with its bearer token.
func juiceUser(target string) (email, password, token string, err error) {
	var b [6]byte
	_, _ = rand.Read(b[:])
	email = "bench-" + hex.EncodeToString(b[:]) + "@azhaq.test"
	password = "Bench-Passw0rd!"
	post := func(path string, body any, out any) error {
		raw, _ := json.Marshal(body)
		resp, err := (&http.Client{Timeout: 15 * time.Second}).Post(target+path, "application/json", bytes.NewReader(raw))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			return &httpError{path, resp.Status}
		}
		if out != nil {
			return json.NewDecoder(resp.Body).Decode(out)
		}
		return nil
	}
	if err := post("api/Users", map[string]string{"email": email, "password": password, "passwordRepeat": password}, nil); err != nil {
		return "", "", "", err
	}
	var login struct {
		Authentication struct {
			Token string `json:"token"`
		} `json:"authentication"`
	}
	if err := post("rest/user/login", map[string]string{"email": email, "password": password}, &login); err != nil {
		return "", "", "", err
	}
	return email, password, login.Authentication.Token, nil
}

type httpError struct{ path, status string }

func (e *httpError) Error() string { return "POST " + e.path + ": " + e.status }
