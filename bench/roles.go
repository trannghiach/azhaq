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
// bench registers.
type rolesRow struct {
	Rows      int      `json:"rows"`
	Expected  []string `json:"expected"`
	Found     []string `json:"found"`
	Seconds   float64  `json:"seconds"`
	LoginFail string   `json:"login_error,omitempty"`
}

// Endpoints any logged-in user may read and an anonymous visitor may not;
// /api/Users lists every account, the broken access control Juice Shop
// teaches.
var rolesExpected = []string{"/api/Users", "/rest/user/authentication-details"}

func benchRoles(target, dir string) *rolesRow {
	row := &rolesRow{Expected: rolesExpected}
	token, err := juiceUser(target)
	if err != nil {
		row.LoginFail = err.Error()
		addCheck("roles: Juice Shop anonymous → user", false, "could not register a user: %v", err)
		return row
	}
	out, m := run("roles", 10*time.Minute, dir, azhaq, "roles", "-dir", filepath.Join(dir, "roles-"+time.Now().Format("150405")),
		"-jsonl", "-role", "anon", "-role", "user=Authorization: Bearer "+token, "--", "-url", target)
	row.Seconds = m.Seconds
	origin := strings.TrimSuffix(target, "/")
	changed := map[string]bool{}
	for _, l := range lines(out) {
		var r struct {
			URL    string         `json:"url"`
			Status map[string]int `json:"status"`
		}
		if json.Unmarshal([]byte(l), &r) != nil {
			continue
		}
		row.Rows++
		if r.Status["anon"] == http.StatusUnauthorized && r.Status["user"] == http.StatusOK {
			changed[strings.TrimPrefix(r.URL, origin)] = true
		}
	}
	for _, e := range rolesExpected {
		if changed[e] {
			row.Found = append(row.Found, e)
		}
	}
	addCheck("roles: Juice Shop anonymous → user", len(row.Found) == len(rolesExpected) && row.Rows >= 5,
		"%d endpoints differ; 401 → 200 on %d/%d of %s", row.Rows, len(row.Found), len(rolesExpected), strings.Join(rolesExpected, ", "))
	return row
}

// juiceUser registers a throwaway account on the local Juice Shop and
// returns its bearer token.
func juiceUser(target string) (string, error) {
	var b [6]byte
	_, _ = rand.Read(b[:])
	email := "bench-" + hex.EncodeToString(b[:]) + "@azhaq.test"
	const password = "Bench-Passw0rd!"
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
		return "", err
	}
	var login struct {
		Authentication struct {
			Token string `json:"token"`
		} `json:"authentication"`
	}
	if err := post("rest/user/login", map[string]string{"email": email, "password": password}, &login); err != nil {
		return "", err
	}
	return login.Authentication.Token, nil
}

type httpError struct{ path, status string }

func (e *httpError) Error() string { return "POST " + e.path + ": " + e.status }
