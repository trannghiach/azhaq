package store

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
)

// Evidence is what stands behind the rows azhaq roles listed: each role's
// answer to each row, kept so that a row can be checked and asked again
// by hand (azhaq roles show).
type Evidence struct{ db *sql.DB }

// EvidenceRow is one listed row: the row as roles -json prints it, and the
// answers behind it.
type EvidenceRow struct {
	URL, Method string
	Row         []byte
	Answers     []EvidenceAnswer
}

// EvidenceAnswer is one role's answer: to the row's URL, or, for a
// control, to a made-up identifier on the same route (Asked).
type EvidenceAnswer struct {
	Role        string
	Kind        string // "answer" or "control"
	Asked       string // the URL asked
	Status      int
	ContentType string
	Curl        string // the request, with the role's session as placeholders
	Body        []byte // as kept: cut, sensitive values taken out
	Truncated   bool
}

// OpenEvidence opens (or makes) the evidence database at path.
func OpenEvidence(path string) (*Evidence, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rows (
  url TEXT NOT NULL,
  method TEXT NOT NULL,
  row TEXT NOT NULL,
  PRIMARY KEY (url, method)
);
CREATE TABLE IF NOT EXISTS answers (
  url TEXT NOT NULL,
  method TEXT NOT NULL,
  role TEXT NOT NULL,
  kind TEXT NOT NULL,
  asked TEXT NOT NULL,
  status INTEGER NOT NULL,
  content_type TEXT NOT NULL,
  curl TEXT NOT NULL,
  body BLOB,
  truncated INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (url, method, role, kind)
);`)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Evidence{db: db}, nil
}

// OpenEvidenceExisting opens an evidence database that must exist.
func OpenEvidenceExisting(path string) (*Evidence, error) {
	if st, err := os.Stat(path); err != nil || st.IsDir() {
		return nil, fmt.Errorf("no evidence at %s", path)
	}
	return OpenEvidence(path)
}

func (e *Evidence) Close() error { return e.db.Close() }

// Save replaces what the database holds with rows, of the roles named in
// order.
func (e *Evidence) Save(roles []string, rows []EvidenceRow) error {
	tx, err := e.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{`DELETE FROM rows`, `DELETE FROM answers`} {
		if _, err := tx.Exec(q); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO meta (k, v) VALUES ('roles', ?)`, strings.Join(roles, "\n")); err != nil {
		return err
	}
	insRow, err := tx.Prepare(`INSERT OR REPLACE INTO rows (url, method, row) VALUES (?, ?, ?)`)
	if err != nil {
		return err
	}
	defer insRow.Close()
	insAns, err := tx.Prepare(`INSERT OR REPLACE INTO answers (url, method, role, kind, asked, status, content_type, curl, body, truncated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer insAns.Close()
	for _, r := range rows {
		if _, err := insRow.Exec(r.URL, r.Method, string(r.Row)); err != nil {
			return err
		}
		for _, a := range r.Answers {
			var body []byte
			if a.Body != nil {
				body = gz(a.Body)
			}
			cut := 0
			if a.Truncated {
				cut = 1
			}
			if _, err := insAns.Exec(r.URL, r.Method, a.Role, a.Kind, a.Asked, a.Status, a.ContentType, a.Curl, body, cut); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// Roles are the roles of the run, in the order they were given.
func (e *Evidence) Roles() []string {
	var v string
	if e.db.QueryRow(`SELECT v FROM meta WHERE k = 'roles'`).Scan(&v) != nil || v == "" {
		return nil
	}
	return strings.Split(v, "\n")
}

// Row is the row kept for url and method ("" for a read).
func (e *Evidence) Row(url, method string) (EvidenceRow, bool, error) {
	out := EvidenceRow{URL: url, Method: method}
	var row string
	switch err := e.db.QueryRow(`SELECT row FROM rows WHERE url = ? AND method = ?`, url, method).Scan(&row); {
	case err == sql.ErrNoRows:
		return out, false, nil
	case err != nil:
		return out, false, err
	}
	out.Row = []byte(row)
	rs, err := e.db.Query(`SELECT role, kind, asked, status, content_type, curl, body, truncated FROM answers WHERE url = ? AND method = ? ORDER BY kind, role`, url, method)
	if err != nil {
		return out, false, err
	}
	defer rs.Close()
	for rs.Next() {
		var a EvidenceAnswer
		var body []byte
		var cut int
		if err := rs.Scan(&a.Role, &a.Kind, &a.Asked, &a.Status, &a.ContentType, &a.Curl, &body, &cut); err != nil {
			return out, false, err
		}
		if body != nil {
			if a.Body, err = gunzip(body); err != nil {
				return out, false, err
			}
		}
		a.Truncated = cut == 1
		out.Answers = append(out.Answers, a)
	}
	return out, true, rs.Err()
}

// Keys are the rows kept, as METHOD URL ("GET" for a read).
func (e *Evidence) Keys() ([]string, error) {
	rs, err := e.db.Query(`SELECT method, url FROM rows ORDER BY url, method`)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []string
	for rs.Next() {
		var m, u string
		if err := rs.Scan(&m, &u); err != nil {
			return nil, err
		}
		if m == "" {
			m = "GET"
		}
		out = append(out, m+" "+u)
	}
	return out, rs.Err()
}
