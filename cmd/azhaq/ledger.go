package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/ledger"
	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/scope"
)

const (
	ledgerHelp   = "write every request and connection to a target to this file, a chain of hashes that azhaq ledger -verify checks (default DB.ledger.jsonl next to the workspace; off: none; with a temporary database, only when given)"
	killFileHelp = "stop all sending, at once, when this file exists, and exit 4; azhaq resume works once it is removed (default DB.stop)"
	sealToHelp   = "when the run ends, append the ledger's seal as one JSON line ({\"time\",\"ledger\",\"seal\",\"entries\"}) to this file, or POST it to this URL: kept where the run's own files are not, so azhaq ledger -verify -seal can tell the ledger from one with lines removed and the rest re-chained to look intact"
)

// runLedger is what a run keeps for the evidence of what it sent: its
// ledger, the watch for the kill file, and where to send the seal when it
// ends (-seal-to), apart from the run's own files.
type runLedger struct {
	l        *ledger.Ledger
	owned    bool // the run opened it, so the run closes it
	stopKill func()
	sealTo   string
}

// startLedger opens the run's ledger and starts watching for its kill file.
// db is the run's workspace; scratch says it is temporary, so nothing is
// kept next to it unless a flag names a file. A ledger already in use
// (roles opens one for all its runs) is the run's too.
func startLedger(ledgerFlag, killFlag, db string, scratch bool, rules scope.Rules, sealTo string) (*runLedger, error) {
	r := &runLedger{stopKill: func() {}, sealTo: sealTo}
	kill := killFlag
	if kill == "" && !scratch {
		kill = db + ".stop"
	}
	r.stopKill = fetch.SetKill(kill)
	if l := ledger.Active(); l != nil {
		r.l = l
		if !rules.Empty() {
			l.Match = rules.Match
		}
		return r, nil
	}
	path := ledgerFlag
	if path == "" && !scratch {
		path = db + ".ledger.jsonl"
	}
	if path == "" || path == "off" {
		return r, nil
	}
	l, err := ledger.Open(path)
	if err != nil {
		r.stopKill()
		return nil, err
	}
	l.Match = rules.Match
	ledger.Use(l)
	r.l, r.owned = l, true
	return r, nil
}

// rolesLedger opens one ledger in dir for everything azhaq roles sends: the
// run of each role, which finds it in use, and the requests between them.
// It returns the func that closes it, and rearm, which watches roles.stop
// again after a role's run ended its own watch: the replay stops at it too.
func rolesLedger(dir string, rep *report) (closeIt, rearm func()) {
	kill := filepath.Join(dir, "roles.stop")
	r := &runLedger{stopKill: fetch.SetKill(kill)}
	rearm = func() { r.stopKill = fetch.SetKill(kill) }
	l, err := ledger.Open(filepath.Join(dir, "roles.ledger.jsonl"))
	if err != nil {
		rep.Notes = append(rep.Notes, "no ledger: "+err.Error())
		return func() { r.stopKill() }, rearm
	}
	ledger.Use(l)
	r.l, r.owned = l, true
	return func() { r.close(rep) }, rearm
}

// killStopped is the run's `stopped` when the kill file ended it.
func killStopped(left int) string {
	var k *neterr.Killed
	errors.As(fetch.Killed(), &k)
	return fmt.Sprintf("the kill switch: kill file %s exists, %d tasks known and not done (remove it, then azhaq resume)", k.Path, left)
}

// close ends the ledger and the kill watch and, in rep, says what was recorded.
func (r *runLedger) close(rep *report) {
	if r == nil {
		return
	}
	r.stopKill()
	if r.l == nil || !r.owned {
		return
	}
	ledger.Use(nil)
	path := r.l.Path()
	if err := r.l.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "azhaq: ledger %s: %v\n", path, err)
		rep.Notes = append(rep.Notes, fmt.Sprintf("ledger %s could not be written (%v): what the run sent may be missing from it", path, err))
		return
	}
	c, _ := ledger.Verify(path)
	seal := r.l.Last()
	rep.Notes = append(rep.Notes, fmt.Sprintf("ledger: %d requests and connections recorded in %s, sealed %s (azhaq ledger -verify %s -seal %s; the seal alone proves no line was later removed and the rest re-chained)", c.Entries, path, seal, path, seal))
	if r.sealTo != "" {
		if err := sendSeal(r.sealTo, path, seal, c.Entries); err != nil {
			rep.Notes = append(rep.Notes, fmt.Sprintf("-seal-to %s: %v: the seal is only in %s, next to the run's own files", r.sealTo, err, path))
		}
	}
}

// sealRecord is the one JSON line -seal-to writes or posts.
type sealRecord struct {
	Time    time.Time `json:"time"`
	Ledger  string    `json:"ledger"`
	Seal    string    `json:"seal"`
	Entries int       `json:"entries"`
}

// sendSeal appends a sealRecord to dest, or POSTs it as JSON when dest is
// an http or https URL: a copy of the seal the run's own files, and
// whoever could edit them, do not hold.
func sendSeal(dest, ledgerPath, seal string, entries int) error {
	raw, err := json.Marshal(sealRecord{Time: time.Now().UTC(), Ledger: ledgerPath, Seal: seal, Entries: entries})
	if err != nil {
		return err
	}
	if u, err := url.Parse(dest); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		client := &http.Client{Timeout: 15 * time.Second}
		resp, err := client.Post(dest, "application/json", bytes.NewReader(raw))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			return fmt.Errorf("%s", resp.Status)
		}
		return nil
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(raw, '\n'))
	return err
}
