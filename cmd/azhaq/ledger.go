package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/internal/ledger"
	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/scope"
)

const (
	ledgerHelp   = "write every request and connection to a target to this file, a chain of hashes `azhaq ledger -verify` checks (default DB.ledger.jsonl next to the workspace; off: none; with a temporary database, only when given)"
	killFileHelp = "stop all sending, at once, when this file exists, and exit 4; azhaq resume works once it is removed (default DB.stop)"
)

// runLedger is what a run keeps for the evidence of what it sent: its
// ledger, and the watch for the kill file.
type runLedger struct {
	l        *ledger.Ledger
	owned    bool // the run opened it, so the run closes it
	stopKill func()
}

// startLedger opens the run's ledger and starts watching for its kill file.
// db is the run's workspace; scratch says it is temporary, so nothing is
// kept next to it unless a flag names a file. A ledger already in use
// (roles opens one for all its runs) is the run's too.
func startLedger(ledgerFlag, killFlag, db string, scratch bool, rules scope.Rules) (*runLedger, error) {
	r := &runLedger{stopKill: func() {}}
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
// The func returned closes it.
func rolesLedger(dir string, rep *report) func() {
	l, err := ledger.Open(filepath.Join(dir, "roles.ledger.jsonl"))
	if err != nil {
		rep.Notes = append(rep.Notes, "no ledger: "+err.Error())
		return func() {}
	}
	ledger.Use(l)
	r := &runLedger{l: l, owned: true, stopKill: func() {}}
	return func() { r.close(rep) }
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
	n, path := r.l.Count(), r.l.Path()
	if err := r.l.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "azhaq: ledger %s: %v\n", path, err)
		rep.Notes = append(rep.Notes, fmt.Sprintf("ledger %s could not be written (%v): what the run sent may be missing from it", path, err))
		return
	}
	rep.Notes = append(rep.Notes, fmt.Sprintf("ledger: %d requests and connections recorded in %s (azhaq ledger -verify %s)", n, path, path))
}
