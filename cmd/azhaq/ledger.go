package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/egress"
	"github.com/trannghiach/azhaq/internal/ledger"
	"github.com/trannghiach/azhaq/internal/neterr"
	"github.com/trannghiach/azhaq/scope"
	"github.com/trannghiach/azhaq/store"
)

const (
	ledgerHelp   = "write every request, connection and DNS query the run sends (to targets, third-party sources and resolvers) to this file, a chain of hashes that azhaq ledger -verify checks (default DB.ledger.jsonl next to the workspace; off: none; with a temporary database, only when given)"
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
	writes   []ledger.Entry // writes of a killed run that a resume does not send again
}

// unsentKey holds, in a workspace, the writes a killed run sent whose
// answers it never stored, until the run has nothing left to resume: a
// second resume, after the first stopped, must not send them either.
func unsentKey(run string) string { return "sent-unanswered:" + run }

// holdWrites is the resume's half of a crash: the ledger has a request
// before it is sent, so the requests after its last seal were sent, or
// were about to be, when the run was killed. A read whose answer was lost
// is asked again; a write is never sent a second time.
func (r *runLedger) holdWrites(st *store.Store, run string) {
	if r == nil || r.l == nil || !r.owned {
		return
	}
	var kept []ledger.Entry
	if raw := st.GetMeta(unsentKey(run)); raw != "" {
		_ = json.Unmarshal([]byte(raw), &kept)
	}
	r.writes = r.l.Guard(kept)
	if len(r.writes) > len(kept) {
		if raw, err := json.Marshal(r.writes); err == nil {
			_ = st.SetMeta(unsentKey(run), string(raw))
		}
	}
}

// maxUnsentListed is how many held writes the summary names one by one.
const maxUnsentListed = 20

// noteResume says in rep what the resume did about the killed run's
// requests.
func (r *runLedger) noteResume(rep *report) {
	if n := len(r.writes); n > 0 {
		for i, e := range r.writes {
			if i == maxUnsentListed {
				rep.Skipped = append(rep.Skipped, engine.Skip{Target: fmt.Sprintf("%d more writes", n-i), Reason: "sent before the run was killed, their answers were not stored: not sent again"})
				break
			}
			rep.Skipped = append(rep.Skipped, engine.Skip{Target: e.Target, Reason: fmt.Sprintf("sent before the run was killed, its answer was not stored: not sent again (%s %s)", e.Method, e.Target)})
		}
		rep.Notes = append(rep.Notes, fmt.Sprintf("%s sent before the run was killed, with no answer stored: not sent again (the work they belonged to continues without them)", nOf(n, "write was", "writes were")))
	}
	if n := r.l.Again(); n > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%s sent before the run was killed had no stored answer and %s asked again", nOf(n, "request", "requests"), map[bool]string{true: "was", false: "were"}[n == 1]))
	}
}

func nOf(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
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
	r.stopKill = egress.SetKill(kill)
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
	r := &runLedger{stopKill: egress.SetKill(kill)}
	rearm = func() { r.stopKill = egress.SetKill(kill) }
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
	errors.As(egress.Killed(), &k)
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
	r.noteResume(rep)
	ledger.Use(nil)
	path := r.l.Path()
	if err := r.l.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "azhaq: ledger %s: %v\n", path, err)
		rep.Notes = append(rep.Notes, fmt.Sprintf("ledger %s could not be written (%v): what the run sent may be missing from it", path, err))
		return
	}
	c, _ := ledger.Verify(path)
	seal := r.l.Last()
	rep.Notes = append(rep.Notes, fmt.Sprintf("ledger: %d requests, connections and queries recorded in %s, sealed %s (azhaq ledger -verify %s -seal %s; the seal alone proves no line was later removed and the rest re-chained)", c.Entries, path, seal, path, seal))
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
		// The user's own endpoint, asked after the ledger is sealed: not recorded in it.
		client := egress.OwnClient(egress.OwnOptions{Timeout: 15 * time.Second, Follow: true})
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
