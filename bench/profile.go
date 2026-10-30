package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// The bench measures every comparison twice, as a reviewer does: with the
// default flags of both tools, and politely, at a rate a program's rules
// allow. The profile names a measurement; the rest of a section is the same.
const (
	profDefault = "default"
	profPolite  = "polite"
)

// Polite settings, one place so a check's detail and the command agree.
const (
	politeHTTP = "5"   // requests per second, azhaq -rate and the reference's equivalent
	politeDNS  = "10"  // DNS queries per second
	politePort = "100" // port connection attempts per second
)

// profileSet is what the comparison sections write. The default profile's
// set is the record's top level (so older records stay comparable); the
// polite one is record.Polite.
type profileSet struct {
	Apps     []appResult  `json:"apps,omitempty"`
	Domains  []domainRow  `json:"domains,omitempty"`
	Brute    *bruteRow    `json:"brute,omitempty"`
	Probe    *probeRow    `json:"probe,omitempty"`
	Ports    *portsRow    `json:"ports,omitempty"`
	Dirs     *dirsRow     `json:"dirs,omitempty"`
	Params   *paramsRow   `json:"params,omitempty"`
	Shots    *shotsRow    `json:"shots,omitempty"`
	Fuzz     *fuzzRow     `json:"fuzz,omitempty"`
	DNS      *dnsRow      `json:"dns,omitempty"`
	URLs     *urlsRow     `json:"urls,omitempty"`
	Services *servicesRow `json:"services,omitempty"`
	Notify   *notifyRow   `json:"notify,omitempty"`
}

var (
	prof   string      // the profile now running; "" for sections that are not comparisons
	cur    *profileSet // where its rows go
	refBin string      // a folder of reference tools built elsewhere, tried before bench/.work/bin
	nmapAt string      // nmap, or a wrapper script for an unpacked one
	// politeWords is how many words a polite sweep sends: at 5 requests per
	// second the whole 4,750-word list is 16 minutes for each tool and app.
	politeWords int
	// politeDomains are the domains the polite profile looks up.
	politeDomains []string
)

func polite() bool { return prof == profPolite }

// pick returns the polite value in the polite profile, else the default.
func pick[T any](def, pol T) T {
	if polite() {
		return pol
	}
	return def
}

// ---- timing: the median of three below 20 s ----

// noCache makes run() execute a reference tool again instead of replaying
// today's run, for the repetitions a median needs.
var noCache bool

const slowRun = 20.0 // seconds: from here a single run is the measure

// timedArgs runs a command, and below slowRun seconds twice more, and
// returns the first run's output with the median of the seconds. mk builds
// the arguments of run i, for commands that must not reuse a file.
// beforeEach, when set, runs before every run timedArgs makes (the bench's
// Juice Shop is started fresh for each sweep of a leg).
var beforeEach func()

func timedArgs(target string, timeout time.Duration, dir, name string, mk func(i int) []string) ([]byte, runMeasure) {
	if beforeEach != nil {
		beforeEach()
	}
	out, m := run(target, timeout, dir, name, mk(0)...)
	if m.Error != "" && !benignExit(m.Error) || m.Seconds >= slowRun {
		return out, m
	}
	secs := []float64{m.Seconds}
	noCache = true
	for i := 1; i < 3; i++ {
		if beforeEach != nil {
			beforeEach()
		}
		_, m2 := run(target, timeout, dir, name, mk(i)...)
		if m2.Error == "" || benignExit(m2.Error) {
			secs = append(secs, m2.Seconds)
		}
	}
	noCache = false
	sort.Float64s(secs)
	m.Seconds = secs[len(secs)/2]
	return out, m
}

func timed(target string, timeout time.Duration, dir, name string, args ...string) ([]byte, runMeasure) {
	return timedArgs(target, timeout, dir, name, func(int) []string { return args })
}

// benignExit: azhaq's exit 3 and 4 say the run was partial or stopped, and
// the output is still a result; a refused command line (exit 2) is not.
func benignExit(e string) bool {
	return strings.Contains(e, "exit status 3") || strings.Contains(e, "exit status 4")
}

// refused is true for a command line azhaq rejected: a flag or a command a
// stream has not delivered, not a measurement.
func refused(m runMeasure) bool {
	return strings.Contains(m.Error, "exit status 2") || strings.Contains(m.Error, "executable file not found")
}

// helpHas is true when `azhaq help CMD` mentions flag.
func helpHas(cmd, flag string) bool {
	out, err := exec.Command(azhaq, "help", cmd).Output()
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(out), "\n") {
		if f := strings.Fields(l); len(f) > 0 && f[0] == flag {
			return true
		}
	}
	return false
}

// ---- the bar ----

// barOne records the two checks every comparison row must pass: results at
// least the reference's, each counted only when independent evidence
// confirms it, and wall time at most 1.05 times the reference's.
//
// az and rf are the confirmed counts; azT and rfT the seconds (the median of
// three below slowRun, one run otherwise); cmds the exact command lines, so
// a reviewer can run them again; note anything else the record should keep,
// the old 95% share among it.
func barOne(name string, az, rf int, azT, rfT float64, evidence, cmds, note string) {
	if note != "" {
		note = "; " + note
	}
	addCheck(name+": results ≥ the reference's, confirmed by "+evidence, az >= rf,
		"azhaq %d, reference %d%s | %s", az, rf, note, cmds)
	// A run that failed is not a fast one.
	failed := strings.Contains(note, "[azhaq: ")
	addCheck(name+": time ≤ 1.05× the reference's", azT <= rfT*1.05 && !failed,
		"azhaq %.1fs, reference %.1fs (%s)%s | %s", azT, rfT, "the median of 3 below 20 s, one run above", pick("", "")+failedNote(failed), cmds)
}

// share is the old bar, kept in the record: the part of the reference's
// results azhaq also has.
func share(shared, ref int) string {
	if ref == 0 {
		return "old bar: reference found none"
	}
	return fmt.Sprintf("old bar: %d of %d = %.0f%%", shared, ref, 100*float64(shared)/float64(ref))
}

// ratio is azhaq's time over the reference's, kept in the record.
func ratio(a, r float64) string {
	if r <= 0 {
		return ""
	}
	return fmt.Sprintf("time ×%.2f of the reference", a/r)
}

// cmdLine is a command for a check's detail.
func cmdLine(name string, args ...string) string {
	return filepath.Base(name) + " " + strings.Join(args, " ")
}

// azErr is the reason azhaq's run did not end clean, for a check's detail.
// A run that finished with failures or stopped (exit 3 or 4) still has results
// and is only noted; any other error is a failed run, and barOne fails the
// time check on the "[azhaq: " it carries.
func azErr(m runMeasure) string {
	switch {
	case m.Error == "":
		return ""
	case benignExit(m.Error):
		return " [azhaq finished with failures or was stopped: " + clip(m.Error, 160) + "]"
	}
	return " [azhaq: " + clip(m.Error, 200) + "]"
}

// fileExists reports whether p is a regular file.
func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// azRun runs azhaq with its stdout and stderr kept, and records the run.
func azRun(target string, timeout time.Duration, dir string, args ...string) azResult {
	r := azStart(dir, args...).wait(timeout)
	m := runMeasure{Tool: "azhaq", Target: target, Seconds: r.seconds, Profile: prof}
	if r.exit != 0 {
		m.Error = fmt.Sprintf("exit status %d %s", r.exit, lastLine(r.stderr))
	}
	rec.Runs = append(rec.Runs, m)
	return r
}

func failedNote(failed bool) string {
	if failed {
		return "; azhaq's run failed, so there is no time to compare"
	}
	return ""
}

// azFail is the reason a run of azhaq failed (not a partial or stopped run),
// in the form barOne looks for.
func azFail(m runMeasure) string {
	if m.Error == "" || benignExit(m.Error) {
		return ""
	}
	return azErr(m)
}

// downNote says that an app went down while a sweep ran: the row is not a
// measure of the tools (Juice Shop runs out of memory under long sweeps).
func downNote(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("; THE APP WENT DOWN %d time(s) DURING THIS SWEEP AND WAS STARTED AGAIN: read the row as unreliable", n)
}
