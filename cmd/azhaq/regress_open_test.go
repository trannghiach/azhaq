package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// Findings that are still open (REGRESSIONS.md). Each test states the
// condition that closes the finding and is skipped until then; the owner
// is the stream that holds the code.

// PRB-17 (owner F2 for dirs, A2 for params): a sweep without a wordlist
// uses a default list or says where to get one.
func TestRegressPRB17WordlistIsFoundOrNamed(t *testing.T) {
	t.Skip("open: PRB-17 (owner F2: dirs; A2: params)")
	for _, cmd := range []string{"dirs", "params"} {
		_, errOut, code := cli(t, cmd, "-u", "http://127.0.0.1:1/")
		if code == exitUsage && !strings.Contains(errOut, "SecLists") && !strings.Contains(errOut, "https://") {
			t.Errorf("%s without -w: %q names no list to use", cmd, errOut)
		}
	}
}

// SAF-23 (a decision, no stream owns roles): write replay changes data on
// the target, so it asks for a confirmation or a dry pass first, or the
// docs record that it does not.
func TestRegressSAF23WriteReplayNeedsConfirmation(t *testing.T) {
	t.Skip("open: SAF-23 (needs a decision; roles has no stream)")
	_, errOut, code := cli(t, "roles", "-role", "anon", "-role", "a=Cookie: x=1", "-replay-writes", "put", "--", "-url", "http://127.0.0.1:1/")
	if code != exitUsage || !strings.Contains(errOut, "-dry-writes") {
		t.Errorf("-replay-writes without -dry-writes ran: exit %d, %q", code, errOut)
	}
}

// OUT-21 (owner A3: notify): a dry run of the notification and a schema
// version in the change set a CI job reads.
func TestRegressOUT21WatchDryNotifyAndSchema(t *testing.T) {
	t.Skip("open: OUT-21 (owner A3: notify)")
	fs := flagsOf("watch")
	if fs == nil || fs.Lookup("dry-notify") == nil {
		t.Error("watch has no -dry-notify")
	}
	var c changes
	raw, _ := json.Marshal(c)
	if !strings.Contains(string(raw), `"schema"`) {
		t.Errorf("the change set has no schema version: %s", raw)
	}
}

// REL-04 (no stream owns releases): azhaq verify checks a release's
// signature without cosign.
func TestRegressREL04VerifyCommand(t *testing.T) {
	t.Skip("open: REL-04 (release tooling; no stream)")
	if _, ok := lookup("verify"); !ok {
		t.Error("there is no azhaq verify")
	}
}

// REL-05 (owner G1 for the Chrome preflight; resume --until-done has no
// stream): a missing Chrome is named with the step that installs it, and
// resume can go on until the work is done.
func TestRegressREL05ChromePreflightAndUntilDone(t *testing.T) {
	t.Skip("open: REL-05 (owner G1: screenshots; resume --until-done: none)")
	t.Setenv("AZHAQ_CHROME", "/nonexistent/chrome")
	_, errOut, _ := cli(t, "shots", "-u", "http://127.0.0.1:1/", "-dir", t.TempDir())
	if !strings.Contains(strings.ToLower(errOut), "install") {
		t.Errorf("a missing Chrome does not say how to get one: %q", errOut)
	}
	if fs := flagsOf("resume"); fs == nil || fs.Lookup("until-done") == nil {
		t.Error("resume has no -until-done")
	}
}
