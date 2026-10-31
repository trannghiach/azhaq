package main

import (
	"strings"
	"testing"
)

// A command called without what it needs is a usage error, exit 2, with the
// message it always had.
func TestMissingArgumentsExitUsage(t *testing.T) {
	t.Setenv("AZHAQ_WORKER_TOKEN", "")
	for _, c := range []struct {
		name string
		run  func([]string) error
		args []string
		msg  string
	}{
		{"worker without -server", cmdWorker, nil, "usage: azhaq worker -server"},
		{"worker without a token", cmdWorker, []string{"-server", "http://127.0.0.1:1"}, "usage: azhaq worker -server"},
		{"watch without -db", cmdWatch, []string{"--", "-url", "http://127.0.0.1:1/"}, "usage: azhaq watch -db"},
		{"watch without run options", cmdWatch, []string{"-db", "x.db"}, "usage: azhaq watch -db"},
		{"new without -db", cmdNew, nil, "give -db WORKSPACE.db"},
		{"scope platform without -program", cmdScope, []string{"-scope", "hackerone"}, "-scope hackerone needs -program"},
	} {
		err := c.run(c.args)
		if err == nil || !strings.Contains(err.Error(), c.msg) {
			t.Errorf("%s: %v, want %q", c.name, err, c.msg)
			continue
		}
		if got := exitCode(err); got != exitUsage {
			t.Errorf("%s: exit %d, want %d", c.name, got, exitUsage)
		}
	}
}
