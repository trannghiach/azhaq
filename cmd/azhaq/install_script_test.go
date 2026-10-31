package main

import (
	"os/exec"
	"runtime"
	"testing"
)

// scripts/install.sh run against a fake release on disk: it requires the
// signature when asked, stops before a download when cosign is missing, and
// names a missing tool first. No network.
func TestInstallScriptOffline(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a shell script")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip(err)
	}
	out, err := exec.Command("sh", "../../scripts/install_offline_test.sh").CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
}
