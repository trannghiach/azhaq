package main

import (
	"os"
	"testing"

	"github.com/trannghiach/azhaq/internal/collectors/subcol"
)

// The name history (subcol) is per user: tests keep theirs in a temp dir.
func TestMain(m *testing.M) {
	if os.Getenv("AZHAQ_TEST_AS_MAIN") == "1" {
		main() // a test that needs the process, with its real stderr, runs this binary again
	}
	dir, err := os.MkdirTemp("", "azhaq-test-data-")
	if err != nil {
		panic(err)
	}
	os.Setenv("AZHAQ_DATA_DIR", dir)
	subcol.DatabaseOff() // no test reaches crt.sh
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
