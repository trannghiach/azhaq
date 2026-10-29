package main

import (
	"os"
	"testing"
)

// The name history (subcol) is per user: tests keep theirs in a temp dir.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "azhaq-test-data-")
	if err != nil {
		panic(err)
	}
	os.Setenv("AZHAQ_DATA_DIR", dir)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
