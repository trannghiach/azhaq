//go:build ignore

// strip writes the part of wappalyzergo's fingerprints_data.json that the
// passive matcher reads: the js and dom rules need a browser and are left
// out. To update, from this directory:
//
//	go run strip.go $(go env GOMODCACHE)/github.com/projectdiscovery/wappalyzergo@vX.Y.Z/fingerprints_data.json
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var data struct {
		Apps map[string]map[string]json.RawMessage `json:"apps"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, app := range data.Apps {
		delete(app, "js")
		delete(app, "dom")
	}
	out, err := json.Marshal(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile("fingerprints_data.json", out, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
