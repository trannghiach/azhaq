package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/trannghiach/azhaq/internal/ledger"
)

// cmdLedger reads a ledger a run wrote: checks its chain, summarizes it,
// or turns it into CSV for a client's report.
func cmdLedger(args []string) error {
	fs := newFlags("ledger")
	verify := fs.String("verify", "", "check the ledger's chain of hashes: exit 0 when intact, 3 naming the first line that is not")
	summary := fs.String("summary", "", "count the ledger's requests and connections by kind, host and method, with the first and last time")
	csvOut := fs.String("csv", "", "print the ledger as CSV")
	asJSON := fs.Bool("json", false, "with -summary: one JSON object")
	if err := parse(fs, args); err != nil {
		return err
	}
	given := 0
	for _, v := range []string{*verify, *summary, *csvOut} {
		if v != "" {
			given++
		}
	}
	if given != 1 {
		return usagef("give one of -verify FILE, -summary FILE or -csv FILE")
	}
	switch {
	case *verify != "":
		n, bad, err := ledger.Verify(*verify)
		switch {
		case bad > 0:
			fmt.Printf("%s: BROKEN at line %d (%d entries before it are intact)\n", *verify, bad, n)
			return exitErr{code: exitPartial, msg: err.Error()}
		case err != nil:
			return err
		}
		fmt.Printf("%s: %d entries, the chain is intact\n", *verify, n)
		return nil
	case *summary != "":
		return ledgerSummary(*summary, *asJSON)
	}
	return ledgerCSV(*csvOut)
}

func ledgerSummary(path string, asJSON bool) error {
	byKind, byHost, byMethod := map[string]int{}, map[string]int{}, map[string]int{}
	byRule := map[string]int{}
	var first, last time.Time
	n := 0
	err := ledger.Read(path, func(e ledger.Entry) error {
		n++
		byKind[e.Kind]++
		byHost[e.Host]++
		if e.Method != "" {
			byMethod[e.Method]++
		}
		byRule[e.Rule]++
		if first.IsZero() || e.Time.Before(first) {
			first = e.Time
		}
		if e.Time.After(last) {
			last = e.Time
		}
		return nil
	})
	if err != nil {
		return err
	}
	if asJSON {
		raw, _ := json.Marshal(map[string]any{"file": path, "entries": n, "first": first, "last": last,
			"kinds": byKind, "hosts": byHost, "methods": byMethod, "rules": byRule})
		fmt.Println(string(raw))
		return nil
	}
	fmt.Printf("%s: %d requests and connections\n", path, n)
	if n == 0 {
		return nil
	}
	fmt.Printf("  first  %s\n  last   %s\n", first.Format(time.RFC3339), last.Format(time.RFC3339))
	for _, g := range []struct {
		title string
		m     map[string]int
	}{{"by kind", byKind}, {"by method", byMethod}, {"by host", byHost}, {"by scope rule", byRule}} {
		fmt.Println("  " + g.title)
		for _, k := range sortedByCount(g.m) {
			name := k
			if name == "" {
				name = "(none)"
			}
			fmt.Printf("    %-8d %s\n", g.m[k], name)
		}
	}
	return nil
}

// sortedByCount lists the keys of m, most frequent first.
func sortedByCount(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	return keys
}

func ledgerCSV(path string) error {
	w := csv.NewWriter(os.Stdout)
	_ = w.Write([]string{"seq", "time", "kind", "method", "target", "host", "rule", "collector", "hash"})
	err := ledger.Read(path, func(e ledger.Entry) error {
		return w.Write([]string{strconv.FormatInt(e.Seq, 10), e.Time.Format(time.RFC3339Nano), e.Kind, e.Method, e.Target, e.Host, e.Rule, e.Collector, e.Hash})
	})
	w.Flush()
	if err != nil {
		return err
	}
	return w.Error()
}
