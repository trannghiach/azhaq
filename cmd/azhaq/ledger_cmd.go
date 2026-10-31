package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/internal/ledger"
)

// cmdLedger reads a ledger a run wrote: checks its chain, summarizes it,
// or turns it into CSV for a client's report.
func cmdLedger(args []string) error {
	fs := newFlags("ledger")
	verify := fs.String("verify", "", "check the ledger's chain of hashes and its seal: exit 0 when intact and sealed, 3 naming the first line that is not intact, or the lines after the last seal")
	seal := fs.String("seal", "", "with -verify: a seal hash kept where the run's own files are not (or a file of one per line, or the JSON lines -seal-to writes) that must be one of the chain's seals; without it, -verify cannot tell the file from one with lines removed and the rest re-chained to look intact")
	summary := fs.String("summary", "", "count the ledger's requests, connections and queries by class, kind, host and method, with the first and last time")
	csvOut := fs.String("csv", "", "print the ledger as CSV")
	asJSON := fs.Bool("json", false, "with -summary: one JSON object")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *seal != "" && *verify == "" {
		return usagef("-seal works with -verify")
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
		return cmdLedgerVerify(*verify, *seal)
	case *summary != "":
		return ledgerSummary(*summary, *asJSON)
	}
	return ledgerCSV(*csvOut)
}

func cmdLedgerVerify(path, seal string) error {
	var want []string
	if seal != "" {
		var err error
		if want, err = readSealWant(seal); err != nil {
			return err
		}
	}
	c, matched, err := ledger.VerifySeal(path, want)
	switch {
	case c.BadLine > 0:
		fmt.Printf("%s: BROKEN at line %d (%d entries before it are intact)\n", path, c.BadLine, c.Entries)
		return exitErr{code: exitPartial, msg: err.Error()}
	case err != nil:
		return err
	case c.Unsealed > 0:
		fmt.Printf("%s: %d entries, the chain is intact, NOT SEALED: the last %d were written after the last seal\n", path, c.Entries, c.Unsealed)
		return exitErr{code: exitPartial, msg: "a run that did not end (killed, crashed or still running) or lines cut from the end: the file cannot show it holds everything that run sent"}
	case seal != "" && matched == "":
		fmt.Printf("%s: %d entries from %d runs, the chain is intact, but none of its seals is the one given\n", path, c.Entries, c.Seals)
		return exitErr{code: exitPartial, msg: "the given seal is not in the chain: lines may have been removed and the rest re-chained to look intact (recomputing the chain alone cannot catch that; only a seal kept apart from this file can)"}
	}
	if seal != "" {
		fmt.Printf("%s: %d entries from %d runs, the chain is intact and sealed; the seal given is in it\n", path, c.Entries, c.Seals)
		return nil
	}
	fmt.Printf("%s: %d entries from %d runs, the chain is intact and sealed\n  last seal %s (azhaq ledger -verify %s -seal %s checks that exact seal is still there)\n", path, c.Entries, c.Seals, c.Seal, path, c.Seal)
	return nil
}

// readSealWant is the seal hashes -seal names: the value itself, or, when
// it is a file, one per line, each either bare or a {"seal": "…"} line as
// -seal-to writes (the "time", "ledger" and "entries" alongside it are not
// needed to tell the hashes apart).
func readSealWant(spec string) ([]string, error) {
	if _, err := os.Stat(spec); err != nil {
		return []string{spec}, nil
	}
	raw, err := os.ReadFile(spec)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec struct {
			Seal string `json:"seal"`
		}
		if json.Unmarshal([]byte(line), &rec) == nil && rec.Seal != "" {
			out = append(out, rec.Seal)
			continue
		}
		out = append(out, line)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no seal found in the file", spec)
	}
	return out, nil
}

func ledgerSummary(path string, asJSON bool) error {
	byClass, byKind, byHost, byMethod := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	byRule := map[string]int{}
	var first, last time.Time
	n := 0
	err := ledger.Read(path, func(e ledger.Entry) error {
		n++
		byClass[entryClass(e)]++
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
			"classes": byClass, "kinds": byKind, "hosts": byHost, "methods": byMethod, "rules": byRule})
		fmt.Println(string(raw))
		return nil
	}
	fmt.Printf("%s: %d requests, connections and queries\n", path, n)
	if n == 0 {
		return nil
	}
	fmt.Printf("  first  %s\n  last   %s\n", first.Format(time.RFC3339), last.Format(time.RFC3339))
	for _, g := range []struct {
		title string
		m     map[string]int
	}{{"by class", byClass}, {"by kind", byKind}, {"by method", byMethod}, {"by host", byHost}, {"by scope rule", byRule}} {
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

// entryClass is what an entry was sent to; a ledger from before classes
// holds targets only.
func entryClass(e ledger.Entry) string {
	if e.Class == "" {
		return ledger.ClassTarget
	}
	return e.Class
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
	_ = w.Write([]string{"seq", "time", "class", "kind", "method", "target", "host", "rule", "collector", "hash"})
	err := ledger.Read(path, func(e ledger.Entry) error {
		return w.Write([]string{strconv.FormatInt(e.Seq, 10), e.Time.Format(time.RFC3339Nano), entryClass(e), e.Kind, e.Method, e.Target, e.Host, e.Rule, e.Collector, e.Hash})
	})
	w.Flush()
	if err != nil {
		return err
	}
	return w.Error()
}
