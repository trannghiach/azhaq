package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/store"
)

// role is one session: a name and the headers its requests carry. A role
// without headers is anonymous.
type role struct {
	name    string
	headers []string
}

// roleRow is an endpoint whose answer depends on the session.
type roleRow struct {
	URL    string         `json:"url"`
	Status map[string]int `json:"status"` // 0: not reached in that role
}

// cmdRoles runs the same seeds once per session and prints the endpoints
// whose status differs between sessions:
//
//	azhaq roles -role anon -role 'user=Authorization: Bearer …' -- -url https://app/
func cmdRoles(args []string) error {
	fs := flag.NewFlagSet("roles", flag.ContinueOnError)
	var specs stringsFlag
	fs.Var(&specs, "role", "NAME, or NAME=Header: value (repeat a name to add headers; a role with none is anonymous)")
	dir := fs.String("dir", "", "directory for one database per role (default: azhaq-roles-<time>)")
	jsonl := fs.Bool("jsonl", false, "print one JSON row per endpoint")
	if err := fs.Parse(args); err != nil {
		return err
	}
	runArgs := fs.Args()
	if len(runArgs) > 0 && runArgs[0] == "--" {
		runArgs = runArgs[1:]
	}
	roles, err := parseRoles(specs)
	if err != nil {
		return err
	}
	if len(roles) < 2 {
		return fmt.Errorf("need at least two -role, for example -role anon -role 'user=Cookie: session=…'")
	}
	if len(runArgs) == 0 {
		return fmt.Errorf("give the run options after --, for example -- -url https://app.example.com/")
	}
	for _, a := range runArgs {
		switch strings.TrimLeft(strings.SplitN(a, "=", 2)[0], "-") {
		case "db", "cookie", "header", "json", "quiet":
			return fmt.Errorf("roles sets -%s itself; leave it out of the run options", strings.TrimLeft(a, "-"))
		}
	}
	if *dir == "" {
		*dir = "azhaq-roles-" + time.Now().Format("20060102-150405")
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		return err
	}

	statuses := map[string]map[string]int{}
	for _, r := range roles {
		db := filepath.Join(*dir, r.name+".db")
		args := append([]string{"-db", db, "-quiet"}, runArgs...)
		for _, h := range r.headers {
			args = append(args, "-header", h)
		}
		fmt.Fprintf(os.Stderr, "azhaq roles: %s\n", r.name)
		// Each run's summary goes to stderr; stdout carries the table.
		stdout := os.Stdout
		os.Stdout = os.Stderr
		err := cmdRun(args)
		os.Stdout = stdout
		if err != nil {
			return fmt.Errorf("role %s: %w", r.name, err)
		}
		got, err := endpointStatus(db)
		if err != nil {
			return err
		}
		statuses[r.name] = got
	}

	rows := roleDiff(roles, statuses)
	if *jsonl {
		enc := json.NewEncoder(os.Stdout)
		for _, row := range rows {
			if err := enc.Encode(row); err != nil {
				return err
			}
		}
		return nil
	}
	names := make([]string, len(roles))
	for i, r := range roles {
		names[i] = r.name
	}
	fmt.Printf("roles  %s  (%d endpoints differ; databases in %s)\n", strings.Join(names, "  "), len(rows), *dir)
	for _, row := range rows {
		cells := make([]string, len(roles))
		for i, r := range roles {
			cells[i] = "-"
			if s := row.Status[r.name]; s != 0 {
				cells[i] = fmt.Sprint(s)
			}
		}
		fmt.Printf("  %s  %s\n", strings.Join(cells, " → "), row.URL)
	}
	return nil
}

func parseRoles(specs []string) ([]role, error) {
	var out []role
	idx := map[string]int{}
	for _, s := range specs {
		name, header, hasHeader := strings.Cut(s, "=")
		name = strings.TrimSpace(name)
		if name == "" || strings.ContainsAny(name, `/\ `) {
			return nil, fmt.Errorf("-role %q: want NAME or NAME=Header: value", s)
		}
		i, ok := idx[name]
		if !ok {
			i = len(out)
			idx[name] = i
			out = append(out, role{name: name})
		}
		if hasHeader {
			if k, _, ok := strings.Cut(header, ":"); !ok || strings.TrimSpace(k) == "" {
				return nil, fmt.Errorf("-role %q: the header must be K: V", s)
			}
			out[i].headers = append(out[i].headers, strings.TrimSpace(header))
		}
	}
	return out, nil
}

// endpointStatus is the status each URL answered with in one run: the
// first status recorded for it, catch-all answers left out.
func endpointStatus(db string) (map[string]int, error) {
	st, err := store.Open(db)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	obs, err := st.Observations()
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	for _, o := range obs {
		var p struct {
			URL      string `json:"url"`
			Status   int    `json:"status"`
			CatchAll bool   `json:"catchall"`
		}
		if json.Unmarshal(o.Payload, &p) != nil || p.URL == "" || p.Status == 0 || p.CatchAll {
			continue
		}
		if _, ok := out[p.URL]; !ok {
			out[p.URL] = p.Status
		}
	}
	return out, nil
}

// roleDiff keeps the URLs whose status is not the same in every role.
func roleDiff(roles []role, statuses map[string]map[string]int) []roleRow {
	urls := map[string]bool{}
	for _, m := range statuses {
		for u := range m {
			urls[u] = true
		}
	}
	var rows []roleRow
	for u := range urls {
		row := roleRow{URL: u, Status: map[string]int{}}
		same := true
		first := statuses[roles[0].name][u]
		for _, r := range roles {
			s := statuses[r.name][u]
			row.Status[r.name] = s
			if s != first {
				same = false
			}
		}
		if !same {
			rows = append(rows, row)
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].URL < rows[j].URL })
	return rows
}
