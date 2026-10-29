package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/internal/hunt"
	"github.com/trannghiach/azhaq/internal/takeover"
	"github.com/trannghiach/azhaq/types"
)

// cmdHunt ranks a workspace's surface: where to look first, and why.
func cmdHunt(args []string) error {
	fs := newFlags("hunt")
	db := fs.String("db", "", "workspace database (default: the last run's)")
	var roles stringsFlag
	fs.Var(&roles, "roles", "the JSONL `azhaq roles -json` printed: rows where one role reached another's data rank first (repeatable)")
	since := fs.Duration("since", 7*24*time.Hour, "first seen within this long is new: a bonus, never the reason a row ranks")
	limit := fs.Int("limit", 25, "rows at most, best first")
	asJSON := fs.Bool("json", false, "one JSON object per row, and the summary as JSON on stderr")
	if err := parse(fs, args); err != nil {
		return err
	}
	path := *db
	if path == "" {
		if path = readLastDB(); path == "" {
			return usagef("give -db FILE")
		}
	}
	if *limit < 1 {
		return usagef("-limit: need at least 1")
	}
	var rows []hunt.RoleRow
	for _, f := range roles {
		fh, err := os.Open(f)
		if err != nil {
			return err
		}
		rs, err := hunt.ReadRoles(fh)
		fh.Close()
		if err != nil {
			return fmt.Errorf("-roles %s: %v", f, err)
		}
		rows = append(rows, rs...)
	}
	g, err := readGraph(path)
	if err != nil {
		return err
	}
	in := hunt.Input{DB: path, Rows: g.rows, Obs: g.obs, Roles: rows, Now: time.Now(), Since: *since}
	for _, s := range secretRows(g.obs) {
		in.Secrets = append(in.Secrets, hunt.Secret{Kind: s.Kind, Severity: s.Severity, Where: s.Where})
	}
	ents := make([]types.Entity, 0, len(g.rows))
	for _, r := range g.rows {
		ents = append(ents, r.Entity)
	}
	for _, t := range takeovers(ents, g.obs) {
		in.Takeovers = append(in.Takeovers, hunt.Takeover{Host: t.Host, Strong: t.Strength == "strong", Detail: takeoverDetail(t.Finding)})
	}
	list := hunt.Build(in)
	matched := len(list)
	if len(list) > *limit {
		list = list[:*limit]
	}
	enc := json.NewEncoder(os.Stdout)
	for _, r := range list {
		if *asJSON {
			if err := enc.Encode(r); err != nil {
				return err
			}
			continue
		}
		parts := make([]string, len(r.Reasons))
		for i, x := range r.Reasons {
			parts[i] = x.Signal + ": " + x.Detail
		}
		fmt.Printf("%3d  %3d  %s  %s  → next: %s\n", r.Rank, r.Score, r.Key, strings.Join(parts, "; "), r.Next)
	}
	rep := newReport("hunt")
	rep.what = "rows"
	rep.Results = len(list)
	rep.DB = path
	if matched > len(list) {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d rows have a signal; -limit %d printed the first %d (best first)", matched, *limit, len(list)))
	}
	return rep.finish(*asJSON, false)
}

func takeoverDetail(f takeover.Finding) string {
	d := f.Service + " takeover, " + f.Strength
	if f.Target != "" {
		d += ": CNAME " + f.Target
	}
	if f.Evidence != "" {
		d += " (" + f.Evidence + ")"
	}
	return d
}
