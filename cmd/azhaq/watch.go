package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/internal/notify"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// change set between the last two runs of a workspace, in the terms a
// person watching a target cares about.
type changes struct {
	DB        string    `json:"db"`
	Run       time.Time `json:"run"`
	Previous  time.Time `json:"previous,omitempty"`
	Baseline  bool      `json:"baseline,omitempty"` // the first run: everything is new
	Hosts     []string  `json:"hosts,omitempty"`    // new names that resolve
	Services  []string  `json:"services,omitempty"` // new web services, "url [status] title"
	URLs      []string  `json:"urls,omitempty"`     // other new URLs
	Ports     []string  `json:"ports,omitempty"`    // "host: 22,80,8443" where the open set changed
	GoneHosts []string  `json:"gone_hosts,omitempty"`
	GoneSvcs  []string  `json:"gone_services,omitempty"`
}

func (c changes) any() bool {
	return len(c.Hosts)+len(c.Services)+len(c.URLs)+len(c.Ports)+len(c.GoneHosts)+len(c.GoneSvcs) > 0
}

// cmdWatch runs the same target into a workspace again and again and
// reports what changed: azhaq watch -db acme.db -every 24h -notify URL -- -scope acme.csv
func cmdWatch(args []string) error {
	fs := newFlags("watch")
	db := fs.String("db", "", "workspace database (required)")
	every := fs.Duration("every", 0, "run again after this long (default: run once, for cron)")
	var hooks stringsFlag
	fs.Var(&hooks, "notify", "webhook for changes: Slack, Discord, Telegram (…/sendMessage?chat_id=…) or any JSON endpoint (repeatable)")
	notifyCmd := fs.String("notify-cmd", "", "command that gets the change set as JSON on stdin")
	always := fs.Bool("always", false, "notify after every run, not only when something changed")
	jsonOut := fs.Bool("json", false, "print the change set as JSON")
	if err := parse(fs, args); err != nil {
		return err
	}
	runArgs := fs.Args()
	if len(runArgs) > 0 && runArgs[0] == "--" {
		runArgs = runArgs[1:]
	}
	if *db == "" || len(runArgs) == 0 {
		return fmt.Errorf("usage: azhaq watch -db WORKSPACE.db [-every 24h] [-notify URL] -- RUN OPTIONS")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	for {
		if _, err := runEmbedded(append(append([]string(nil), runArgs...), "-db", *db, "-quiet")); err != nil {
			return err
		}
		ch, err := diffRuns(*db)
		if err != nil {
			return err
		}
		if *jsonOut {
			_ = json.NewEncoder(os.Stdout).Encode(ch)
		} else {
			fmt.Print(ch.text())
		}
		if ch.any() || *always {
			for _, h := range hooks {
				if err := notify.Send(ctx, h, ch.text(), ch); err != nil {
					fmt.Fprintf(os.Stderr, "azhaq watch: %v\n", err)
				}
			}
			if *notifyCmd != "" {
				raw, _ := json.Marshal(ch)
				cmd := exec.CommandContext(ctx, "/bin/sh", "-c", *notifyCmd)
				cmd.Stdin = strings.NewReader(string(raw) + "\n")
				cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
				if err := cmd.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "azhaq watch: -notify-cmd: %v\n", err)
				}
			}
		}
		if *every <= 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(*every):
		}
	}
}

// diffRuns compares the last two runs of a workspace.
func diffRuns(path string) (changes, error) {
	old, err := store.OpenExisting(path)
	if err != nil {
		return changes{}, err
	}
	defer old.Close()
	neu, err := store.OpenExisting(path)
	if err != nil {
		return changes{}, err
	}
	defer neu.Close()
	runs, err := old.Runs()
	if err != nil || len(runs) == 0 {
		return changes{}, err
	}
	last := runs[len(runs)-1]
	neu.UseRun(last.ID)
	ch := changes{DB: path, Run: last.Started}
	if len(runs) == 1 {
		ch.Baseline = true
		old.UseRun("\x00none") // a run that saw nothing: everything is added
	} else {
		prev := runs[len(runs)-2]
		ch.Previous = prev.Started
		old.UseRun(prev.ID)
	}
	d, err := store.Compare(old, neu)
	if err != nil {
		return ch, err
	}
	newFacts := factsByEntity(neu)
	oldFacts := factsByEntity(old)
	for _, e := range d.Added {
		switch e.Type {
		case types.TypeHostname:
			if ips := newFacts[e.ID].ips; len(ips) > 0 {
				ch.Hosts = append(ch.Hosts, e.Key+" ("+strings.Join(ips, ", ")+")")
			}
		case types.TypeURL:
			f := newFacts[e.ID]
			switch {
			case f.catchAll:
			case f.status != 0 && isFront(e.Key):
				ch.Services = append(ch.Services, strings.TrimSpace(fmt.Sprintf("%s [%d] %s", e.Key, f.status, f.title)))
			case f.role != "script" && f.role != "asset" && f.role != "sourcemap":
				ch.URLs = append(ch.URLs, e.Key)
			}
		}
	}
	for _, e := range d.Removed {
		switch {
		case e.Type == types.TypeHostname && len(oldFacts[e.ID].ips) > 0:
			ch.GoneHosts = append(ch.GoneHosts, e.Key)
		case e.Type == types.TypeURL && oldFacts[e.ID].status != 0 && isFront(e.Key):
			ch.GoneSvcs = append(ch.GoneSvcs, e.Key)
		}
	}
	// Ports: the open set of a host that was scanned in both runs.
	for id, f := range newFacts {
		if f.ports == nil {
			continue
		}
		if o := oldFacts[id]; o.ports != nil && strings.Join(o.ports, ",") != strings.Join(f.ports, ",") {
			ch.Ports = append(ch.Ports, f.host+": "+strings.Join(f.ports, ","))
		}
	}
	for _, xs := range [][]string{ch.Hosts, ch.Services, ch.URLs, ch.Ports, ch.GoneHosts, ch.GoneSvcs} {
		sort.Strings(xs)
	}
	return ch, nil
}

type facts struct {
	ips         []string
	status      int
	title, role string
	catchAll    bool
	ports       []string
	host        string
}

func factsByEntity(st *store.Store) map[string]facts {
	obs, _ := st.Observations()
	out := map[string]facts{}
	for _, o := range obs {
		var p map[string]any
		if json.Unmarshal(o.Payload, &p) != nil {
			continue
		}
		f := out[o.EntityID]
		switch o.Collector {
		case "azhaq-dns":
			if ips, ok := p["ips"].([]any); ok && p["wildcard"] == nil {
				for _, ip := range ips {
					f.ips = append(f.ips, fmt.Sprint(ip))
				}
			}
		case "azhaq-http":
			if st, ok := p["status"].(float64); ok && f.status == 0 {
				f.status = int(st)
			}
			if t, ok := p["title"].(string); ok && f.title == "" {
				f.title = t
			}
			if p["catchall"] == true {
				f.catchAll = true
			}
		case "azhaq-ports":
			f.host, _ = p["host"].(string)
			f.ports = []string{}
			if open, ok := p["open"].([]any); ok {
				for _, x := range open {
					f.ports = append(f.ports, fmt.Sprint(x))
				}
			}
		}
		if r, ok := p["role"].(string); ok && f.role == "" {
			f.role = r
		}
		out[o.EntityID] = f
	}
	return out
}

func isFront(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Path == "" || u.Path == "/")
}

func (c changes) text() string {
	var b strings.Builder
	when := c.Run.Local().Format("2006-01-02 15:04")
	if c.Baseline {
		fmt.Fprintf(&b, "azhaq watch %s: first run %s\n", c.DB, when)
	} else {
		fmt.Fprintf(&b, "azhaq watch %s: %s against %s\n", c.DB, when, c.Previous.Local().Format("2006-01-02 15:04"))
	}
	if !c.any() {
		b.WriteString("no change\n")
		return b.String()
	}
	section := func(sign, what string, xs []string) {
		if len(xs) == 0 {
			return
		}
		fmt.Fprintf(&b, "%s %d %s\n", sign, len(xs), what)
		for i, x := range xs {
			if i == 20 {
				fmt.Fprintf(&b, "    … and %d more\n", len(xs)-20)
				break
			}
			fmt.Fprintf(&b, "    %s\n", x)
		}
	}
	section("+", "hostnames that resolve", c.Hosts)
	section("+", "web services", c.Services)
	section("+", "URLs", c.URLs)
	section("~", "hosts whose open ports changed", c.Ports)
	section("-", "hostnames gone", c.GoneHosts)
	section("-", "web services gone", c.GoneSvcs)
	return b.String()
}

// cmdNew lists what a workspace first saw within a window, for triage.
func cmdNew(args []string) error {
	fs := newFlags("new")
	db := fs.String("db", "", "workspace database (required)")
	since := fs.Duration("since", 7*24*time.Hour, "first seen within this long")
	jsonOut := fs.Bool("json", false, "JSONL")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *db == "" {
		return fmt.Errorf("give -db WORKSPACE.db")
	}
	st, err := store.OpenExisting(*db)
	if err != nil {
		return err
	}
	defer st.Close()
	ents, err := st.Entities()
	if err != nil {
		return err
	}
	f := factsByEntity(st)
	cut := time.Now().Add(-*since)
	sort.Slice(ents, func(i, j int) bool {
		if ents[i].Type != ents[j].Type {
			return ents[i].Type < ents[j].Type
		}
		return ents[i].FirstSeen.After(ents[j].FirstSeen)
	})
	enc := json.NewEncoder(os.Stdout)
	for _, e := range ents {
		if e.FirstSeen.Before(cut) || (e.Type != types.TypeHostname && e.Type != types.TypeURL && e.Type != types.TypeIPAddress) {
			continue
		}
		x := f[e.ID]
		if e.Type == types.TypeURL && x.catchAll {
			continue
		}
		if *jsonOut {
			row := map[string]any{"type": e.Type, "key": e.Key, "first_seen": e.FirstSeen, "last_seen": e.LastSeen}
			if len(x.ips) > 0 {
				row["ips"] = x.ips
			}
			if x.status != 0 {
				row["status"], row["title"] = x.status, x.title
			}
			if err := enc.Encode(row); err != nil {
				return err
			}
			continue
		}
		detail := ""
		switch {
		case len(x.ips) > 0:
			detail = strings.Join(x.ips, ", ")
		case x.status != 0:
			detail = strings.TrimSpace(fmt.Sprintf("[%d] %s", x.status, x.title))
		}
		fmt.Printf("%s  %-9s %s  %s\n", e.FirstSeen.Local().Format("2006-01-02 15:04"), e.Type, e.Key, detail)
	}
	return nil
}
