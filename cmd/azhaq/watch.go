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
	"github.com/trannghiach/azhaq/internal/webextract"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// change set between the last two runs of a workspace, in the terms a
// person watching a target cares about.
type changes struct {
	DB        string        `json:"db"`
	Run       time.Time     `json:"run"`
	Previous  time.Time     `json:"previous,omitempty"`
	Baseline  bool          `json:"baseline,omitempty"` // the first run: everything is new
	Hosts     []string      `json:"hosts,omitempty"`    // new names that resolve
	Services  []string      `json:"services,omitempty"` // new web services, "url [status] title"
	URLs      []string      `json:"urls,omitempty"`     // other new URLs
	Ports     []string      `json:"ports,omitempty"`    // "host: 22,80,8443" where the open set changed
	Changed   []string      `json:"changed,omitempty"`  // "url: [200] old title → [403] new title"
	GoneHosts []string      `json:"gone_hosts,omitempty"`
	GoneSvcs  []string      `json:"gone_services,omitempty"`
	GoneURLs  []string      `json:"gone_urls,omitempty"`
	Routes    []routeChange `json:"routes,omitempty"` // API routes, methods and body names the scripts call that changed
}

func (c changes) any() bool {
	return len(c.Hosts)+len(c.Services)+len(c.URLs)+len(c.Ports)+len(c.Changed)+len(c.GoneHosts)+len(c.GoneSvcs)+len(c.GoneURLs)+len(c.Routes) > 0
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
		rep, err := runEmbeddedAs(append(append([]string(nil), runArgs...), "-db", *db, "-quiet"), *jsonOut)
		if err != nil {
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
			// The run's exit code: 3 when something failed, 4 when a
			// limit stopped it, whatever changed.
			return rep.err()
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
	if !ch.Baseline {
		if ch.Routes, err = diffRoutes(old, neu); err != nil {
			return ch, err
		}
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
		f := oldFacts[e.ID]
		switch {
		case e.Type == types.TypeHostname && len(f.ips) > 0:
			ch.GoneHosts = append(ch.GoneHosts, e.Key)
		case e.Type == types.TypeURL && f.status != 0 && isFront(e.Key):
			ch.GoneSvcs = append(ch.GoneSvcs, e.Key)
		case e.Type == types.TypeURL && f.status != 0 && !f.catchAll && f.role != "script" && f.role != "asset" && f.role != "sourcemap":
			ch.GoneURLs = append(ch.GoneURLs, e.Key)
		}
	}
	// What answered in both runs, differently: a page that now needs a
	// login, a service that changed its title.
	for id, nf := range newFacts {
		of, ok := oldFacts[id]
		if !ok || nf.status == 0 || of.status == 0 || nf.catchAll || of.catchAll {
			continue
		}
		switch {
		case nf.status != of.status || nf.title != of.title:
			ch.Changed = append(ch.Changed, fmt.Sprintf("%s: [%d] %s → [%d] %s", nf.url, of.status, of.title, nf.status, nf.title))
		case nf.items > 0 && of.items > 0 && nf.items != of.items:
			// An API listing that grew or shrank: a user, a book, an order.
			ch.Changed = append(ch.Changed, fmt.Sprintf("%s: [%d] %d items → [%d] %d items", nf.url, of.status, of.items-1, nf.status, nf.items-1))
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
	ch.URLs = withoutRoutes(ch.URLs, ch.Routes, "new")
	ch.GoneURLs = withoutRoutes(ch.GoneURLs, ch.Routes, "gone")
	for _, xs := range [][]string{ch.Hosts, ch.Services, ch.URLs, ch.Ports, ch.Changed, ch.GoneHosts, ch.GoneSvcs, ch.GoneURLs} {
		sort.Strings(xs)
	}
	return ch, nil
}

type facts struct {
	ips         []string
	status      int
	url         string
	title, role string
	catchAll    bool
	ports       []string
	host        string
	items       int // items of a JSON listing, plus one; 0 when it is not one
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
				f.url, _ = p["url"].(string)
			}
			if t, ok := p["title"].(string); ok && f.title == "" {
				f.title = t
			}
			if n, ok := p["json_items"].(float64); ok {
				f.items = int(n) + 1 // stored plus one: zero means not a listing
			}
			if p["catchall"] == true {
				f.catchAll = true
			}
		case "azhaq-ports":
			if n, _ := p["scanned"].(float64); n == 0 {
				break // not scanned (no IPv6 route): nothing to compare
			}
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

// isStatic: a script, style sheet or image, which no one triages.
func isStatic(raw string) bool {
	c := webextract.ClassifyURL(raw)
	return c == "asset" || c == "script"
}

func isFront(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Path == "" || u.Path == "/")
}

func (c changes) text() string {
	var b strings.Builder
	when := c.Run.Local().Format("2006-01-02 15:04:05")
	if c.Baseline {
		fmt.Fprintf(&b, "azhaq watch %s: first run %s\n", c.DB, when)
	} else {
		fmt.Fprintf(&b, "azhaq watch %s: %s against %s\n", c.DB, when, c.Previous.Local().Format("2006-01-02 15:04:05"))
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
	section("~", "API routes", routeLines(c.Routes))
	section("~", "hosts whose open ports changed", c.Ports)
	section("~", "pages that answer differently", c.Changed)
	section("-", "hostnames gone", c.GoneHosts)
	section("-", "web services gone", c.GoneSvcs)
	section("-", "URLs gone", c.GoneURLs)
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
	// What the newest run still saw: a page removed since is not new.
	if runs, err := st.Runs(); err == nil && len(runs) > 0 {
		st.UseRun(runs[len(runs)-1].ID)
	}
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
		if e.Type == types.TypeURL && (x.catchAll || x.role == "script" || x.role == "asset" || x.role == "sourcemap" || isStatic(e.Key)) {
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
		fmt.Printf("%s  %-9s %s  %s\n", e.FirstSeen.Local().Format("2006-01-02 15:04:05"), e.Type, e.Key, detail)
	}
	return nil
}
