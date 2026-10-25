package main

import (
	"fmt"
	"os"
	"text/tabwriter"
)

func printReport() {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if len(rec.Apps) > 0 {
		fmt.Fprintln(w, "\napps\tazhaq routes\tknown\tshell\ttime\tRSS\tkatana routes\tknown\tshell\ttime\tRSS")
		for _, a := range rec.Apps {
			fmt.Fprintf(w, "%s\t%d\t%s\t%d\t%.1fs\t%.0fMB\t%d\t%s\t%d\t%.1fs\t%.0fMB\n", a.Name,
				a.Azhaq.Routes, known(a.Azhaq), a.Azhaq.Shell, a.Azhaq.Seconds, a.Azhaq.RSSMB,
				a.Katana.Routes, known(a.Katana), a.Katana.Shell, a.Katana.Seconds, a.Katana.RSSMB)
		}
		for _, a := range rec.Apps {
			if f := a.Ffuf; f != nil {
				fmt.Fprintf(w, "\nwordlist (%d words)\tazhaq hits\tshell\tffuf -ac hits\tshell\tshared\tffuf time\n", f.Words)
				fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%d\t%d\t%.1fs\n", a.Name, f.AzhaqHits, f.AzhaqShell, f.FfufHits, f.FfufShell, f.Shared, f.Seconds)
			}
		}
	}
	if len(rec.Domains) > 0 {
		fmt.Fprintln(w, "\ndomains (passive)\tlive\tazhaq live\tnames\ttime\tsubfinder live\tnames\ttime\tshared\tazhaq URLs\tgau URLs")
		for _, d := range rec.Domains {
			fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%.0fs\t%d\t%d\t%.0fs\t%d\t%d\t%d\n", d.Domain, d.Live,
				d.AzhaqLive, d.AzhaqNames, d.AzhaqSeconds, d.SubfinderLive, d.SubfinderNames, d.SubSeconds,
				d.SharedLive, d.AzhaqURLs, d.GauURLs)
		}
		fmt.Fprintln(w, "\nsources\tsubdomain sources\tarchives")
		for _, d := range rec.Domains {
			fmt.Fprintf(w, "%s\t%s\t%s\n", d.Domain, d.CT, d.CDX)
		}
	}
	if b := rec.Brute; b != nil {
		fmt.Fprintf(w, "\nactive DNS (%s)\tazhaq\tdnsx\tshared\tazhaq time\tdnsx time\n", b.Domain)
		fmt.Fprintf(w, "brute force, %d words\t%d\t%d\t%d\t%.1fs\t%.1fs\n", b.Words, b.AzhaqFound, b.DnsxFound, b.Shared, b.AzhaqSeconds, b.DnsxSeconds)
		fmt.Fprintf(w, "permutations\t%d\t%d (alterx)\t%d\t\t\n", b.PermuteAzhaq, b.PermuteAlterx, b.PermuteShared)
		fmt.Fprintf(w, "wildcard zone, %d words, %d real\t%d found, %d fake\t%d unfiltered\t\t\t\n", b.WildcardWords, b.WildcardReal, b.WildcardAzhaq, b.WildcardFake, b.WildcardNoWild)
	}
	if p := rec.Probe; p != nil {
		fmt.Fprintf(w, "\nprobe (%d hosts)\tanswered\tshared\tstatus\ttitle\ttech\tall\tfavicon\tcdn\ttime\n", p.Hosts)
		fmt.Fprintf(w, "azhaq\t%d\t%d\t%d\t%d\t%d\t%d\t%d/%d\t%d/%d\t%.1fs\n", p.AzhaqAnswered, p.Shared, p.Status, p.Title, p.Tech, p.All, p.FaviconAgree, p.FaviconBoth, p.CDNAgree, p.CDNHttpx, p.AzhaqSeconds)
		fmt.Fprintf(w, "httpx\t%d\t\t\t\t\t\t\t\t%.1fs\n", p.HttpxAnswered, p.HttpxSeconds)
	}
	w.Flush()
	if p := rec.Probe; p != nil && len(p.Disagree) > 0 {
		fmt.Println("\nprobe differences (azhaq/httpx)")
		for _, d := range p.Disagree {
			fmt.Printf("  %s\n", d)
		}
	}
	fmt.Println("\nchecks")
	for _, c := range rec.Checks {
		mark := "PASS"
		if !c.Pass {
			mark = "FAIL"
		}
		fmt.Printf("  %s  %s  (%s)\n", mark, c.Name, c.Detail)
	}
	for _, r := range rec.Runs {
		if r.Error != "" {
			fmt.Printf("  note: %s on %s: %s\n", r.Tool, r.Target, r.Error)
		}
	}
}

func known(s toolScore) string {
	if s.TruthOf == 0 {
		return "-"
	}
	return fmt.Sprintf("%d/%d", s.Truth, s.TruthOf)
}
