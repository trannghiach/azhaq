package main

import (
	"fmt"
	"sort"
	"strings"
)

// sourceHealth is the summary's answer to "did the sources answer": how
// many were asked (a source for each domain counts once), how many
// answered, which failed and why, and what each gave. It is for a caller
// that reads exit 0 as "all of them did".
type sourceHealth struct {
	Asked              int `json:"asked"`
	Answered           int `json:"answered"`
	Failed             int `json:"failed"`
	OffByDefaultFailed int `json:"off_by_default_failed,omitempty"` // ran only because of -all-sources
	// Names is what each source gave, names for subs and URLs for urls, before
	// any DNS check or filter.
	Names map[string]int `json:"names,omitempty"`
	URLs  map[string]int `json:"urls,omitempty"`
	// FailedSources has the reason of each failure; with several domains each
	// reason names its domain.
	FailedSources map[string]string `json:"failed_sources,omitempty"`
}

// healthTally collects sourceHealth from the per-domain payloads.
type healthTally struct {
	h       sourceHealth
	reasons map[string][]string // source → "domain: reason"
	domains map[string]bool
	urls    bool
}

func newHealthTally(urls bool) *healthTally {
	t := &healthTally{reasons: map[string][]string{}, domains: map[string]bool{}, urls: urls}
	if urls {
		t.h.URLs = map[string]int{}
	} else {
		t.h.Names = map[string]int{}
	}
	return t
}

// add reads one domain's source rows.
func (t *healthTally) add(domain string, srcs map[string]any) {
	for name, v := range srcs {
		row, _ := v.(map[string]any)
		if row["skipped"] != nil || name == "history" {
			continue // not asked: a key it lacks, a local file
		}
		t.domains[domain] = true
		t.h.Asked++
		gave := t.h.Names
		if t.urls {
			gave = t.h.URLs
		}
		gave[name] += intOf(row["count"])
		if row["error"] == nil {
			t.h.Answered++
			continue
		}
		if row["default"] == false {
			t.h.OffByDefaultFailed++
		} else {
			t.h.Failed++
		}
		t.reasons[name] = append(t.reasons[name], domain+"\x00"+fmt.Sprint(row["error"]))
	}
}

// result is the block, nil when no source was asked.
func (t *healthTally) result() *sourceHealth {
	if t.h.Asked == 0 {
		return nil
	}
	h := t.h
	if len(t.reasons) > 0 {
		h.FailedSources = map[string]string{}
		for name, rs := range t.reasons {
			sort.Strings(rs)
			var parts []string
			for _, r := range rs {
				domain, why, _ := strings.Cut(r, "\x00")
				if len(t.domains) > 1 {
					why = domain + ": " + why
				}
				parts = append(parts, why)
			}
			h.FailedSources[name] = strings.Join(parts, "; ")
		}
	}
	return &h
}

// failures is how many asks failed, off-by-default ones included.
func (h *sourceHealth) failures() int { return h.Failed + h.OffByDefaultFailed }

// line is the sentence that says what exit 0 (or 3) means for the sources:
// "23 of 33 sources answered, 10 failed (listed above); exit 0 because …".
func (h *sourceHealth) line(exit int, ownFailures int, failOnErrors, archives bool) string {
	what := "sources"
	if archives {
		what = "archives"
	}
	s := fmt.Sprintf("%d of %d %s answered, %d failed (listed above)", h.Answered, h.Asked, what, h.failures())
	switch {
	case exit == exitPartial && ownFailures > 0 && failOnErrors:
		s += "; exit 3 because -fail-on-errors counts every failed source"
	case exit == exitPartial && ownFailures > 0 && archives:
		s += "; exit 3 because an archive that failed is not made up for by the others: the URLs it holds may be missing"
	case exit == exitOK:
		s += "; exit 0 because other sources answered for the same domain (-fail-on-errors makes it 3)"
	case exit == exitPartial && ownFailures > 0:
		s += "; exit 3 because a failed source was not made up for by others answering for the same domain"
	}
	return s
}

// archiveHealth is the block for urls: its archives are the sources.
func archiveHealth(ps []map[string]any) *sourceHealth {
	t := newHealthTally(true)
	for _, p := range ps {
		domain, _ := p["domain"].(string)
		srcs, _ := p["sources"].(map[string]any)
		t.add(domain, srcs)
	}
	return t.result()
}
