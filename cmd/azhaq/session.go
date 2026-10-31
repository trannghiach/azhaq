package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/types"
)

// watchSession gives a signed-in run its session check (fetch.Session): a
// page the run asks with its session and without it, whose answers differ,
// asked every 50 requests and when an answer looks like the end of the
// session. renew signs in again (-login); nil for a session given with
// -cookie or -header, which the run cannot renew.
func watchSession(ctx context.Context, seeds []types.Seed, home, loginURL string, renew func(context.Context) error, rep *report) {
	if !fetch.HasSession() {
		return
	}
	s := fetch.Session{Renew: renew, SignIn: loginURL}
	if renew == nil {
		s.Why = "the session was given with -cookie or -header: give a fresh one and run azhaq resume"
	}
	var candidates []string
	if home != "" {
		candidates = append(candidates, home)
	}
	for _, sd := range seeds {
		if sd.Type == types.TypeURL && len(candidates) < 4 {
			candidates = append(candidates, sd.Key())
		}
	}
	var tried []string
	for _, c := range candidates {
		with, without, err := fetch.Measure(ctx, c)
		if err != nil {
			continue
		}
		if with != without && with.Status != 0 {
			s.Check, s.Want = c, with
			break
		}
		tried = append(tried, c)
	}
	if s.Check == "" && len(candidates) > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("session check: %s answered the same with the session and without it, so a lost session is noticed only when a response clears the session cookie", strings.Join(tried, ", ")))
	}
	fetch.WatchSession(s)
}
