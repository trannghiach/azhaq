package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/trannghiach/azhaq/store"
)

// cmdResume continues the latest run of a database that has tasks left:
// one interrupted, or stopped by -max-requests, a daily budget or
// -max-items. The run's options are read back from the database; session
// values are not stored and are given again after -db:
//
//	azhaq resume -db app.db [-cookie session=… | -login-pass …] [-max-items 4096]
func cmdResume(args []string) error {
	db := ""
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-db" || a == "--db":
			if i+1 < len(args) {
				db = args[i+1]
				i++
			}
		case strings.HasPrefix(a, "-db=") || strings.HasPrefix(a, "--db="):
			db = a[strings.Index(a, "=")+1:]
		default:
			rest = append(rest, a)
		}
	}
	if db == "" {
		return usagef("give -db FILE, the database of the run to continue (run options to add, such as -cookie or -login-pass, may follow)")
	}
	st, err := store.OpenExisting(db)
	if err != nil {
		return err
	}
	id, runArgs, left, ok, err := st.Resumable()
	st.Close()
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("nothing to resume in %s: every run finished", db)
	}
	fmt.Fprintf(os.Stderr, "azhaq: resuming run %s of %s, %d tasks left\n", id, db, left)
	// Later options win: what is given now overrides what was stored.
	all := append(append(append([]string(nil), runArgs...), rest...), "-db", db, "-resume-run", id)
	return cmdRun(all)
}

// keptArgs are the run options stored for azhaq resume: everything but the
// database and the values that carry a session or a secret (cookies, a
// password, the worker token, headers whose name sounds like a
// credential).
func keptArgs(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		name, val, inline := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !strings.HasPrefix(a, "-") {
			out = append(out, a)
			continue
		}
		takesValue := !inline && i+1 < len(args)
		switch name {
		case "db", "resume-run", "cookie", "login-pass", "worker-token":
			if takesValue {
				i++
			}
			continue
		case "header":
			if !inline && takesValue {
				val = args[i+1]
				i++
			}
			if secretHeader(val) {
				continue
			}
			out = append(out, "-header="+val)
			continue
		}
		out = append(out, a)
	}
	return out
}

func secretHeader(h string) bool {
	k, _, _ := strings.Cut(h, ":")
	k = strings.ToLower(strings.TrimSpace(k))
	for _, w := range []string{"auth", "cookie", "token", "key", "session", "secret", "csrf", "xsrf"} {
		if strings.Contains(k, w) {
			return true
		}
	}
	return false
}
