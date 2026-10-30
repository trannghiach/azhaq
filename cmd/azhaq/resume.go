package main

import (
	"encoding/json"
	"fmt"
	"github.com/trannghiach/azhaq/internal/collectors/httpcol"
	"os"
	"path/filepath"
	"strings"

	"github.com/trannghiach/azhaq/internal/collectors/dirscol"
	"github.com/trannghiach/azhaq/internal/scopefile"
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
	// A stopped fuzz run keeps the command that goes on from where it was.
	if raw := st.GetMeta(fuzzResumeKey); raw != "" {
		var args []string
		if json.Unmarshal([]byte(raw), &args) == nil && len(args) > 0 {
			st.Close()
			return cmdFuzz(append(args, rest...))
		}
	}
	id, runArgs, left, ok, err := st.Resumable()
	st.Close()
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("nothing to resume in %s: every run finished", db)
	}
	if !wantsJSON(rest) {
		fmt.Fprintf(os.Stderr, "azhaq: resuming run %s of %s, %d tasks known and not done\n", id, db, left)
	}
	if !hasFlag(rest, "list") {
		if runArgs, err = listFromWorkspace(db, id, runArgs); err != nil {
			return err
		}
	}
	// Later options win: what is given now overrides what was stored.
	all := append(append(append([]string(nil), runArgs...), rest...), "-db", db, "-resume-run", id)
	return cmdRun(all)
}

// listFromWorkspace points the stored run's -list at the copy the
// workspace keeps: the file may be gone (stdin, the temporary list a
// command such as dirs or probe wrote and removed) or changed since, and
// a resumed run continues the targets it started with. A -list given to
// azhaq resume replaces it.
func listFromWorkspace(db, id string, args []string) ([]string, error) {
	out := append([]string(nil), args...)
	for i := 0; i < len(out); i++ {
		name, val, inline := strings.Cut(strings.TrimLeft(out[i], "-"), "=")
		if name != "list" || !strings.HasPrefix(out[i], "-") {
			continue
		}
		at := i
		if !inline {
			if i+1 >= len(out) {
				break
			}
			at, val = i+1, out[i+1]
		}
		st, err := store.OpenExisting(db)
		if err != nil {
			return nil, err
		}
		kept := st.GetMeta("list:" + id)
		st.Close()
		if kept == "" {
			if _, err := os.Stat(val); val != "-" && err == nil {
				continue // a run from before workspaces kept their lists
			}
			return nil, fmt.Errorf("the run's target list %s is gone and %s keeps no copy of it: give it again with -list FILE", val, db)
		}
		if now, err := loadLines(val); err == nil && val != "-" && strings.Join(now, "\n") != kept {
			fmt.Fprintf(os.Stderr, "azhaq: %s changed since the run started; resuming the targets the run started with (give -list to use the file as it is now)\n", val)
		}
		storedList = strings.Split(kept, "\n")
		if inline {
			out[i] = "-list=@run"
		} else {
			out[at] = "@run"
		}
	}
	return out, nil
}

// keptArgs are the run options stored for azhaq resume: everything but the
// database and the values that carry a session or a secret (cookies, a
// password, the worker token, headers whose name sounds like a
// credential). A -scope file is kept by its full path, so a resume or an
// export started in another directory reads the same file.
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
		case "list", "in", "cloud", "facts", "paths", "providers", "resolvers", "dns-brute", "dirs", "params", "params-targets", "screenshots", "urls", "ledger", "kill-file":
			// Files and directories, made absolute: azhaq resume may run
			// from another directory.
			if !inline && takesValue {
				val = args[i+1]
				i++
			}
			if val != "-" && val != "" && !(name == "ledger" && val == "off") && (name != "resolvers" || isFile(val)) && !(name == "params" && builtinNames(val)) && !(name == "dirs" && val == dirscol.Builtin) {
				if abs, err := filepath.Abs(val); err == nil {
					val = abs
				}
			}
			out = append(out, "-"+name+"="+val)
			continue
		case "probe-opts":
			// probe's options hold a raw request whose credential headers are
			// kept as little as -header's are.
			if !inline && takesValue {
				val = args[i+1]
				i++
			}
			out = append(out, "-probe-opts="+redactProbeOpts(val))
			continue
		case "scope":
			if !inline && takesValue {
				val = args[i+1]
				i++
			}
			if _, platform := scopefile.Platforms[val]; !platform && val != "" {
				if abs, err := filepath.Abs(val); err == nil {
					val = abs
				}
			}
			out = append(out, "-scope="+val)
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

// redactProbeOpts drops the credential headers of the raw request in
// probe's options, as keptArgs drops them from -header.
func redactProbeOpts(raw string) string {
	var spec httpcol.Spec
	if json.Unmarshal([]byte(raw), &spec) != nil || spec.Raw == nil {
		return raw
	}
	for k := range spec.Raw.Header {
		if secretHeader(k + ":") {
			delete(spec.Raw.Header, k)
		}
	}
	out, err := json.Marshal(&spec)
	if err != nil {
		return raw
	}
	return string(out)
}
