package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// ffuf's configuration file (-config FILE, else ~/.config/ffuf/ffufrc, else
// ~/.ffufrc) is read for fuzz as a list of flags put in front of the command
// line's own, so a flag given on the command line wins, and one that takes
// several values (-H, -w) adds to the file's. Keys are ffuf's, in any
// spelling of case and underscores (recursion_depth, recursiondepth).

// rcKeys is [section] key -> the flag it sets. A bool key gives the flag
// only when true.
var rcKeys = map[string]string{
	"http.cookies": "b", "http.data": "d", "http.followredirects": "r", "http.headers": "H", "http.ignorebody": "ignore-body",
	"http.method": "X", "http.proxyurl": "x", "http.raw": "raw", "http.recursion": "recursion", "http.recursiondepth": "recursion-depth",
	"http.recursionstrategy": "recursion-strategy", "http.replayproxyurl": "replay-proxy", "http.sni": "sni", "http.timeout": "timeout",
	"http.url": "u", "http.http2": "http2", "http.clientcert": "cc", "http.clientkey": "ck",
	"general.autocalibration": "ac", "general.autocalibrationstrings": "acc", "general.autocalibrationstrategy": "acs",
	"general.autocalibrationstrategies": "acs", "general.autocalibrationkeyword": "ack", "general.autocalibrationperhost": "ach",
	"general.colors": "c", "general.delay": "p", "general.json": "json", "general.maxtime": "maxtime", "general.maxtimejob": "maxtime-job",
	"general.noninteractive": "noninteractive", "general.quiet": "s", "general.rate": "rate", "general.stopon403": "sf",
	"general.stoponall": "sa", "general.stoponerrors": "se", "general.threads": "t", "general.verbose": "v",
	"input.dirsearchcompat": "D", "input.encoders": "enc", "input.extensions": "e", "input.ignorewordlistcomments": "ic",
	"input.inputmode": "mode", "input.inputnum": "input-num", "input.inputshell": "input-shell", "input.inputcommands": "input-cmd",
	"input.request": "request", "input.requestproto": "request-proto", "input.wordlists": "w",
	"output.debuglog": "debug-log", "output.outputdirectory": "od", "output.outputfile": "o", "output.outputformat": "of", "output.outputskipemptyfile": "or",
	"filter.mode": "fmode", "filter.lines": "fl", "filter.regexp": "fr", "filter.size": "fs", "filter.status": "fc", "filter.time": "ft", "filter.words": "fw",
	"matcher.mode": "mmode", "matcher.lines": "ml", "matcher.regexp": "mr", "matcher.size": "ms", "matcher.status": "mc", "matcher.time": "mt", "matcher.words": "mw",
}

// rcIgnored are keys of ffuf's file for things azhaq fuzz does not have
// (scrapers, the audit log); they are named in a note, not dropped silently.
var rcIgnored = map[string]bool{
	"general.scrapers": true, "general.scraperfile": true, "output.auditlog": true,
}

func normalizeKey(k string) string {
	return strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(k))
}

// rcPath is the file to read: -config, else ffuf's two places; "" when none.
func rcPath(args []string) (path string, explicit bool) {
	if v, ok := flagValue(args, "config"); ok {
		return v, true
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", false
	}
	for _, p := range []string{filepath.Join(home, ".config", "ffuf", "ffufrc"), filepath.Join(home, ".ffufrc")} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, false
		}
	}
	return "", false
}

// flagValue is the value of -name (or --name) on a command line, the last
// one given.
func flagValue(args []string, name string) (string, bool) {
	val, found := "", false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		k, v, eq := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !strings.HasPrefix(a, "-") || k != name {
			continue
		}
		switch {
		case eq:
			val, found = v, true
		case i+1 < len(args):
			val, found = args[i+1], true
			i++
		}
	}
	return val, found
}

// rcArgs reads a configuration file as flags.
func rcArgs(path string) (out, ignored []string, err error) {
	var doc map[string]map[string]any
	if _, err := toml.DecodeFile(path, &doc); err != nil {
		return nil, nil, fmt.Errorf("%s: %v", path, err)
	}
	sections := make([]string, 0, len(doc))
	for s := range doc {
		sections = append(sections, s)
	}
	sort.Strings(sections)
	for _, sec := range sections {
		keys := make([]string, 0, len(doc[sec]))
		for k := range doc[sec] {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, key := range keys {
			full := normalizeKey(sec) + "." + normalizeKey(key)
			if rcIgnored[full] {
				if v, _ := rcValues(doc[sec][key]); len(v) > 0 && v[0] != "" && v[0] != "false" && !(full == "general.scrapers" && v[0] == "all") {
					ignored = append(ignored, key)
				}
				continue
			}
			if full == "output.outputcreateemptyfile" {
				if on, ok := doc[sec][key].(bool); ok && !on {
					out = append(out, "-or") // ffuf's name for the same switch, turned round
				}
				continue
			}
			flagName, ok := rcKeys[full]
			if !ok {
				return nil, nil, fmt.Errorf("%s: [%s] %s is not a setting azhaq fuzz knows (ffuf's names: threads, headers, wordlists, ...; preflights are flags)", path, sec, key)
			}
			vals, err := rcValues(doc[sec][key])
			if err != nil {
				return nil, nil, fmt.Errorf("%s: [%s] %s: %v", path, sec, key, err)
			}
			for _, v := range vals {
				switch v {
				case "true":
					out = append(out, "-"+flagName)
				case "false", "":
					// an off switch or an empty string is ffuf's default: nothing to give
				default:
					out = append(out, "-"+flagName, v)
				}
			}
		}
	}
	return out, ignored, nil
}

func rcValues(v any) ([]string, error) {
	switch x := v.(type) {
	case string:
		return []string{x}, nil
	case bool:
		return []string{strconv.FormatBool(x)}, nil
	case int64:
		return []string{strconv.FormatInt(x, 10)}, nil
	case float64:
		return []string{strconv.FormatFloat(x, 'f', -1, 64)}, nil
	case []any:
		var out []string
		for _, e := range x {
			s, err := rcValues(e)
			if err != nil {
				return nil, err
			}
			out = append(out, s...)
		}
		return out, nil
	}
	return nil, fmt.Errorf("a %T is not a value a flag takes", v)
}
