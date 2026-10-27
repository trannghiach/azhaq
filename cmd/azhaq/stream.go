package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/trannghiach/azhaq/types"
)

// streamFound prints what a run finds as it finds it, once per name, URL
// or open port: a long run is not silent for minutes before its map.
// Lines go to stdout before the map; with -json each is an object with
// "type":"found".
func streamFound(asJSON bool) func(types.Entity, types.Observation) {
	var mu sync.Mutex
	seen := map[string]bool{}
	enc := json.NewEncoder(os.Stdout)
	return func(_ types.Entity, o types.Observation) {
		var p map[string]any
		if json.Unmarshal(o.Payload, &p) != nil {
			return
		}
		str := func(k string) string { s, _ := p[k].(string); return s }
		var kind, key, more string
		switch o.Kind {
		case "application":
			if st, ok := p["status"].(float64); ok && st > 0 {
				kind, key, more = "answer", str("url"), fmt.Sprintf("[%d] %s", int(st), str("title"))
			}
		case "url":
			kind, key = "url", str("url")
		case "dns":
			if ips, _ := p["ips"].([]any); len(ips) > 0 && p["wildcard"] != true {
				kind, key = "name", str("fqdn")
			}
		case "ports":
			if open, _ := p["open"].([]any); len(open) > 0 {
				kind, key, more = "ports", str("ip"), fmt.Sprint(open)
				if h := str("host"); h != "" && h != key {
					key = h + " (" + key + ")"
				}
			}
		}
		if key == "" {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if seen[kind+" "+key] {
			return
		}
		seen[kind+" "+key] = true
		if asJSON {
			row := map[string]any{"type": "found", "kind": kind, "key": key, "collector": o.Collector}
			if more != "" {
				row["detail"] = more
			}
			_ = enc.Encode(row)
			return
		}
		fmt.Fprintln(os.Stdout, strings.TrimSpace(fmt.Sprintf("found  %-7s %s  %s", kind, key, more)))
	}
}
