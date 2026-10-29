package hunt

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// RoleRow is the part of a line of `azhaq roles -json` the ranking reads.
type RoleRow struct {
	URL        string   `json:"url"`
	Method     string   `json:"method"`
	Template   string   `json:"template"`
	Owner      string   `json:"owner"`
	Readers    []string `json:"readers"`
	Sensitive  []string `json:"sensitive"`
	Verdict    string   `json:"verdict"`
	Evidence   string   `json:"evidence"`
	Confidence string   `json:"confidence"`
}

// ReadRoles reads a roles output, one row per line. Lines that are not a
// row (the summary, blank lines) are skipped.
func ReadRoles(r io.Reader) ([]RoleRow, error) {
	var out []RoleRow
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var row RoleRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			return nil, fmt.Errorf("line %d: not a roles row: %v", n, err)
		}
		if row.URL != "" && row.Verdict != "" {
			out = append(out, row)
		}
	}
	return out, sc.Err()
}

func (h *hunter) roles() {
	for _, r := range h.in.Roles {
		w, ok := verdictWeight[r.Verdict]
		if !ok {
			continue
		}
		if s, ok := confidenceScale[r.Confidence]; ok {
			w = w * s / 100
		}
		base := r.URL
		if r.Template != "" {
			base = r.Template
		}
		key := GroupKey(base, false)
		c := h.cands["URL\x00"+key]
		if c == nil {
			c = h.get("URL", key, "target")
			if u, err := url.Parse(base); err == nil {
				c.origin = u.Scheme + "://" + u.Host
			}
		}
		if c.roleURL == "" {
			c.roleURL, c.roleM = r.URL, r.Method
		}
		d := r.Verdict
		switch {
		case r.Evidence != "":
			d += ": " + r.Evidence
		case len(r.Sensitive) > 0:
			d += ": " + strings.Join(r.Sensitive, ", ")
		}
		if r.Confidence != "" {
			d += " (" + r.Confidence + ")"
		}
		if r.Method != "" {
			d = r.Method + " " + d
		}
		c.addW("cross-role", w, d)
	}
}
