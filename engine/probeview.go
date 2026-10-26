package engine

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/types"
)

// ProbeRow is one probed web service, the way httpx prints it.
type ProbeRow struct {
	URL         string   `json:"url"`
	Status      int      `json:"status"`
	FinalStatus int      `json:"final_status,omitempty"`
	FinalURL    string   `json:"final_url,omitempty"`
	Title       string   `json:"title,omitempty"`
	Tech        []string `json:"tech,omitempty"`
	Server      string   `json:"server,omitempty"`
	CDN         string   `json:"cdn,omitempty"`
	CDNType     string   `json:"cdn_type,omitempty"`
	IP          string   `json:"ip,omitempty"`
	Favicon     string   `json:"favicon,omitempty"`
	ContentType string   `json:"content_type,omitempty"`
	Location    string   `json:"location,omitempty"`
	Length      int      `json:"length"`
	Words       int      `json:"words"`
	Lines       int      `json:"lines"`
	MS          int      `json:"ms"`
	CatchAll    bool     `json:"catchall,omitempty"`
}

// ProbeRows lists the HTTP observations of a run with the CDN its host's
// DNS answer pointed to, sorted by URL.
func ProbeRows(obs []types.StoredObservation) []ProbeRow {
	cdn := map[string][2]string{}
	for _, o := range obs {
		if o.Collector != "azhaq-dns" {
			continue
		}
		var p struct {
			FQDN    string `json:"fqdn"`
			CDN     string `json:"cdn"`
			CDNType string `json:"cdn_type"`
		}
		if json.Unmarshal(o.Payload, &p) == nil && p.CDN != "" {
			cdn[p.FQDN] = [2]string{p.CDN, p.CDNType}
		}
	}
	var rows []ProbeRow
	seen := map[string]bool{}
	for _, o := range obs {
		r, ok := ProbeRowOf(o.Observation)
		if !ok || seen[r.URL] {
			continue
		}
		seen[r.URL] = true
		if c, ok := cdn[normalize.HostFromURL(r.URL)]; ok {
			r.CDN, r.CDNType = c[0], c[1]
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].URL < rows[j].URL })
	return rows
}

// ProbeRowOf reads one azhaq-http observation, without the CDN (it comes
// from DNS).
func ProbeRowOf(o types.Observation) (ProbeRow, bool) {
	var r ProbeRow
	if o.Collector != "azhaq-http" || o.Kind == "error" || json.Unmarshal(o.Payload, &r) != nil || r.URL == "" || r.Status == 0 {
		return ProbeRow{}, false
	}
	if r.FinalURL == r.URL {
		r.FinalURL = ""
	}
	return r, true
}

// Line is the row in httpx's bracket style.
func (r ProbeRow) Line() string {
	var b strings.Builder
	b.WriteString(r.URL)
	status := fmt.Sprint(r.Status)
	if r.FinalStatus != 0 {
		status += "," + fmt.Sprint(r.FinalStatus)
	}
	fmt.Fprintf(&b, " [%s]", status)
	if r.Title != "" {
		fmt.Fprintf(&b, " [%s]", r.Title)
	}
	if len(r.Tech) > 0 {
		fmt.Fprintf(&b, " [%s]", strings.Join(r.Tech, ","))
	}
	if r.CDN != "" {
		fmt.Fprintf(&b, " [%s:%s]", r.CDNType, r.CDN)
	}
	if r.IP != "" {
		fmt.Fprintf(&b, " [%s]", r.IP)
	}
	if r.Favicon != "" {
		fmt.Fprintf(&b, " [favicon:%s]", r.Favicon)
	}
	if r.FinalURL != "" {
		fmt.Fprintf(&b, " -> %s", r.FinalURL)
	}
	if r.CatchAll {
		b.WriteString(" (catch-all)")
	}
	return b.String()
}
