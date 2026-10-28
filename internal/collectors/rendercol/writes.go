package rendercol

import (
	"encoding/json"
	"net/url"
	"slices"
	"time"

	"github.com/trannghiach/azhaq/internal/browser"
	"github.com/trannghiach/azhaq/internal/webextract"
	"github.com/trannghiach/azhaq/types"
)

// WriteFacts is what the writes of page say: each route of its origin
// with the methods and names it was sent (op source "browser"), as a
// script's call says it, never fetched for it; and the writes Chrome did
// not send, listed as left alone (browser.WriteReason).
func WriteFacts(collector, page string, ws []browser.Write) []types.Observation {
	now := time.Now().UTC()
	var out []types.Observation
	type route struct {
		methods, params, body []string
		ops                   []map[string]any
	}
	routes := map[string]*route{}
	var order, refused []string
	for _, w := range ws {
		if !w.Sent {
			refused = append(refused, w.Target())
		}
		if !webextract.SameOrigin(page, w.URL) {
			continue
		}
		if u, err := url.Parse(w.URL); err == nil && webextract.SocketPath(u.Path) {
			continue // socket.io's polling POST: the socket's row says it, as azhaq-js has it
		}
		k := webextract.RouteKey(w.URL)
		r := routes[k]
		if r == nil {
			r = &route{}
			routes[k] = r
			order = append(order, k)
		}
		op := map[string]any{"method": w.Method, "source": "browser"}
		if len(w.Query) > 0 {
			op["query"] = w.Query
		}
		if len(w.Body) > 0 {
			op["body"], op["body_type"] = w.Body, w.BodyType
		}
		r.ops = append(r.ops, op)
		r.methods = add(r.methods, w.Method)
		r.params = add(r.params, w.Query...)
		r.body = add(r.body, w.Body...)
	}
	for _, k := range order {
		r := routes[k]
		row := map[string]any{"url": k, "via": "browser", "seen": "write", "role": "api", "methods": r.methods, "ops": r.ops}
		if len(r.params) > 0 {
			row["params"] = r.params
		}
		if len(r.body) > 0 {
			row["body"] = r.body
		}
		payload, _ := json.Marshal(row)
		out = append(out, types.Observation{Collector: collector, Source: page, Kind: "url", Payload: payload, Confidence: 0.8, ObservedAt: now})
	}
	if len(refused) > 0 {
		payload, _ := json.Marshal(map[string]any{"skipped": browser.WriteReason, "urls": refused})
		out = append(out, types.Observation{Collector: collector, Source: page, Kind: "skipped", Payload: payload, Confidence: 0.9, ObservedAt: now})
	}
	return out
}

func add(xs []string, ys ...string) []string {
	for _, y := range ys {
		if !slices.Contains(xs, y) {
			xs = append(xs, y)
		}
	}
	return xs
}
