// Package types holds what flows through Azhaq: seeds (what to look at),
// observations (what a collector saw), entities and edges (the graph they
// build) and run metadata.
package types

import (
	"context"
	"encoding/json"
	"time"
)

type SeedType string

const (
	TypeURL          SeedType = "URL"
	TypeHostname     SeedType = "Hostname"
	TypeDomain       SeedType = "Domain"
	TypeIPAddress    SeedType = "IPAddress"
	TypePrefix       SeedType = "Prefix" // Keys["prefix"]: 192.0.2.0/24
	TypeASN          SeedType = "ASN"    // Keys["asn"]: AS64500
	TypeCertificate  SeedType = "Certificate"
	TypeOrganization SeedType = "Organization"
	TypeEmail        SeedType = "Email"
	TypeCloudAccount SeedType = "CloudAccount"
	TypeApplication  SeedType = "Application"
)

type Seed struct {
	Type SeedType          `json:"type"`
	Keys map[string]string `json:"keys"`
}

// DerivedKey marks a domain the engine derived from a URL or hostname, as
// opposed to one the user asked about: collectors may spend less time on
// it so the application's own map is not held up.
const DerivedKey = "derived"

// SameTargetKey marks a hint that is the seed it came from in another form
// (the scheme that answered for host:port): it does not count as a step of
// -depth.
const SameTargetKey = "same"

// RedirectKey marks a hint that is where the seed it came from redirected to,
// within the site: the redirect is the answer to the seed, so it is no step
// of -depth either.
const RedirectKey = "redirect"

// FromURLKey on a hostname the engine derived from a URL holds that URL:
// a collector that tries a name on both schemes can leave it out when the
// URL is the service the user named.
const FromURLKey = "from_url"

// StartKey marks a URL seed the user gave, as against one a collector
// found: a path sweep starts from the path of the first, not the second.
const StartKey = "start"

// GivenKey marks a URL seed the user named: a page they asked for,
// whatever its path, where the URLs a run finds are shot only when they
// are front pages.
const GivenKey = "given"

// ViaKey on a URL hint says where it was found when that sets what it is
// worth: ViaArchive for a URL an archive listed, which a run under a
// budget requests after what the application itself serves and names.
// On a hostname, ViaPermute is a name a variation found, which is not varied
// again.
const (
	ViaKey     = "via"
	ViaArchive = "archive"
	ViaPermute = "permute"
)

// Derived reports whether the engine derived s from another seed.
func (s Seed) Derived() bool { return s.Keys[DerivedKey] != "" }

func Known(t SeedType) bool {
	switch t {
	case TypeURL, TypeHostname, TypeDomain, TypeIPAddress, TypePrefix, TypeASN, TypeCertificate, TypeOrganization, TypeEmail, TypeCloudAccount, TypeApplication:
		return true
	default:
		return false
	}
}

func (s Seed) Key() string {
	switch s.Type {
	case TypeURL:
		return s.Keys["url"]
	case TypeHostname:
		return s.Keys["fqdn"]
	case TypeDomain:
		return s.Keys["domain"]
	case TypeIPAddress:
		return s.Keys["ip"]
	case TypePrefix:
		return s.Keys["prefix"]
	case TypeASN:
		return s.Keys["asn"]
	case TypeOrganization:
		if s.Keys["handle"] != "" {
			return s.Keys["handle"]
		}
		return s.Keys["name"]
	case TypeCloudAccount:
		if s.Keys["id"] != "" {
			return s.Keys["id"]
		}
		return s.Keys["path"]
	default:
		if v, ok := s.Keys["id"]; ok {
			return v
		}
		for _, v := range s.Keys {
			return v
		}
		return ""
	}
}

type Observation struct {
	Collector  string          `json:"collector"`
	Source     string          `json:"source"`
	Kind       string          `json:"kind"`
	Payload    json.RawMessage `json:"payload"`
	Confidence float64         `json:"confidence"`
	ObservedAt time.Time       `json:"observed_at"`
	// Keep: written even when the request budget stops its task, which
	// azhaq resume runs again (what a port scan found before it stopped).
	Keep bool `json:"-"`
}

type WorkItem struct {
	ID        string `json:"id"`
	Collector string `json:"collector"`
	Seed      Seed   `json:"seed"`
}

type RunMeta struct {
	ItemID    string `json:"item_id"`
	Status    string `json:"status"` // ok, error, denied, cancelled
	EmitCount int    `json:"emit_count"`
	Error     string `json:"error,omitempty"`
	NextHints []Seed `json:"next_hints,omitempty"`
	// Drop tells collectors that wait on this one (catalog.Info.After) to
	// leave the seed alone: a name that does not resolve, a wildcard answer.
	Drop bool `json:"drop,omitempty"`
	// Requests is how many requests to targets the work sent, set when the
	// request budget stopped it.
	Requests int `json:"requests,omitempty"`
}

type Entity struct {
	ID        string    `json:"id"`
	Type      SeedType  `json:"type"`
	Key       string    `json:"key"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type Edge struct {
	From       string    `json:"from"`
	To         string    `json:"to"`
	Type       string    `json:"type"`
	ObservedAt time.Time `json:"observed_at"`
}

type StoredObservation struct {
	ID       string `json:"id"`
	EntityID string `json:"entity_id"`
	Observation
}

const (
	StatusOK        = "ok"
	StatusError     = "error"
	StatusCancelled = "cancelled"
	StatusDegraded  = "degraded"
	// StatusCapped is work that stopped because the run's request budget
	// was spent; it is left for azhaq resume.
	StatusCapped = "capped"
)

// CutShort marks work the run's -timeout stopped: the run hit its limit
// (exit 4, resumable); the collector did not fail.
const CutShort = "cut short by the run's -timeout"

// BatchEmit hands several observations at once; the engine writes them in
// one transaction, which a collector with thousands of them (a path sweep)
// needs to keep up with its own requests.
type BatchEmit func([]Observation) error

type batchKey struct{}

// WithBatchEmit is ctx carrying f for the collector's Run.
func WithBatchEmit(ctx context.Context, f BatchEmit) context.Context {
	return context.WithValue(ctx, batchKey{}, f)
}

// BatchEmitFrom is the batch emit the engine gave a collector's Run, or
// nil when it gave none (a connector worker): the collector then emits one
// at a time.
func BatchEmitFrom(ctx context.Context) BatchEmit {
	f, _ := ctx.Value(batchKey{}).(BatchEmit)
	return f
}
