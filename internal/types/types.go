package types

import (
	"encoding/json"
	"time"
)

type SeedType string

const (
	TypeURL          SeedType = "URL"
	TypeHostname     SeedType = "Hostname"
	TypeDomain       SeedType = "Domain"
	TypeIPAddress    SeedType = "IPAddress"
	TypePrefix       SeedType = "Prefix"
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

func Known(t SeedType) bool {
	switch t {
	case TypeURL, TypeHostname, TypeDomain, TypeIPAddress, TypePrefix, TypeCertificate, TypeOrganization, TypeEmail, TypeCloudAccount, TypeApplication:
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
)
