package engine

import (
	"context"
	"time"

	"github.com/trannghiach/azhaq/internal/connector"
	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/internal/types"
)

// Ingest writes connector facts onto the graph and returns seeds to Plan/Run.
func (e *Engine) Ingest(ctx context.Context, facts []connector.Fact) ([]types.Seed, error) {
	now := time.Now().UTC()
	var hints []types.Seed
	seen := map[string]bool{}
	add := func(s types.Seed) {
		s = normalize.Seed(s)
		if s.Key() == "" {
			return
		}
		k := seedKey(s)
		if seen[k] {
			return
		}
		seen[k] = true
		hints = append(hints, s)
	}
	for _, f := range facts {
		if ctx.Err() != nil {
			return hints, ctx.Err()
		}
		switch f.Kind {
		case "hello", "meta":
			continue
		case "seed", "hint":
			if f.Seed != nil {
				add(*f.Seed)
			}
		case "entity":
			t, key := f.Entity()
			s := normalize.Seed(seedFor(t, key))
			if s.Key() == "" {
				continue
			}
			ent, err := e.Store.UpsertEntity(s.Type, s.Key(), now)
			if err != nil {
				return hints, err
			}
			e.linkInDomain(s, ent, now)
			add(s)
		case "observation":
			o := f.ObservationValue()
			t, key := f.Entity()
			s := normalize.Seed(seedFor(t, key))
			if s.Key() == "" {
				continue
			}
			ent, err := e.Store.UpsertEntity(s.Type, s.Key(), now)
			if err != nil {
				return hints, err
			}
			if o.Collector == "" {
				o.Collector = "connector"
			}
			if _, err := e.Store.AddObservation(ent.ID, o); err != nil {
				return hints, err
			}
			e.linkFacts(ent, o, now)
			e.linkInDomain(s, ent, now)
			add(s)
		}
	}
	return hints, nil
}

func seedFor(t types.SeedType, key string) types.Seed {
	s := types.Seed{Type: t, Keys: map[string]string{}}
	switch t {
	case types.TypeURL:
		s.Keys["url"] = key
	case types.TypeHostname:
		s.Keys["fqdn"] = key
	case types.TypeDomain:
		s.Keys["domain"] = key
	case types.TypeIPAddress:
		s.Keys["ip"] = key
	case types.TypeOrganization:
		s.Keys["name"] = key
	case types.TypeCloudAccount:
		s.Keys["id"] = key
	default:
		s.Keys["id"] = key
	}
	return s
}
