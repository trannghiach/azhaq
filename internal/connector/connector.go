package connector

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/trannghiach/azhaq/internal/normalize"
	"github.com/trannghiach/azhaq/types"
)

// Protocol is the stdin/stdout JSONL contract version.
const Protocol = "azhaq.connector.v1"

// Fact is one JSONL line on the connector pipe.
//
// Azhaq → connector:  {"kind":"seed","seed":{...}}
// Connector → Azhaq:  {"kind":"observation",...} and/or {"kind":"hint","seed":{...}}
type Fact struct {
	Kind        string             `json:"kind"`
	Seed        *types.Seed        `json:"seed,omitempty"`
	EntityType  types.SeedType     `json:"entity_type,omitempty"`
	EntityKey   string             `json:"entity_key,omitempty"`
	Collector   string             `json:"collector,omitempty"`
	Source      string             `json:"source,omitempty"`
	ObsKind     string             `json:"obs_kind,omitempty"`
	Payload     json.RawMessage    `json:"payload,omitempty"`
	Confidence  float64            `json:"confidence,omitempty"`
	Observation *types.Observation `json:"observation,omitempty"`
}

func CheckLine(f Fact, raw []byte) error {
	var env struct {
		Kind        string          `json:"kind"`
		Entity      json.RawMessage `json:"entity"`
		Edge        json.RawMessage `json:"edge"`
		Observation json.RawMessage `json:"observation"`
		Collector   string          `json:"collector"`
		ID          string          `json:"id"`
		EntityID    string          `json:"entity_id"`
	}
	_ = json.Unmarshal(raw, &env)
	if f.Kind == "" {
		return fmt.Errorf("missing kind (not a connector fact)")
	}
	switch f.Kind {
	case "hello", "meta":
		return nil
	case "seed", "hint":
		if f.Seed == nil || f.Seed.Key() == "" {
			return fmt.Errorf("%s missing seed", f.Kind)
		}
	case "entity":
		if len(env.Entity) > 0 && f.EntityKey == "" {
			return fmt.Errorf("azhaq export envelope; ingest wants connector facts (use the same -db)")
		}
	case "observation":
		var nested struct {
			EntityID string `json:"entity_id"`
		}
		_ = json.Unmarshal(env.Observation, &nested)
		if nested.EntityID != "" && f.EntityKey == "" {
			return fmt.Errorf("azhaq export envelope; ingest wants connector facts (use the same -db)")
		}
	case "edge":
		return fmt.Errorf("azhaq export envelope; ingest wants connector facts (use the same -db)")
	}
	if env.Collector != "" && env.ID != "" && f.Seed == nil && f.Kind != "observation" && f.Kind != "entity" && f.Kind != "seed" && f.Kind != "hint" {
		return fmt.Errorf("plan work item, not a connector fact")
	}
	return nil
}

func DecodeLine(raw []byte) (Fact, error) {
	var f Fact
	if err := json.Unmarshal(raw, &f); err != nil {
		return f, err
	}
	return f, nil
}

func ReadJSONL(r io.Reader) ([]Fact, error) {
	var out []Fact
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 2<<20)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		raw := []byte(line)
		f, err := DecodeLine(raw)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		if err := CheckLine(f, raw); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		out = append(out, f)
	}
	return out, sc.Err()
}

func ReadFile(path string) ([]Fact, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ReadJSONL(bytes.NewReader(raw))
}

func WriteSeeds(w io.Writer, seeds []types.Seed) error {
	enc := json.NewEncoder(w)
	for _, s := range seeds {
		s = normalize.Seed(s)
		if s.Key() == "" {
			continue
		}
		if err := enc.Encode(Fact{Kind: "seed", Seed: &s}); err != nil {
			return err
		}
	}
	return nil
}

// Exec runs argv as a connector: seeds on stdin, facts on stdout.
func Exec(ctx context.Context, argv []string, seeds []types.Seed) ([]Fact, error) {
	if len(argv) == 0 || argv[0] == "" {
		return nil, fmt.Errorf("empty connector command")
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if err := WriteSeeds(stdin, seeds); err != nil {
		_ = stdin.Close()
		_ = cmd.Wait()
		return nil, err
	}
	_ = stdin.Close()
	waitErr := cmd.Wait()
	facts, err := ReadJSONL(&stdout)
	if err != nil {
		return nil, err
	}
	if waitErr != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return facts, fmt.Errorf("%w: %s", waitErr, msg)
		}
		return facts, waitErr
	}
	return facts, nil
}

func (f Fact) ObservationValue() types.Observation {
	if f.Observation != nil {
		o := *f.Observation
		if o.ObservedAt.IsZero() {
			o.ObservedAt = time.Now().UTC()
		}
		return o
	}
	kind := f.ObsKind
	if kind == "" {
		kind = "connector"
	}
	col := f.Collector
	if col == "" {
		col = "connector"
	}
	payload := f.Payload
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	conf := f.Confidence
	if conf == 0 {
		conf = 0.6
	}
	return types.Observation{
		Collector:  col,
		Source:     f.Source,
		Kind:       kind,
		Payload:    payload,
		Confidence: conf,
		ObservedAt: time.Now().UTC(),
	}
}

func (f Fact) Entity() (types.SeedType, string) {
	if f.EntityKey != "" {
		t := f.EntityType
		if t == "" {
			t = types.TypeHostname
		}
		return t, f.EntityKey
	}
	o := f.ObservationValue()
	var p map[string]any
	_ = json.Unmarshal(o.Payload, &p)
	if u, _ := p["url"].(string); u != "" {
		if n, err := normalize.URL(u); err == nil {
			return types.TypeURL, n
		}
	}
	if d, _ := p["domain"].(string); d != "" {
		return types.TypeDomain, normalize.Hostname(d)
	}
	if h, _ := p["fqdn"].(string); h != "" {
		return types.TypeHostname, normalize.Hostname(h)
	}
	if f.Seed != nil && f.Seed.Key() != "" {
		s := normalize.Seed(*f.Seed)
		return s.Type, s.Key()
	}
	return "", ""
}
