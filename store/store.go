// Package store is the SQLite graph: entities, observations and edges,
// the runs that saw them, and the comparison of two runs.
package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/trannghiach/azhaq/types"
)

type Store struct {
	db    *sql.DB
	mu    sync.Mutex
	runID string
}

func OpenExisting(path string) (*Store, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("no such db %s", path)
	}
	if st.IsDir() {
		return nil, fmt.Errorf("%s is a directory", path)
	}
	return Open(path)
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	// A new database gives back the pages freed when a run's kept answers
	// are dropped (DropResponses); the mode can only be set before the
	// first table.
	var tables int
	if db.QueryRow(`SELECT COUNT(*) FROM sqlite_master`).Scan(&tables) == nil && tables == 0 {
		_, _ = db.Exec(`PRAGMA auto_vacuum = INCREMENTAL`)
	}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS entities (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  key TEXT NOT NULL,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  UNIQUE(type, key)
);
CREATE TABLE IF NOT EXISTS observations (
  id TEXT PRIMARY KEY,
  entity_id TEXT NOT NULL,
  collector TEXT NOT NULL,
  source TEXT NOT NULL,
  kind TEXT NOT NULL,
  payload TEXT NOT NULL,
  confidence REAL NOT NULL,
  observed_at INTEGER NOT NULL,
  FOREIGN KEY(entity_id) REFERENCES entities(id)
);
CREATE TABLE IF NOT EXISTS edges (
  from_id TEXT NOT NULL,
  to_id TEXT NOT NULL,
  type TEXT NOT NULL,
  observed_at INTEGER NOT NULL,
  PRIMARY KEY (from_id, to_id, type)
);
CREATE TABLE IF NOT EXISTS idempotency (
  key TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS meta (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY,
  started INTEGER NOT NULL,
  capped INTEGER NOT NULL DEFAULT 0,
  depth INTEGER NOT NULL DEFAULT 0,
  max_items INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS run_entities (
  run_id TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  PRIMARY KEY (run_id, entity_id)
);
CREATE TABLE IF NOT EXISTS tasks (
  run_id TEXT NOT NULL,
  id TEXT NOT NULL,
  collector TEXT NOT NULL,
  seed TEXT NOT NULL,
  depth INTEGER NOT NULL,
  prio INTEGER NOT NULL,
  done INTEGER NOT NULL DEFAULT 0,
  tries INTEGER NOT NULL DEFAULT 0,
  need INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (run_id, id)
);
CREATE TABLE IF NOT EXISTS spend (
  program TEXT NOT NULL,
  day TEXT NOT NULL,
  requests INTEGER NOT NULL,
  PRIMARY KEY (program, day)
);
CREATE TABLE IF NOT EXISTS claims (
  run_id TEXT NOT NULL,
  key TEXT NOT NULL,
  owner TEXT NOT NULL,
  PRIMARY KEY (run_id, key)
);
CREATE TABLE IF NOT EXISTS responses (
  run_id TEXT NOT NULL,
  url TEXT NOT NULL,
  meta TEXT NOT NULL,
  body BLOB,
  PRIMARY KEY (run_id, url)
);
CREATE TABLE IF NOT EXISTS run_edges (
  run_id TEXT NOT NULL,
  from_id TEXT NOT NULL,
  to_id TEXT NOT NULL,
  type TEXT NOT NULL,
  PRIMARY KEY (run_id, from_id, to_id, type)
);
`)
	if err != nil {
		return err
	}
	if err := s.ensureColumn("observations", "run_id", "TEXT"); err != nil {
		return err
	}
	return s.ensureColumn("runs", "args", "TEXT")
}

func (s *Store) ensureColumn(table, col, decl string) error {
	rows, err := s.db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == col {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = s.db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + col + ` ` + decl)
	if err != nil && !strings.Contains(err.Error(), "duplicate column") {
		return err
	}
	return nil
}

// BeginRun binds later writes and Stats() to id. Concurrent processes
// each call this with their own id on a shared database.
func (s *Store) BeginRun(id string, depth, maxItems int) error {
	if id == "" {
		return fmt.Errorf("empty run id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runID = id
	_, err := s.db.Exec(`INSERT INTO runs (id, started, capped, depth, max_items) VALUES (?, ?, 0, ?, ?)`,
		id, time.Now().UTC().UnixNano(), depth, maxItems)
	return err
}

// Run is one run recorded in a database.
type Run struct {
	ID      string
	Started time.Time
}

// Runs lists the runs in the database, oldest first.
func (s *Store) Runs() ([]Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id, started FROM runs ORDER BY started`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		var r Run
		var ts int64
		if err := rows.Scan(&r.ID, &ts); err != nil {
			return nil, err
		}
		r.Started = time.Unix(0, ts)
		out = append(out, r)
	}
	return out, rows.Err()
}

// UseRun selects a recorded run for reading, without starting a new one.
func (s *Store) UseRun(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runID = id
}

func (s *Store) RunID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.runID
}

func (s *Store) MarkCapped() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runID != "" {
		if _, err := s.db.Exec(`UPDATE runs SET capped = 1 WHERE id = ?`, s.runID); err != nil {
			return err
		}
	}
	_, err := s.db.Exec(`INSERT INTO meta (k, v) VALUES ('capped', '1') ON CONFLICT(k) DO UPDATE SET v = excluded.v`)
	return err
}

func EntityID(t types.SeedType, key string) string {
	sum := sha256.Sum256([]byte(string(t) + "\x00" + key))
	return hex.EncodeToString(sum[:16])
}

func (s *Store) UpsertEntity(t types.SeedType, key string, at time.Time) (types.Entity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := EntityID(t, key)
	ts := at.UnixNano()
	_, err := s.db.Exec(`
INSERT INTO entities (id, type, key, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)
ON CONFLICT(type, key) DO UPDATE SET last_seen = excluded.last_seen
`, id, string(t), key, ts, ts)
	if err != nil {
		return types.Entity{}, err
	}
	s.recordEntityLocked(id)
	return types.Entity{ID: id, Type: t, Key: key, FirstSeen: at, LastSeen: at}, nil
}

// UpsertMany adds entities of one type in one transaction and, when from
// is set, an edge of edgeType from it to each: the names a source gave
// for a domain.
func (s *Store) UpsertMany(t types.SeedType, keys []string, at time.Time, from, edgeType string) error {
	if len(keys) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	ts := at.UnixNano()
	ent, err := tx.Prepare(`INSERT INTO entities (id, type, key, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)
ON CONFLICT(type, key) DO UPDATE SET last_seen = excluded.last_seen`)
	if err != nil {
		return err
	}
	defer ent.Close()
	runEnt, err := tx.Prepare(`INSERT OR IGNORE INTO run_entities (run_id, entity_id) VALUES (?, ?)`)
	if err != nil {
		return err
	}
	defer runEnt.Close()
	edge, err := tx.Prepare(`INSERT OR IGNORE INTO edges (from_id, to_id, type, observed_at) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer edge.Close()
	runEdge, err := tx.Prepare(`INSERT OR IGNORE INTO run_edges (run_id, from_id, to_id, type) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer runEdge.Close()
	for _, k := range keys {
		id := EntityID(t, k)
		if _, err := ent.Exec(id, string(t), k, ts, ts); err != nil {
			return err
		}
		if s.runID != "" {
			if _, err := runEnt.Exec(s.runID, id); err != nil {
				return err
			}
		}
		if from == "" {
			continue
		}
		if _, err := edge.Exec(from, id, edgeType, ts); err != nil {
			return err
		}
		if s.runID != "" {
			if _, err := runEdge.Exec(s.runID, from, id, edgeType); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func (s *Store) AddObservation(entityID string, o types.Observation) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw := o.Payload
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	// Within a run, the same fact is stored once (a task run again after
	// an interruption reports it again); facts ingested outside a run keep
	// their time.
	stamp := s.runID
	if stamp == "" {
		stamp = o.ObservedAt.UTC().Format(time.RFC3339Nano)
	}
	sum := sha256.Sum256([]byte(entityID + o.Collector + o.Kind + string(o.Payload) + stamp))
	id := hex.EncodeToString(sum[:16])
	_, err := s.db.Exec(`
INSERT OR IGNORE INTO observations (id, entity_id, collector, source, kind, payload, confidence, observed_at, run_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, entityID, o.Collector, o.Source, o.Kind, string(raw), o.Confidence, o.ObservedAt.UnixNano(), s.runID)
	if err == nil {
		s.recordEntityLocked(entityID)
	}
	return id, err
}

func (s *Store) AddEdge(from, to, edgeType string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`
INSERT OR IGNORE INTO edges (from_id, to_id, type, observed_at) VALUES (?, ?, ?, ?)`,
		from, to, edgeType, at.UnixNano())
	if err == nil && s.runID != "" {
		_, err = s.db.Exec(`INSERT OR IGNORE INTO run_edges (run_id, from_id, to_id, type) VALUES (?, ?, ?, ?)`,
			s.runID, from, to, edgeType)
	}
	return err
}

func (s *Store) recordEntityLocked(entityID string) {
	if s.runID == "" || entityID == "" {
		return
	}
	_, _ = s.db.Exec(`INSERT OR IGNORE INTO run_entities (run_id, entity_id) VALUES (?, ?)`, s.runID, entityID)
}

// Seen reports whether this run already did a piece of work. A database
// used for many runs (a workspace) redoes the work on every run.
func (s *Store) Seen(key string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	err := s.db.QueryRow(`SELECT 1 FROM idempotency WHERE key = ?`, s.runID+key).Scan(&n)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func (s *Store) MarkSeen(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT OR IGNORE INTO idempotency (key) VALUES (?)`, s.runID+key)
	return err
}

// Entities, Observations and Edges list what the current run saw, or
// everything in the database when no run is selected (export, ingest).
func (s *Store) Entities() ([]types.Entity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q, args := `SELECT id, type, key, first_seen, last_seen FROM entities ORDER BY type, key`, []any{}
	if s.runID != "" {
		q = `SELECT e.id, e.type, e.key, e.first_seen, e.last_seen FROM entities e
JOIN run_entities r ON r.entity_id = e.id AND r.run_id = ? ORDER BY e.type, e.key`
		args = append(args, s.runID)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Entity
	for rows.Next() {
		var e types.Entity
		var t string
		var fs, ls int64
		if err := rows.Scan(&e.ID, &t, &e.Key, &fs, &ls); err != nil {
			return nil, err
		}
		e.Type = types.SeedType(t)
		e.FirstSeen = time.Unix(0, fs)
		e.LastSeen = time.Unix(0, ls)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) Observations() ([]types.StoredObservation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q, args := `SELECT id, entity_id, collector, source, kind, payload, confidence, observed_at FROM observations ORDER BY observed_at`, []any{}
	if s.runID != "" {
		q = `SELECT id, entity_id, collector, source, kind, payload, confidence, observed_at FROM observations WHERE run_id = ? ORDER BY observed_at`
		args = append(args, s.runID)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.StoredObservation
	for rows.Next() {
		var so types.StoredObservation
		var payload string
		var ts int64
		if err := rows.Scan(&so.ID, &so.EntityID, &so.Collector, &so.Source, &so.Kind, &payload, &so.Confidence, &ts); err != nil {
			return nil, err
		}
		so.Payload = json.RawMessage(payload)
		so.ObservedAt = time.Unix(0, ts)
		out = append(out, so)
	}
	return out, rows.Err()
}

func (s *Store) Edges() ([]types.Edge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q, args := `SELECT from_id, to_id, type, observed_at FROM edges`, []any{}
	if s.runID != "" {
		q = `SELECT e.from_id, e.to_id, e.type, e.observed_at FROM edges e
JOIN run_edges r ON r.from_id = e.from_id AND r.to_id = e.to_id AND r.type = e.type AND r.run_id = ?`
		args = append(args, s.runID)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Edge
	for rows.Next() {
		var e types.Edge
		var ts int64
		if err := rows.Scan(&e.From, &e.To, &e.Type, &ts); err != nil {
			return nil, err
		}
		e.ObservedAt = time.Unix(0, ts)
		out = append(out, e)
	}
	return out, rows.Err()
}

type Stats struct {
	Kind         string `json:"kind"`
	RunID        string `json:"run_id,omitempty"`
	DB           string `json:"db,omitempty"`
	Entities     int    `json:"entities"`
	Observations int    `json:"observations"`
	Edges        int    `json:"edges"`
	Errors       int    `json:"errors"`
	Degraded     int    `json:"degraded"`
	Capped       bool   `json:"capped"`
	Depth        int    `json:"depth"`
	MaxItems     int    `json:"max_items,omitempty"`
	Requests     int64  `json:"requests"` // sent to targets by this process
	MaxRequests  int64  `json:"max_requests,omitempty"`
}

func (st Stats) Line() string {
	sum := fmt.Sprintf("entities=%d observations=%d edges=%d errors=%d degraded=%d", st.Entities, st.Observations, st.Edges, st.Errors, st.Degraded)
	if st.Requests > 0 {
		sum += fmt.Sprintf(" requests=%d", st.Requests)
	}
	if st.Capped {
		sum += " capped=1"
	}
	if st.RunID != "" {
		sum += " run_id=" + st.RunID
	}
	return sum
}

func (s *Store) Stats() (Stats, error) {
	s.mu.Lock()
	id := s.runID
	s.mu.Unlock()
	if id != "" {
		return s.statsForRun(id)
	}
	ents, err := s.Entities()
	if err != nil {
		return Stats{}, err
	}
	obs, err := s.Observations()
	if err != nil {
		return Stats{}, err
	}
	edges, err := s.Edges()
	if err != nil {
		return Stats{}, err
	}
	errors, degraded := CountIssues(obs)
	st := Stats{
		Kind:         "summary",
		RunID:        s.GetMeta("run_id"),
		Entities:     len(ents),
		Observations: len(obs),
		Edges:        len(edges),
		Errors:       errors,
		Degraded:     degraded,
		Capped:       s.GetMeta("capped") == "1",
	}
	if n := s.GetMeta("depth"); n != "" {
		fmt.Sscanf(n, "%d", &st.Depth)
	}
	if n := s.GetMeta("max_items"); n != "" {
		fmt.Sscanf(n, "%d", &st.MaxItems)
	}
	return st, nil
}

func (s *Store) statsForRun(id string) (Stats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Stats{Kind: "summary", RunID: id}
	var capped int
	err := s.db.QueryRow(`SELECT capped, depth, max_items FROM runs WHERE id = ?`, id).Scan(&capped, &st.Depth, &st.MaxItems)
	if err != nil && err != sql.ErrNoRows {
		return Stats{}, err
	}
	st.Capped = capped == 1
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM run_entities WHERE run_id = ?`, id).Scan(&st.Entities); err != nil {
		return Stats{}, err
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM run_edges WHERE run_id = ?`, id).Scan(&st.Edges); err != nil {
		return Stats{}, err
	}
	rows, err := s.db.Query(`SELECT collector, kind, payload FROM observations WHERE run_id = ?`, id)
	if err != nil {
		return Stats{}, err
	}
	defer rows.Close()
	var obs []types.StoredObservation
	for rows.Next() {
		var so types.StoredObservation
		var payload string
		if err := rows.Scan(&so.Collector, &so.Kind, &payload); err != nil {
			return Stats{}, err
		}
		so.Payload = json.RawMessage(payload)
		obs = append(obs, so)
	}
	if err := rows.Err(); err != nil {
		return Stats{}, err
	}
	st.Observations = len(obs)
	st.Errors, st.Degraded = CountIssues(obs)
	return st, nil
}

func (s *Store) Summary() (string, error) {
	st, err := s.Stats()
	if err != nil {
		return "", err
	}
	return st.Line(), nil
}

func (s *Store) SetMeta(k, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, k, v)
	return err
}

func (s *Store) GetMeta(k string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var v string
	if err := s.db.QueryRow(`SELECT v FROM meta WHERE k = ?`, k).Scan(&v); err != nil {
		return ""
	}
	return v
}

// CountIssues classifies stored facts: hard errors vs third-party degradation.
// NXDOMAIN and reserved-TLD skips are complete answers, not failures.
func CountIssues(obs []types.StoredObservation) (errors, degraded int) {
	for _, o := range obs {
		e, d := classifyIssue(o.Observation)
		errors += e
		degraded += d
	}
	return errors, degraded
}

func classifyIssue(o types.Observation) (errors, degraded int) {
	var p map[string]any
	if err := json.Unmarshal(o.Payload, &p); err != nil {
		p = nil
	}
	if p != nil {
		if s, _ := p["skipped"].(string); s == "reserved" {
			return 0, 0
		}
		// A third-party source failed or was rate limited.
		if d, _ := p["degraded"].(bool); d {
			return 0, 1
		}
	}
	if p != nil {
		st := asInt(p["status"])
		if st == 429 || st == 503 {
			return 0, 1
		}
		if st == 403 {
			switch o.Collector {
			case "azhaq-ct", "azhaq-cdx", "azhaq-rdap":
				return 0, 1
			}
		}
	}
	if o.Kind == "error" {
		return 1, 0
	}
	if p != nil {
		if ev, ok := p["error"]; ok {
			s := strings.ToLower(fmt.Sprint(ev))
			if s == "nxdomain" || strings.Contains(s, "no such host") {
				return 0, 0
			}
			return 1, 0
		}
	}
	return 0, 0
}

func asInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	default:
		var i int
		fmt.Sscanf(fmt.Sprint(v), "%d", &i)
		return i
	}
}

type Diff struct {
	Added   []types.Entity
	Removed []types.Entity
	NewObs  []types.StoredObservation
}

func Compare(old, neu *Store) (Diff, error) {
	var d Diff
	oe, err := old.Entities()
	if err != nil {
		return d, err
	}
	ne, err := neu.Entities()
	if err != nil {
		return d, err
	}
	om := map[string]types.Entity{}
	for _, e := range oe {
		om[stableKey(e)] = e
	}
	nm := map[string]types.Entity{}
	for _, e := range ne {
		k := stableKey(e)
		nm[k] = e
		if _, ok := om[k]; !ok {
			d.Added = append(d.Added, e)
		}
	}
	for k, e := range om {
		if _, ok := nm[k]; !ok {
			d.Removed = append(d.Removed, e)
		}
	}
	oo, err := old.Observations()
	if err != nil {
		return d, err
	}
	no, err := neu.Observations()
	if err != nil {
		return d, err
	}
	seen := map[string]bool{}
	for _, o := range oo {
		seen[obsKey(o)] = true
	}
	for _, o := range no {
		if !seen[obsKey(o)] {
			d.NewObs = append(d.NewObs, o)
		}
	}
	return d, nil
}

// volatileParams change on every request of the same page: cache
// busters, timestamps, socket.io's session and poll counter.
var volatileParams = map[string]bool{"t": true, "_": true, "ts": true, "timestamp": true, "cb": true, "cachebuster": true,
	"nocache": true, "rand": true, "random": true, "nonce": true, "sid": true, "_t": true, "v": false}

// stableKey identifies an entity across runs: a URL without the query
// values that change on every request.
func stableKey(e types.Entity) string {
	k := string(e.Type) + "\x00" + e.Key
	if e.Type != types.TypeURL || !strings.Contains(e.Key, "?") {
		return k
	}
	base, q, _ := strings.Cut(e.Key, "?")
	var keep []string
	for _, kv := range strings.Split(q, "&") {
		name, _, _ := strings.Cut(kv, "=")
		if !volatileParams[strings.ToLower(name)] {
			keep = append(keep, kv)
		}
	}
	if len(keep) == 0 {
		return string(e.Type) + "\x00" + base
	}
	return string(e.Type) + "\x00" + base + "?" + strings.Join(keep, "&")
}

func obsKey(o types.StoredObservation) string {
	return o.Collector + "\x00" + o.Kind + "\x00" + stablePayload(o.Payload)
}

// volatile payload fields change between identical runs: a body hash or
// size on a page with a CSRF token or captcha, the session a run was given,
// response times, the CDN address that answered, the identifiers an
// answer held (a captcha id).
var volatile = []string{"body_hash", "auth", "length", "words", "lines", "ms", "ip", "json_ids"}

// stablePayload is the payload as diff compares it: volatile fields
// dropped, per-source timings dropped and response headers reduced to
// their names (rate-limit counters and request IDs change on every
// request).
func stablePayload(raw json.RawMessage) string {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return string(raw)
	}
	for _, k := range volatile {
		delete(m, k)
	}
	if srcs, ok := m["sources"].(map[string]any); ok {
		for _, v := range srcs {
			if row, ok := v.(map[string]any); ok {
				delete(row, "seconds")
			}
		}
	}
	if h, ok := m["headers"].(map[string]any); ok {
		names := make([]string, 0, len(h))
		for k := range h {
			names = append(names, k)
		}
		sort.Strings(names)
		m["headers"] = names
	}
	out, err := json.Marshal(m)
	if err != nil {
		return string(raw)
	}
	return string(out)
}

// SeedsKey identifies what a run was pointed at, so diffs compare runs of
// the same target.
func SeedsKey(seeds []types.Seed) string {
	lines := make([]string, 0, len(seeds))
	for _, s := range seeds {
		lines = append(lines, string(s.Type)+" "+s.Key())
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// Spent is how many requests runs on this database sent to a program's
// targets on a day (YYYY-MM-DD, UTC).
func (s *Store) Spent(program, day string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	_ = s.db.QueryRow(`SELECT requests FROM spend WHERE program = ? AND day = ?`, program, day).Scan(&n)
	return n
}

// AddSpent adds a run's requests to a program's day.
func (s *Store) AddSpent(program, day string, n int64) error {
	if n <= 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO spend (program, day, requests) VALUES (?, ?, ?)
ON CONFLICT(program, day) DO UPDATE SET requests = requests + excluded.requests`, program, day, n)
	return err
}

// SaveInput records the seeds the run was given (see SeedsKey).
func (s *Store) SaveInput(key string) error { return s.SetMeta("input", key) }

// Input is the SeedsKey of the run, or "" for databases written by ingest
// or by older versions.
func (s *Store) Input() string { return s.GetMeta("input") }

func (s *Store) SaveSeeds(seeds []types.Seed) error {
	raw, err := json.Marshal(seeds)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.Exec(`INSERT INTO meta (k, v) VALUES ('seeds', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, string(raw))
	return err
}

func (s *Store) SaveLeftover(seeds []types.Seed) error {
	if seeds == nil {
		seeds = []types.Seed{}
	}
	raw, err := json.Marshal(seeds)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.Exec(`INSERT INTO meta (k, v) VALUES ('leftover', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, string(raw))
	return err
}

func (s *Store) LoadLeftover() ([]types.Seed, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var raw string
	err := s.db.QueryRow(`SELECT v FROM meta WHERE k = 'leftover'`).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var seeds []types.Seed
	if err := json.Unmarshal([]byte(raw), &seeds); err != nil {
		return nil, err
	}
	return seeds, nil
}

func (s *Store) LoadSeeds() ([]types.Seed, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var raw string
	err := s.db.QueryRow(`SELECT v FROM meta WHERE k = 'seeds'`).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var seeds []types.Seed
	if err := json.Unmarshal([]byte(raw), &seeds); err != nil {
		return nil, err
	}
	return seeds, nil
}
