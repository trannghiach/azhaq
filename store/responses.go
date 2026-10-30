package store

import (
	"bytes"
	"compress/gzip"
	"io"
)

// Response is one answer a run got from a target: azhaq resume reads it
// back instead of asking again. Meta is the answer without its body.
type Response struct {
	URL  string
	Meta []byte
	Body []byte
}

// SaveResponses records answers of the current run, a few hundred to a
// transaction: the store is not held for a sweep's thousands at once.
func (s *Store) SaveResponses(rs []Response) error {
	const chunk = 256
	for len(rs) > 0 {
		n := min(len(rs), chunk)
		if err := s.saveResponses(rs[:n]); err != nil {
			return err
		}
		rs = rs[n:]
	}
	return nil
}

func (s *Store) saveResponses(rs []Response) error {
	packed := make([][]byte, len(rs))
	for i, r := range rs {
		packed[i] = gz(r.Body)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runID == "" {
		return nil
	}
	tx, commit, rollback, err := s.begin()
	if err != nil {
		return err
	}
	defer rollback()
	ins, err := tx.Prepare(`INSERT OR REPLACE INTO responses (run_id, url, meta, body) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer ins.Close()
	for i, r := range rs {
		if _, err := ins.Exec(s.runID, r.URL, string(r.Meta), packed[i]); err != nil {
			return err
		}
	}
	return commit()
}

// LoadResponse is the current run's recorded answer for url.
func (s *Store) LoadResponse(url string) (Response, bool) {
	s.mu.Lock()
	run := s.runID
	s.mu.Unlock()
	var meta string
	var body []byte
	err := s.db.QueryRow(`SELECT meta, body FROM responses WHERE run_id = ? AND url = ?`, run, url).Scan(&meta, &body)
	if err != nil {
		return Response{}, false
	}
	raw, err := gunzip(body)
	if err != nil {
		return Response{}, false
	}
	return Response{URL: url, Meta: []byte(meta), Body: raw}, true
}

// DropResponses forgets the answers recorded for every run but keep: they
// only serve a run that azhaq resume may still continue.
func (s *Store) DropResponses(keep string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.q().Exec(`DELETE FROM responses WHERE run_id <> ?`, keep)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		_, _ = s.q().Exec(`PRAGMA incremental_vacuum`)
	}
	return nil
}

func gz(b []byte) []byte {
	var buf bytes.Buffer
	w, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

func gunzip(b []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}
