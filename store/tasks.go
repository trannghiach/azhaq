package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/trannghiach/azhaq/types"
)

// Task is one collector on one seed, as the scheduler planned it. The
// tasks of a run are its frontier: azhaq resume runs the ones not done.
type Task struct {
	ID        string     `json:"id"`
	Collector string     `json:"collector"`
	Seed      types.Seed `json:"seed"`
	Depth     int        `json:"depth"`
	Prio      int        `json:"prio"`
	Done      bool       `json:"done"`
	Tries     int        `json:"tries"` // times the request budget stopped it
	Need      int        `json:"need"`  // more requests than it sent before the budget stopped it
}

// Stopped is a task the request budget stopped after it had sent Used
// requests.
type Stopped struct {
	ID   string
	Used int
}

// SaveTasks records newly planned tasks, the ids of tasks that are done
// and of tasks the request budget stopped, in one transaction: a task's
// hints are never lost between it being marked done and them being
// recorded.
func (s *Store) SaveTasks(add []Task, done []string, stopped []Stopped) error {
	if len(add) == 0 && len(done) == 0 && len(stopped) == 0 {
		return nil
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
	if len(add) > 0 {
		ins, err := tx.Prepare(`INSERT OR IGNORE INTO tasks (run_id, id, collector, seed, depth, prio, done) VALUES (?, ?, ?, ?, ?, ?, 0)`)
		if err != nil {
			return err
		}
		defer ins.Close()
		for _, t := range add {
			raw, err := json.Marshal(t.Seed)
			if err != nil {
				return err
			}
			if _, err := ins.Exec(s.runID, t.ID, t.Collector, string(raw), t.Depth, t.Prio); err != nil {
				return err
			}
		}
	}
	if len(done) > 0 {
		upd, err := tx.Prepare(`UPDATE tasks SET done = 1 WHERE run_id = ? AND id = ?`)
		if err != nil {
			return err
		}
		defer upd.Close()
		for _, id := range done {
			if _, err := upd.Exec(s.runID, id); err != nil {
				return err
			}
		}
	}
	if len(stopped) > 0 {
		upd, err := tx.Prepare(`UPDATE tasks SET tries = tries + 1, need = MAX(need, ?) WHERE run_id = ? AND id = ?`)
		if err != nil {
			return err
		}
		defer upd.Close()
		for _, t := range stopped {
			if _, err := upd.Exec(t.Used+1, s.runID, t.ID); err != nil {
				return err
			}
		}
	}
	return commit()
}

// Tasks lists the current run's tasks: the ones that need the fewest
// requests first (those the budget never stopped, then the cheapest of the
// rest), then in the order they were planned. Once the budget is spent the
// rest wait, so cheap work is not starved by a long sweep.
func (s *Store) Tasks() ([]Task, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.q().Query(`SELECT id, collector, seed, depth, prio, done, tries, need FROM tasks WHERE run_id = ? ORDER BY need, rowid`, s.runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Task
	for rows.Next() {
		var t Task
		var raw string
		if err := rows.Scan(&t.ID, &t.Collector, &raw, &t.Depth, &t.Prio, &t.Done, &t.Tries, &t.Need); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &t.Seed); err != nil {
			return nil, fmt.Errorf("task %s: %w", t.ID, err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// TasksDone counts the current run's tasks that are done.
func (s *Store) TasksDone() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	_ = s.q().QueryRow(`SELECT COUNT(*) FROM tasks WHERE run_id = ? AND done = 1`, s.runID).Scan(&n)
	return n
}

// TasksLeft counts the current run's tasks that are not done.
func (s *Store) TasksLeft() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	_ = s.q().QueryRow(`SELECT COUNT(*) FROM tasks WHERE run_id = ? AND done = 0`, s.runID).Scan(&n)
	return n
}

// Forget clears the done-marks (see Seen) of work items in the current
// run, so a task that ran but was not recorded as done runs again whole.
func (s *Store) Forget(ids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(ids) > 0 {
		n := min(len(ids), 500)
		args := make([]any, n)
		for i, id := range ids[:n] {
			args[i] = s.runID + id
		}
		if _, err := s.q().Exec(`DELETE FROM idempotency WHERE key IN (?`+strings.Repeat(",?", n-1)+`)`, args...); err != nil {
			return err
		}
		ids = ids[n:]
	}
	return nil
}

// SetRunArgs records the options the current run was started with, for
// azhaq resume.
func (s *Store) SetRunArgs(args []string) error {
	raw, err := json.Marshal(args)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.q().Exec(`UPDATE runs SET args = ? WHERE id = ?`, string(raw), s.runID)
	return err
}

// RunArgs are the options the current run was started with (see
// SetRunArgs); nil when none were recorded.
func (s *Store) RunArgs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var raw sql.NullString
	if s.q().QueryRow(`SELECT args FROM runs WHERE id = ?`, s.runID).Scan(&raw) != nil || !raw.Valid {
		return nil
	}
	var args []string
	_ = json.Unmarshal([]byte(raw.String), &args)
	return args
}

// Resumable is the latest run with tasks not done, its options, and how
// many tasks are left; ok is false when every run finished.
func (s *Store) Resumable() (id string, args []string, left int, ok bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var raw sql.NullString
	err = s.q().QueryRow(`
SELECT r.id, r.args, (SELECT COUNT(*) FROM tasks t WHERE t.run_id = r.id AND t.done = 0) AS left
FROM runs r WHERE left > 0 ORDER BY r.started DESC LIMIT 1`).Scan(&id, &raw, &left)
	if err == sql.ErrNoRows {
		return "", nil, 0, false, nil
	}
	if err != nil {
		return "", nil, 0, false, err
	}
	if raw.Valid && raw.String != "" {
		if err := json.Unmarshal([]byte(raw.String), &args); err != nil {
			return "", nil, 0, false, err
		}
	}
	return id, args, left, true, nil
}

// Claim records owner for key in the current run unless the run has an
// owner for it already, and returns the owner (see catalog.Claim).
func (s *Store) Claim(key, owner string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runID == "" {
		return owner
	}
	if _, err := s.q().Exec(`INSERT OR IGNORE INTO claims (run_id, key, owner) VALUES (?, ?, ?)`, s.runID, key, owner); err != nil {
		return owner
	}
	got := owner
	_ = s.q().QueryRow(`SELECT owner FROM claims WHERE run_id = ? AND key = ?`, s.runID, key).Scan(&got)
	return got
}

// Reopen marks the done tasks of collector on the targets named (seed
// keys) not done, so a resume runs them again: work the run's -timeout
// cut short. It returns how many it reopened.
func (s *Store) Reopen(collector string, targets []string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	want := map[string]bool{}
	for _, t := range targets {
		want[t] = true
	}
	rows, err := s.q().Query(`SELECT id, seed FROM tasks WHERE run_id = ? AND collector = ? AND done = 1`, s.runID, collector)
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			rows.Close()
			return 0, err
		}
		var seed types.Seed
		if json.Unmarshal([]byte(raw), &seed) == nil && want[seed.Key()] {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		if _, err := s.q().Exec(`UPDATE tasks SET done = 0 WHERE run_id = ? AND id = ?`, s.runID, id); err != nil {
			return 0, err
		}
	}
	return len(ids), nil
}
