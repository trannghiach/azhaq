package engine_test

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// remoteGet is a collector that asks the page with the cookie of the process
// it runs in, as a worker does, and reports what it saw of the session.
type remoteGet struct {
	app    *sessionApp
	cookie func() string
	local  func(types.Seed) // the run's own process: told the seed
}

func (remoteGet) Name() string       { return "test-get" }
func (remoteGet) Info() catalog.Info { return catalog.Info{Kind: catalog.Touch} }
func (remoteGet) Inputs() []types.SeedType {
	return []types.SeedType{types.TypeURL}
}
func (remoteGet) Outputs() []string { return nil }
func (c remoteGet) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	if c.local != nil {
		c.local(seed)
		return types.RunMeta{Status: types.StatusOK}, nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, seed.Key(), nil)
	req.Header.Set("Cookie", "sid="+c.cookie())
	resp, err := c.app.srv.Client().Transport.RoundTrip(req)
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	resp.Body.Close()
	p, _ := json.Marshal(map[string]any{"url": seed.Key(), "status": resp.StatusCode, "location": resp.Header.Get("Location"), "cleared": len(resp.Header["Set-Cookie"]) > 0})
	meta := types.RunMeta{Status: types.StatusOK}
	if strings.HasSuffix(seed.Key(), "/") {
		for _, p := range []string{"/a", "/logout", "/b", "/c"} {
			meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": c.app.srv.URL + p}})
		}
	}
	return meta, emit(types.Observation{Kind: "page", Payload: p})
}

// worker runs the claimed tasks as azhaq worker does: with its own
// session, fetching the run's new one when a task says it was renewed, and
// telling what its answers said of the session.
func worker(w *engine.Workers, app *sessionApp, gens *[]int, mu *sync.Mutex, stop <-chan struct{}, received func()) {
	cookie, have := "s1", 0
	cat := catalog.New()
	cat.MustRegister(remoteGet{app: app, cookie: func() string { return cookie }})
	for {
		select {
		case <-stop:
			return
		default:
		}
		task, err := w.Claim(context.Background(), 100*time.Millisecond)
		if err != nil {
			return
		}
		if task == nil {
			continue
		}
		if task.Session != have {
			have = task.Session
			// what GET /v1/run serves: the run's headers now
			for _, l := range fetch.ExtraLines() {
				if v, ok := strings.CutPrefix(l, "Cookie: sid="); ok {
					cookie = v
				}
			}
		}
		received()
		mu.Lock()
		*gens = append(*gens, task.Session)
		mu.Unlock()
		out := engine.Execute(context.Background(), cat, task.Item)
		out.Requests = 1
		rep := &fetch.SessionReport{Asked: []string{task.Item.Seed.Key()}}
		for _, o := range out.Observations {
			var p struct {
				Status   int
				Location string
				Cleared  bool
			}
			_ = json.Unmarshal(o.Payload, &p)
			if p.Cleared {
				rep.EndedBy = task.Item.Seed.Key()
			}
			rep.Due = rep.Due || p.Cleared || p.Status == 401 || strings.HasSuffix(p.Location, "/login")
		}
		out.Session = rep
		w.Done(context.Background(), task.ID, out)
	}
}

// runWithWorker runs the run with all its work lent to one worker: the
// run's own slot holds a decoy until release, so nothing is asked from here.
func runWithWorker(t *testing.T, app *sessionApp, s fetch.Session, until func() bool, received func()) (*store.Store, []int, error) {
	t.Helper()
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	fetch.SetExtra(http.Header{"Cookie": {"sid=s1"}})
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	_ = st.BeginRun("r", 3, 0)
	release := make(chan struct{})
	var released atomic.Bool // after release the run's own slot may take what is left
	var localOnce sync.Once
	cat := catalog.New()
	cat.MustRegister(remoteGet{app: app, local: func(sd types.Seed) {
		if strings.Contains(sd.Key(), "decoy") {
			<-release
			return
		}
		// Asked here, a request is refused once the session is lost.
		if fetch.SessionLost() == nil && !released.Load() {
			t.Errorf("%s ran in the run's own process", sd.Key())
		}
	}})
	w := engine.NewWorkers()
	eng := &engine.Engine{Cat: cat, Store: st, Workers: w}
	var mu sync.Mutex
	var gens []int
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); worker(w, app, &gens, &mu, stop, received) }()
	go func() {
		for !until() {
			time.Sleep(20 * time.Millisecond)
		}
		localOnce.Do(func() { released.Store(true); close(release) })
	}()
	fetch.WatchSession(s)
	seeds := []types.Seed{
		{Type: types.TypeURL, Keys: map[string]string{"url": "http://decoy.invalid/"}},
		{Type: types.TypeURL, Keys: map[string]string{"url": app.srv.URL + "/"}},
	}
	done := make(chan error, 1)
	go func() {
		done <- eng.RunLocal(context.Background(), seeds, engine.Budgets{MaxDepth: 3, MaxItems: 64, Parallel: 1})
	}()
	select {
	case err = <-done:
	case <-time.After(20 * time.Second):
		localOnce.Do(func() { released.Store(true); close(release) })
		t.Fatal("the run did not end")
	}
	close(stop)
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	return st, append([]int(nil), gens...), err
}

// A worker that is answered without its session says so; the run checks,
// signs in again, hands the new session to the worker with its next task
// and asks again the pages the worker asked since the last good check.
func TestWorkersSessionEndsAndIsRenewed(t *testing.T) {
	app := newSessionApp(t)
	var renewed atomic.Int32 // Renew runs on the scheduler's goroutine
	s := fetch.Session{Check: app.srv.URL + "/", Want: fetch.Print{Status: 200}, Every: 1000, SignIn: app.srv.URL + "/login",
		Renew: func(context.Context) error {
			renewed.Add(1)
			app.mu.Lock()
			app.live["s2"] = true
			app.mu.Unlock()
			fetch.SetExtra(http.Header{"Cookie": {"sid=s2"}})
			return nil
		}}
	st, gens, err := runWithWorker(t, app, s, func() bool {
		return renewed.Load() > 0 && len(app.signedInAsked()) >= 4 && fetch.SessionLost() == nil && redone(app)
	}, func() {})
	if err != nil {
		t.Fatal(err)
	}
	if renewed.Load() != 1 || fetch.SessionGen() != 1 {
		t.Fatalf("signed in again %d times, generation %d", renewed.Load(), fetch.SessionGen())
	}
	late := 0
	for _, g := range gens {
		if g == 1 {
			late++
		}
	}
	if late == 0 || gens[0] != 0 {
		t.Errorf("tasks lent under sessions %v: some must carry the renewed one", gens)
	}
	asked := app.signedInAsked()
	for _, p := range []string{"/", "/a", "/b", "/c"} {
		if !asked[p] {
			t.Errorf("%s was never asked with a live session: %v", p, app.asked)
		}
	}
	if st.TasksLeft() != 0 {
		t.Errorf("%d tasks left", st.TasksLeft())
	}
	if n := strings.Join(fetch.Notes(), "\n"); !strings.Contains(n, "signed in again; ") {
		t.Errorf("notes %q", n)
	}
}

// redone says the pages after /logout were answered to a live session.
func redone(a *sessionApp) bool {
	asked := a.signedInAsked()
	return asked["/b"] && asked["/c"]
}

// A session that cannot be signed in again ends the signed-in work: the
// run lends nothing more, and says why.
func TestWorkersSessionLostIsNotRenewed(t *testing.T) {
	app := newSessionApp(t)
	s := fetch.Session{Check: app.srv.URL + "/", Want: fetch.Print{Status: 200}, Every: 1000, SignIn: app.srv.URL + "/login",
		Why: "the session was given with -cookie or -header"}
	var lostAt, late atomic.Int64
	_, _, err := runWithWorker(t, app, s, func() bool {
		if fetch.SessionLost() != nil {
			lostAt.CompareAndSwap(0, time.Now().UnixNano())
			return time.Since(time.Unix(0, lostAt.Load())) > 400*time.Millisecond
		}
		return false
	}, func() {
		if fetch.SessionLost() != nil {
			late.Add(1)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if lost := fetch.SessionLost(); lost == nil || !strings.Contains(lost.Error(), "-cookie") {
		t.Fatalf("lost: %v", lost)
	}
	if late.Load() != 0 {
		t.Errorf("%d tasks were lent after the session was lost", late.Load())
	}
}
