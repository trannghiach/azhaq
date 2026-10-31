package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

func TestForWorkers(t *testing.T) {
	fetch.Reset()
	defer fetch.Reset()
	words := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(words, []byte("admin\nbackup\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fs := newFlags("run")
	fs.String("url", "", "")
	fs.String("db", "", "")
	fs.String("dirs", "", "")
	fs.Bool("no-tech", false, "")
	fs.Int("depth", 4, "")
	fs.String("login-pass", "", "")
	fs.String("serve", "", "")
	fs.Var(new(stringsFlag), "deny-path", "")
	args := []string{"-url", "https://app.test/", "-db", "x.db", "-dirs", words, "-no-tech", "-depth=2", "-login-pass", "pw", "-serve", ":7777", "-deny-path", "^/x"}
	if err := parse(fs, args); err != nil {
		t.Fatal(err)
	}
	if err := applyExtra([]string{"sid=1"}, nil); err != nil {
		t.Fatal(err)
	}
	cfg, err := forWorkers(fs, args, []string{"app.test"}, []string{"=admin.app.test"})
	if err != nil {
		t.Fatal(err)
	}
	// -deny-path travels as its own setting (workerConfig.DenyPath), not twice.
	if want := []string{"-no-tech", "-depth=2", "-allow=app.test", "-deny==admin.app.test"}; !reflect.DeepEqual(cfg.Args, want) {
		t.Errorf("args %q", cfg.Args)
	}
	if string(cfg.Files["dirs"]) != "admin\nbackup\n" || !reflect.DeepEqual(cfg.Headers, []string{"Cookie: sid=1"}) {
		t.Errorf("files %v headers %v", cfg.Files, cfg.Headers)
	}
}

type echo struct{}

func (echo) Name() string             { return "test-echo" }
func (echo) Info() catalog.Info       { return catalog.Info{Kind: catalog.Touch} }
func (echo) Inputs() []types.SeedType { return []types.SeedType{types.TypeURL} }
func (echo) Outputs() []string        { return nil }
func (echo) Run(_ context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	return types.RunMeta{Status: types.StatusOK}, emit(types.Observation{Kind: "seen", Payload: []byte(`{"url":"` + seed.Key() + `"}`)})
}

func TestWorkerProtocol(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_ = st.BeginRun("r", 4, 0)
	cat := catalog.New()
	cat.MustRegister(echo{})
	w := engine.NewWorkers()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	stop, err := serveWorkers(addr, "tok", w, workerConfig{Args: []string{"-no-tech"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	base := "http://" + addr

	var cfg workerConfig
	if err := call(context.Background(), "GET", base+"/v1/run", "wrong", nil, &cfg); err == nil {
		t.Fatal("a wrong token was let in")
	}
	if err := call(context.Background(), "GET", base+"/v1/run", "tok", nil, &cfg); err != nil || len(cfg.Args) != 1 {
		t.Fatalf("config %v %v", cfg, err)
	}

	// The run keeps one task for itself: the worker gets the other.
	eng := &engine.Engine{Cat: cat, Store: st, Workers: w}
	b := engine.DefaultBudgets()
	b.Parallel = 1
	seeds := []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": "https://a.test/1"}}, {Type: types.TypeURL, Keys: map[string]string{"url": "https://a.test/2"}}}
	ran := make(chan error, 1)
	go func() { ran <- eng.RunLocal(context.Background(), seeds, b) }()
	got := 0
	for {
		var task engine.Task
		err := call(context.Background(), "POST", base+"/v1/claim", "tok", nil, &task)
		if errors.Is(err, errGone) {
			break
		}
		if errors.Is(err, errNoContent) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		got++
		if err := call(context.Background(), "POST", base+"/v1/done?id="+task.ID, "tok", engine.Execute(context.Background(), cat, task.Item), nil); !errors.Is(err, errNoContent) {
			t.Fatalf("done: %v", err)
		}
	}
	select {
	case err := <-ran:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the run did not end")
	}
	stats, _ := st.Stats()
	if stats.Observations != 2 || st.TasksLeft() != 0 {
		t.Errorf("%d observations, %d tasks left (worker ran %d)", stats.Observations, st.TasksLeft(), got)
	}
}
