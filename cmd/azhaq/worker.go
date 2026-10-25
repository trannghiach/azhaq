package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/fetch"
)

// workerConfig is what a worker needs to build the run's collectors: the
// options (without seeds, sessions or coordinator-only ones), the files
// they name, and the session headers.
type workerConfig struct {
	Args    []string          `json:"args"`
	Files   map[string][]byte `json:"files,omitempty"` // flag → file contents
	Headers []string          `json:"headers,omitempty"`
}

// Options a worker never takes: seeds, outputs, the database, sessions
// (sent as headers), the budget (kept by the run) and what only the run's
// own process does (sign in, Chrome, third-party sources, DNS).
var coordinatorOnly = map[string]bool{
	"db": true, "serve": true, "worker-token": true, "resume-run": true, "worker-of": true,
	"url": true, "domain": true, "list": true, "in": true, "org": true, "cloud": true, "asn": true, "cidr": true,
	"scope": true, "program": true, "facts": true, "exec": true, "demo": true,
	"login": true, "login-user": true, "login-pass": true, "cookie": true, "header": true,
	"urls": true, "screenshots": true, "browser": true, "tabs": true,
	"max-requests": true, "daily-requests": true, "json": true, "quiet": true, "obs": true,
	"providers": true, "sources": true, "exclude-sources": true, "all-sources": true,
	"allow": true, "deny": true, "parallel": true, "fail-on-errors": true, "fail-on-capped": true,
}

// File options: the worker gets the file's contents.
var fileOptions = map[string]bool{"dirs": true, "params": true, "paths": true, "dns-brute": true, "resolvers": true}

// forWorkers builds the configuration workers get from the run's own
// options, its scope (as -allow and -deny rules) and its session.
func forWorkers(fs *flag.FlagSet, args, allow, deny []string) (workerConfig, error) {
	cfg := workerConfig{Files: map[string][]byte{}}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			continue
		}
		name, val, inline := strings.Cut(strings.TrimLeft(a, "-"), "=")
		f := fs.Lookup(name)
		if f == nil {
			continue
		}
		isBool := false
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			isBool = true
		}
		if !isBool && !inline && i+1 < len(args) {
			val = args[i+1]
			i++
		}
		switch {
		case coordinatorOnly[name]:
		case fileOptions[name]:
			raw, err := os.ReadFile(val)
			if err != nil {
				return cfg, fmt.Errorf("-%s: %w", name, err)
			}
			cfg.Files[name] = raw
		case isBool && !inline:
			cfg.Args = append(cfg.Args, "-"+name)
		default:
			cfg.Args = append(cfg.Args, "-"+name+"="+val)
		}
	}
	for _, r := range allow {
		cfg.Args = append(cfg.Args, "-allow="+r)
	}
	for _, r := range deny {
		cfg.Args = append(cfg.Args, "-deny="+r)
	}
	for k, vs := range fetch.Extra {
		for _, v := range vs {
			cfg.Headers = append(cfg.Headers, k+": "+v)
		}
	}
	return cfg, nil
}

// serveWorkers lets azhaq worker processes take the run's work over HTTP;
// every request carries the token.
func serveWorkers(addr, token string, w *engine.Workers, cfg workerConfig) (stop func(), err error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	auth := func(r *http.Request) bool {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		return subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/run", func(rw http.ResponseWriter, r *http.Request) {
		if !auth(r) {
			http.Error(rw, "token", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(rw).Encode(cfg)
	})
	mux.HandleFunc("POST /v1/claim", func(rw http.ResponseWriter, r *http.Request) {
		if !auth(r) {
			http.Error(rw, "token", http.StatusUnauthorized)
			return
		}
		task, err := w.Claim(r.Context(), 20*time.Second)
		switch {
		case errors.Is(err, engine.ErrRunOver):
			rw.WriteHeader(http.StatusGone)
		case err != nil || task == nil:
			rw.WriteHeader(http.StatusNoContent)
		default:
			_ = json.NewEncoder(rw).Encode(task)
		}
	})
	mux.HandleFunc("POST /v1/done", func(rw http.ResponseWriter, r *http.Request) {
		if !auth(r) {
			http.Error(rw, "token", http.StatusUnauthorized)
			return
		}
		var out engine.Outcome
		if err := json.NewDecoder(io.LimitReader(r.Body, 256<<20)).Decode(&out); err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		if !w.Done(r.Context(), r.URL.Query().Get("id"), out) {
			rw.WriteHeader(http.StatusGone)
			return
		}
		rw.WriteHeader(http.StatusNoContent)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}, nil
}

func newToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// The worker side: set by cmdWorker for the cmdRun it starts.
var workerHeaders []string

// cmdWorker joins a run started with -serve and runs the work it hands out.
//
//	azhaq worker -server http://10.0.0.5:7777 -token T [-slots 8]
func cmdWorker(args []string) error {
	fs := flag.NewFlagSet("worker", flag.ContinueOnError)
	server := fs.String("server", "", "the run's address (azhaq run -serve)")
	token := fs.String("token", os.Getenv("AZHAQ_WORKER_TOKEN"), "the run's worker token (default $AZHAQ_WORKER_TOKEN)")
	slots := fs.Int("slots", 8, "tasks run at once")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *server == "" || *token == "" {
		return fmt.Errorf("usage: azhaq worker -server http://HOST:PORT -token T [-slots N]")
	}
	base := strings.TrimSuffix(*server, "/")
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	var cfg workerConfig
	if err := call(context.Background(), http.MethodGet, base+"/v1/run", *token, nil, &cfg); err != nil {
		return fmt.Errorf("joining %s: %w", base, err)
	}
	dir, err := os.MkdirTemp("", "azhaq-worker-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	runArgs := append([]string(nil), cfg.Args...)
	for name, raw := range cfg.Files {
		p := filepath.Join(dir, name+".txt")
		if err := os.WriteFile(p, raw, 0o600); err != nil {
			return err
		}
		runArgs = append(runArgs, "-"+name+"="+p)
	}
	workerHeaders = cfg.Headers
	runArgs = append(runArgs, "-worker-of="+base, "-worker-token="+*token, "-parallel="+strconv.Itoa(*slots),
		"-db="+filepath.Join(dir, "worker.db"), "-quiet")
	return cmdRun(runArgs)
}

// runWorker claims tasks from the run at base and runs them with cat, in
// slots goroutines, until the run is over.
func runWorker(cat *catalog.Catalog, base, token string, slots int) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	fmt.Fprintf(os.Stderr, "azhaq worker: joined %s, %d slots\n", base, slots)
	var done atomic.Int64
	var wg sync.WaitGroup
	errs := make(chan error, slots)
	for i := 0; i < max(1, slots); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			failures := 0
			for ctx.Err() == nil {
				var task engine.Task
				err := call(ctx, http.MethodPost, base+"/v1/claim", token, nil, &task)
				switch {
				case errors.Is(err, errGone):
					return
				case errors.Is(err, errNoContent):
					failures = 0
					continue
				case err != nil:
					// The run may have ended between two claims.
					if failures++; failures > 12 {
						errs <- err
						return
					}
					sleepCtx(ctx, 5*time.Second)
					continue
				}
				failures = 0
				out := engine.Execute(ctx, cat, task.Item)
				if err := call(ctx, http.MethodPost, base+"/v1/done?id="+task.ID, token, out, nil); err != nil && !errors.Is(err, errGone) && !errors.Is(err, errNoContent) {
					fmt.Fprintf(os.Stderr, "azhaq worker: sending %s: %v\n", task.Item.Collector, err)
				}
				if n := done.Add(1); n%50 == 0 {
					fmt.Fprintf(os.Stderr, "azhaq worker: %d tasks done\n", n)
				}
			}
		}()
	}
	wg.Wait()
	fmt.Fprintf(os.Stderr, "azhaq worker: the run is over; %d tasks done here\n", done.Load())
	select {
	case err := <-errs:
		return fmt.Errorf("lost the run at %s: %w", base, err)
	default:
		return nil
	}
}

var (
	errGone      = errors.New("gone")
	errNoContent = errors.New("no content")
)

// call sends one request to the run and decodes its JSON answer.
func call(ctx context.Context, method, url, token string, body, out any) error {
	var r io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, r)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 2 * time.Minute}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		if out == nil {
			return nil
		}
		return json.NewDecoder(resp.Body).Decode(out)
	case http.StatusNoContent:
		return errNoContent
	case http.StatusGone:
		return errGone
	default:
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
