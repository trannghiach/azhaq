package main

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// scaleRow is a run that does not happen in one go, on Juice Shop behind
// a proxy that counts the requests it receives: stopped by a request
// budget and resumed until done, killed and resumed, and shared with two
// workers. Each must map what one uninterrupted run maps.
type scaleRow struct {
	URLs int `json:"urls"` // one uninterrupted run

	Budget       int  `json:"budget"`         // -max-requests per process
	Processes    int  `json:"processes"`      // the run and its resumes
	MostReceived int  `json:"most_received"`  // requests Juice Shop received from one process
	BudgetSame   bool `json:"budget_same"`    // same URLs as one run
	BudgetMissed int  `json:"budget_missing"` // URLs one run has and this one lacks

	KilledAfter float64 `json:"killed_after_seconds"`
	KilledSame  bool    `json:"killed_same"`

	WorkerTasks int     `json:"worker_tasks"` // tasks the two workers ran
	WorkersSame bool    `json:"workers_same"`
	Seconds     float64 `json:"workers_seconds"`
	OneSeconds  float64 `json:"one_seconds"`
}

func benchScale(target string) *scaleRow {
	row := &scaleRow{Budget: 100}
	dir, _ := filepath.Abs(filepath.Join(work, "scale"))
	must(os.RemoveAll(dir))
	must(os.MkdirAll(dir, 0o755))

	// The proxy counts what reaches the app.
	up, err := url.Parse(target)
	must(err)
	var received atomic.Int64
	proxy := httputil.NewSingleHostReverseProxy(up)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	defer ln.Close()
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		proxy.ServeHTTP(w, r)
	}))
	site := "http://" + ln.Addr().String() + "/"
	db := func(name string) string { return filepath.Join(dir, name+".db") }
	paths := func(name string) map[string]bool {
		out, _ := runOut(azhaq, "export", "-db", db(name))
		set := map[string]bool{}
		for _, u := range readExport(out).urls() {
			set[strings.TrimPrefix(u, strings.TrimSuffix(site, "/"))] = true
		}
		return set
	}

	// One run.
	_, m := run("scale", 10*time.Minute, dir, azhaq, "run", "-url", site, "-db", db("one"), "-quiet")
	row.OneSeconds = m.Seconds
	one := paths("one")
	row.URLs = len(one)

	// A request budget, then azhaq resume until nothing is left.
	received.Store(0)
	run("scale", 10*time.Minute, dir, azhaq, "run", "-url", site, "-db", db("budget"), "-max-requests", strconv.Itoa(row.Budget), "-quiet")
	row.Processes = 1
	row.MostReceived = int(received.Load())
	for i := 0; i < 100; i++ {
		received.Store(0)
		cmd := exec.Command(azhaq, "resume", "-db", db("budget"), "-quiet")
		cmd.Dir = dir
		out, _ := cmd.CombinedOutput()
		if bytes.Contains(out, []byte("nothing to resume")) || bytes.Contains(out, []byte("no task finished")) {
			break
		}
		row.Processes++
		row.MostReceived = max(row.MostReceived, int(received.Load()))
	}
	budget := paths("budget")
	row.BudgetMissed = len(one) - overlap(one, budget)
	row.BudgetSame = sameSet(one, budget)
	addCheck("scale: a run stopped by -max-requests and resumed maps what one run maps", row.BudgetSame && row.MostReceived <= row.Budget,
		"%d processes of at most %d requests (Juice Shop received at most %d from one); %d URLs, one run %d, %d missing",
		row.Processes, row.Budget, row.MostReceived, len(budget), len(one), row.BudgetMissed)

	// Killed with SIGKILL a third of the way, then resumed.
	row.KilledAfter = max(0.3, m.Seconds/3)
	cmd := exec.Command(azhaq, "run", "-url", site, "-db", db("killed"), "-quiet")
	cmd.Dir = dir
	must(cmd.Start())
	time.Sleep(time.Duration(row.KilledAfter * float64(time.Second)))
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	run("scale", 10*time.Minute, dir, azhaq, "resume", "-db", db("killed"), "-quiet")
	killed := paths("killed")
	row.KilledSame = sameSet(one, killed)
	addCheck("scale: a run killed with SIGKILL and resumed maps what one run maps", row.KilledSame,
		"killed after %.1fs; %d URLs, one run %d", row.KilledAfter, len(killed), len(one))

	// The run with two workers.
	free, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	addr := free.Addr().String()
	free.Close()
	t0 := time.Now()
	coord := exec.Command(azhaq, "run", "-url", site, "-db", db("workers"), "-parallel", "2", "-serve", addr, "-worker-token", "bench", "-quiet")
	coord.Dir = dir
	must(coord.Start())
	var workers []*exec.Cmd
	var logs []*bytes.Buffer
	for i := 0; i < 2; i++ {
		var buf bytes.Buffer
		w := exec.Command(azhaq, "worker", "-server", "http://"+addr, "-token", "bench", "-slots", "4")
		w.Stderr = &buf
		for try := 0; try < 20; try++ {
			if c, err := net.Dial("tcp", addr); err == nil {
				c.Close()
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		must(w.Start())
		workers = append(workers, w)
		logs = append(logs, &buf)
	}
	_ = coord.Wait()
	row.Seconds = time.Since(t0).Seconds()
	doneRE := regexp.MustCompile(`(\d+) tasks done here`)
	for i, w := range workers {
		_ = w.Wait()
		if m := doneRE.FindStringSubmatch(logs[i].String()); m != nil {
			n, _ := strconv.Atoi(m[1])
			row.WorkerTasks += n
		}
	}
	shared := paths("workers")
	row.WorkersSame = sameSet(one, shared)
	addCheck("scale: a run shared with two workers maps what one run maps", row.WorkersSame && row.WorkerTasks > 0,
		"%d URLs, one run %d; the workers ran %d tasks", len(shared), len(one), row.WorkerTasks)
	return row
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	var miss []string
	for k := range a {
		if !b[k] {
			miss = append(miss, k)
		}
	}
	sort.Strings(miss)
	if len(miss) > 0 && verbose {
		logf("missing: %s", strings.Join(miss, " "))
	}
	return len(miss) == 0
}
