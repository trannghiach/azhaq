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
	URLs        int `json:"urls"`         // one uninterrupted run
	OneReceived int `json:"one_received"` // requests Juice Shop received from it

	Budget       int  `json:"budget"`         // -max-requests per process
	Processes    int  `json:"processes"`      // the run and its resumes
	MostReceived int  `json:"most_received"`  // requests Juice Shop received from one process
	AllReceived  int  `json:"all_received"`   // from the run and its resumes together
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
	received.Store(0)
	_, m := run("scale", 10*time.Minute, dir, azhaq, "run", "-url", site, "-db", db("one"), "-quiet")
	row.OneSeconds = m.Seconds
	row.OneReceived = int(received.Load())
	one := paths("one")
	row.URLs = len(one)

	// A request budget, then azhaq resume until nothing is left.
	received.Store(0)
	run("scale", 10*time.Minute, dir, azhaq, "run", "-url", site, "-db", db("budget"), "-max-requests", strconv.Itoa(row.Budget), "-quiet")
	row.Processes = 1
	row.MostReceived = int(received.Load())
	row.AllReceived = row.MostReceived
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
		row.AllReceived += int(received.Load())
	}
	budget := paths("budget")
	row.BudgetMissed = len(one) - overlap(one, budget)
	row.BudgetSame = covers(one, budget)
	addCheck("scale: a run stopped by -max-requests and resumed maps everything one run maps", row.BudgetSame && row.MostReceived <= row.Budget,
		"%d processes of at most %d requests (Juice Shop received at most %d from one); %d URLs, one run %d, %d missing",
		row.Processes, row.Budget, row.MostReceived, len(budget), len(one), row.BudgetMissed)
	addCheck("scale: a stopped and resumed run sends at most 10% more than one run", float64(row.AllReceived) <= 1.1*float64(row.OneReceived),
		"%d requests over %d processes, one run %d", row.AllReceived, row.Processes, row.OneReceived)

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
	row.KilledSame = covers(one, killed)
	addCheck("scale: a run killed with SIGKILL and resumed maps everything one run maps", row.KilledSame,
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
	row.WorkersSame = covers(one, shared)
	addCheck("scale: a run shared with two workers maps everything one run maps", row.WorkersSame && row.WorkerTasks > 0,
		"%d URLs, one run %d; the workers ran %d tasks", len(shared), len(one), row.WorkerTasks)
	return row
}

// covers reports whether got holds every URL of ref: a resumed, killed-and-
// resumed or worker-shared run must map everything one run maps. Finding
// more is not a failure — a run retries a target that timed out once, and
// the single reference run, under the harness's concurrent load, may itself
// have lost one; what must never happen is losing work one run found.
func covers(ref, got map[string]bool) bool {
	var miss []string
	for k := range ref {
		if !got[k] {
			miss = append(miss, k)
		}
	}
	sort.Strings(miss)
	if len(miss) > 0 && verbose {
		logf("missing: %s", strings.Join(miss, " "))
	}
	return len(miss) == 0
}
