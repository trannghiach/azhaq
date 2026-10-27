package engine

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/trannghiach/azhaq/internal/fetch"
	"github.com/trannghiach/azhaq/store"
)

// keeper records a run's answers in its workspace (fetch.Keeper), in
// batches off the request path. Only a resumed run reads them back: what
// the run asked before it was stopped is not asked again, nor counted
// against the request budget.
type keeper struct {
	st     *store.Store
	resume bool

	mu    sync.Mutex
	queue []store.Response
	kick  chan struct{}
	quit  chan struct{}
	done  chan struct{}
}

// keptMeta is a fetch.Result without its body.
type keptMeta struct {
	RequestURL  string        `json:"request_url"`
	Status      int           `json:"status"`
	URL         string        `json:"url"`
	Header      http.Header   `json:"header,omitempty"`
	StatusLine  string        `json:"status_line,omitempty"`
	Hops        []fetch.Hop   `json:"hops,omitempty"`
	Truncated   bool          `json:"truncated,omitempty"`
	FinalHeader http.Header   `json:"final_header,omitempty"`
	IP          string        `json:"ip,omitempty"`
	Elapsed     time.Duration `json:"elapsed,omitempty"`
}

// KeepResponses sets fetch.Keep to the run's workspace; resume says the
// run continues an earlier one, whose answers are read back. stop writes
// what is still queued.
func KeepResponses(st *store.Store, resume bool) (stop func()) {
	k := &keeper{st: st, resume: resume, kick: make(chan struct{}, 1), quit: make(chan struct{}), done: make(chan struct{})}
	go k.write()
	fetch.Keep = k
	fetch.Memos = k
	return func() {
		fetch.Keep = nil
		fetch.Memos = nil
		close(k.quit)
		<-k.done
	}
}

func (k *keeper) Load(raw string) (fetch.Result, bool) {
	if !k.resume {
		return fetch.Result{}, false
	}
	r, ok := k.st.LoadResponse(raw)
	if !ok {
		return fetch.Result{}, false
	}
	var m keptMeta
	if json.Unmarshal(r.Meta, &m) != nil {
		return fetch.Result{}, false
	}
	return fetch.Result{
		RequestURL: m.RequestURL, Status: m.Status, URL: m.URL, Header: m.Header, Body: r.Body,
		StatusLine: m.StatusLine, Hops: m.Hops, Truncated: m.Truncated, FinalHeader: m.FinalHeader,
		IP: m.IP, Elapsed: m.Elapsed,
	}, true
}

func (k *keeper) Keep(raw string, res fetch.Result) {
	meta, err := json.Marshal(keptMeta{
		RequestURL: res.RequestURL, Status: res.Status, URL: res.URL, Header: res.Header,
		StatusLine: res.StatusLine, Hops: res.Hops, Truncated: res.Truncated, FinalHeader: res.FinalHeader,
		IP: res.IP, Elapsed: res.Elapsed,
	})
	if err != nil {
		return
	}
	k.mu.Lock()
	k.queue = append(k.queue, store.Response{URL: raw, Meta: meta, Body: res.Body})
	n := len(k.queue)
	k.mu.Unlock()
	if n >= 64 {
		select {
		case k.kick <- struct{}{}:
		default:
		}
	}
}

// memoPrefix keeps memos apart from URLs in the responses table.
const memoPrefix = "memo:"

func (k *keeper) Recall(key string) ([]byte, bool) {
	if !k.resume {
		return nil, false
	}
	r, ok := k.st.LoadResponse(memoPrefix + key)
	return r.Meta, ok
}

func (k *keeper) Remember(key string, v []byte) {
	k.mu.Lock()
	k.queue = append(k.queue, store.Response{URL: memoPrefix + key, Meta: v})
	k.mu.Unlock()
}

func (k *keeper) write() {
	defer close(k.done)
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-k.quit:
			k.flush()
			return
		case <-k.kick:
		case <-tick.C:
		}
		k.flush()
	}
}

func (k *keeper) flush() {
	k.mu.Lock()
	batch := k.queue
	k.queue = nil
	k.mu.Unlock()
	_ = k.st.SaveResponses(batch)
}
