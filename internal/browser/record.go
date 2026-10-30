package browser

import (
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
)

// Caps on what one page's record keeps, so that a page that logs or asks
// without end does not fill the database.
const (
	maxNetLog     = 2000
	maxConsole    = 200
	maxConsoleLen = 2000
)

// Record is what Chrome saw of one page: its document's answer, the TLS
// session it came over, the requests it made and what its scripts logged.
// It is read from the events Chrome sends anyway; no request is made for it.
type Record struct {
	Status        int         `json:"response_code,omitempty"`
	Reason        string      `json:"response_reason,omitempty"`
	Protocol      string      `json:"protocol,omitempty"`
	ContentLength int64       `json:"content_length,omitempty"`
	Headers       []Header    `json:"headers,omitempty"`
	TLS           *TLS        `json:"tls,omitempty"`
	Network       []NetEntry  `json:"network,omitempty"`
	NetworkMore   int         `json:"network_more,omitempty"` // requests past the cap, not listed
	Console       []ConsoleLn `json:"console,omitempty"`
}

// Header is one response header.
type Header struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// TLS is the session of the page's document.
type TLS struct {
	Protocol    string   `json:"protocol"`
	KeyExchange string   `json:"key_exchange,omitempty"`
	Cipher      string   `json:"cipher"`
	Subject     string   `json:"subject_name"`
	SAN         []string `json:"san_list,omitempty"`
	Issuer      string   `json:"issuer"`
	ValidFrom   string   `json:"valid_from"`
	ValidTo     string   `json:"valid_to"`
	SigAlg      int64    `json:"server_signature_algorithm,omitempty"`
	ECH         bool     `json:"encrypted_client_hello,omitempty"`
}

// NetEntry is one request of the page, with how it ended.
type NetEntry struct {
	Type     string  `json:"request_type"`
	Method   string  `json:"method,omitempty"`
	Status   int     `json:"status_code,omitempty"`
	URL      string  `json:"url"`
	RemoteIP string  `json:"remote_ip,omitempty"`
	MIME     string  `json:"mime_type,omitempty"`
	Millis   float64 `json:"time_ms,omitempty"`
	Bytes    int64   `json:"bytes,omitempty"`
	Error    string  `json:"error,omitempty"`

	rt      network.ResourceType
	sub     bool // a frame's page, not the tab's own
	start   float64
	done    bool
	blocked bool // refused by azhaq: its scope, its pace of the icon; not a failure of the page
}

// ConsoleLn is one line a page's scripts wrote to the console, or an
// error they threw.
type ConsoleLn struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// pageLog collects a Record from the events of one tab.
type pageLog struct {
	mu    sync.Mutex
	main  cdp.FrameID
	rec   Record
	cur   map[network.RequestID]*NetEntry
	all   []*NetEntry
	doc   bool // the document's answer is kept: the last one of the main frame
	docID network.RequestID
	prog  *progress
}

func newPageLog(main cdp.FrameID, p *progress) *pageLog {
	return &pageLog{main: main, cur: map[network.RequestID]*NetEntry{}, prog: p}
}

func (r *pageLog) requestSent(ev *network.EventRequestWillBeSent) {
	if ev.Request == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if prev := r.cur[ev.RequestID]; prev != nil && ev.RedirectResponse != nil {
		// A redirect's next hop reuses the request's ID: the hop before it
		// ended with the answer that redirected.
		prev.Status = int(ev.RedirectResponse.Status)
		prev.done = true
		prev.Millis = ms(prev.start, float64(ev.Timestamp))
	}
	e := &NetEntry{Type: string(ev.Type), Method: ev.Request.Method, URL: ev.Request.URL, rt: ev.Type}
	e.start = float64(ev.Timestamp)
	if ev.Type == "" {
		e.Type = "Other"
	}
	e.sub = ev.Type == network.ResourceTypeDocument && ev.FrameID != r.main
	r.cur[ev.RequestID] = e
	if len(r.all) < maxNetLog {
		r.all = append(r.all, e)
	} else {
		r.rec.NetworkMore++
	}
}

func ms(from, to float64) float64 {
	if from == 0 || to < from {
		return 0
	}
	return float64(int((to-from)*10000)) / 10
}

func (r *pageLog) responded(ev *network.EventResponseReceived) {
	if ev.Response == nil {
		return
	}
	r.prog.touch()
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.cur[ev.RequestID]; e != nil {
		e.Status = int(ev.Response.Status)
		e.MIME = ev.Response.MimeType
		e.RemoteIP = ev.Response.RemoteIPAddress
	}
	if ev.Type != network.ResourceTypeDocument || ev.FrameID != r.main {
		return
	}
	resp := ev.Response
	r.rec.Status, r.rec.Reason, r.rec.Protocol = int(resp.Status), resp.StatusText, resp.Protocol
	r.rec.Headers = headerList(resp.Headers)
	r.rec.TLS = nil
	if d := resp.SecurityDetails; d != nil {
		r.rec.TLS = &TLS{
			Protocol: d.Protocol, KeyExchange: d.KeyExchange, Cipher: d.Cipher, Subject: d.SubjectName,
			SAN: d.SanList, Issuer: d.Issuer, ValidFrom: stamp(d.ValidFrom), ValidTo: stamp(d.ValidTo),
			SigAlg: d.ServerSignatureAlgorithm, ECH: d.EncryptedClientHello,
		}
	}
	r.doc, r.docID = true, ev.RequestID
}

func stamp(t cdp.TimeSinceEpoch) string {
	if t <= 0 {
		return ""
	}
	return time.Unix(int64(t), 0).UTC().Format(time.RFC3339)
}

// headerList is h as a sorted list; a header that came more than once is
// one entry per line of it.
func headerList(h network.Headers) []Header {
	var out []Header
	for k, v := range h {
		s, _ := v.(string)
		for _, line := range strings.Split(s, "\n") {
			out = append(out, Header{Key: k, Value: line})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Key != out[j].Key {
			return out[i].Key < out[j].Key
		}
		return out[i].Value < out[j].Value
	})
	return out
}

func (r *pageLog) finished(ev *network.EventLoadingFinished) {
	r.prog.touch()
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.cur[ev.RequestID]; e != nil {
		e.done = true
		e.Bytes = int64(ev.EncodedDataLength)
		if r.doc && ev.RequestID == r.docID {
			r.rec.ContentLength = e.Bytes
		}
		e.Millis = ms(e.start, float64(ev.Timestamp))
	}
}

func (r *pageLog) failed(ev *network.EventLoadingFailed) {
	r.prog.touch()
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.cur[ev.RequestID]; e != nil {
		e.done = true
		e.Error = ev.ErrorText
		// Refused by azhaq (outside the scope, the tab's icon): the page
		// was held to where it may go, which is not a page that did not load.
		e.blocked = strings.HasPrefix(ev.ErrorText, "net::ERR_BLOCKED_BY_CLIENT") || ev.Canceled
		e.Millis = ms(e.start, float64(ev.Timestamp))
	}
}

func (r *pageLog) logged(ev *runtime.EventConsoleAPICalled) {
	var parts []string
	for _, a := range ev.Args {
		switch {
		case a.Value != nil && len(a.Value) > 0:
			var s string
			if json.Unmarshal(a.Value, &s) == nil {
				parts = append(parts, s)
			} else {
				parts = append(parts, string(a.Value))
			}
		case a.Description != "":
			parts = append(parts, a.Description)
		default:
			parts = append(parts, string(a.Type))
		}
	}
	r.addConsole(string(ev.Type), strings.Join(parts, " "))
}

func (r *pageLog) thrown(ev *runtime.EventExceptionThrown) {
	if ev.ExceptionDetails == nil {
		return
	}
	text := ev.ExceptionDetails.Text
	if x := ev.ExceptionDetails.Exception; x != nil && x.Description != "" {
		text = x.Description
	}
	r.addConsole("exception", text)
}

func (r *pageLog) addConsole(kind, value string) {
	if len(value) > maxConsoleLen {
		value = value[:maxConsoleLen]
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.rec.Console) < maxConsole {
		r.rec.Console = append(r.rec.Console, ConsoleLn{Type: kind, Value: value})
	}
}

// snapshot is the record so far, and how many of the requests that make a
// screenshot (images, styles, scripts, fonts, media, a frame's page) have
// not come back or came back as an error of the network, out of how many
// were made.
func (r *pageLog) snapshot() (rec Record, unloaded, total int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec = r.rec
	rec.Headers = append([]Header(nil), rec.Headers...)
	rec.Console = append([]ConsoleLn(nil), rec.Console...)
	for _, e := range r.all {
		rec.Network = append(rec.Network, *e)
		if !counted(e.rt) && !e.sub {
			continue
		}
		if e.blocked {
			continue
		}
		total++
		if !e.done || e.Error != "" {
			unloaded++
		}
	}
	return rec, unloaded, total
}
