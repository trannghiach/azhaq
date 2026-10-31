package fetch

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/trannghiach/azhaq/internal/neterr"
)

var posts atomic.Int64

// Posts is how many form submissions the run sent (-submit-forms).
func Posts() int64 { return posts.Load() }

// SubmitForm sends one POST of a form's fields, urlencoded. It is the only
// write a crawl sends, and only when -submit-forms is given: it is held to
// the run's scope, spends a request of the budget and the pace, is
// entered in the ledger like every request, and is counted for the
// summary. The answer is read but not followed to its redirect.
func SubmitForm(ctx context.Context, c *http.Client, raw, query string) (Result, error) {
	if EndsSession(raw) {
		return Result{}, neterr.ErrEndsSession
	}
	if !inScope(raw) {
		return Result{}, neterr.ErrOutOfScope
	}
	if err := originRefused(ctx, raw); err != nil {
		return Result{}, err
	}
	release, err := acquireHost(ctx, raw)
	if err != nil {
		return Result{}, err
	}
	defer release()
	if err := beforeSend(ctx, raw); err != nil {
		return Result{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, raw, bytes.NewReader([]byte(query)))
	if err != nil {
		return Result{}, err
	}
	ApplyHeaders(req)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if u, err := url.Parse(raw); err == nil && req.Header.Get("Referer") == "" {
		req.Header.Set("Referer", u.Scheme+"://"+u.Host+"/")
	}
	withJar(req)
	if err := Spend(ctx); err != nil {
		return Result{}, err
	}
	posts.Add(1)
	resp, err := noFollow(c).Do(req)
	noteOrigin(ctx, raw, err)
	if errors.Is(err, neterr.ErrNotRepeated) {
		posts.Add(-1) // held back: nothing was sent
	}
	if err != nil {
		return Result{}, err
	}
	body, trunc, err := readBody(resp.Body, MaxBody)
	resp.Body.Close()
	if err != nil {
		return Result{}, err
	}
	keepCookies(resp)
	afterAnswer(raw, resp.StatusCode, resp.Header.Get("Retry-After"))
	return Result{
		RequestURL: raw, Status: resp.StatusCode, StatusLine: strings.TrimSpace(resp.Status), URL: raw,
		Header: resp.Header, FinalHeader: resp.Header, Body: body, Truncated: trunc,
		Hops: []Hop{{URL: raw, Status: resp.StatusCode, Location: resp.Header.Get("Location")}},
	}, nil
}
