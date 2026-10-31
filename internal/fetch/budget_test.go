package fetch

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/trannghiach/azhaq/internal/egress"
	"github.com/trannghiach/azhaq/internal/neterr"
)

func TestBudgetStopsRequests(t *testing.T) {
	Reset()
	defer Reset()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/moved" {
			http.Redirect(w, r, "/target", http.StatusFound)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(srv.Close)
	egress.SetMaxRequests(3)
	for i := 0; i < 2; i++ {
		if _, _, err := Do(context.Background(), srv.Client(), fmt.Sprintf("%s/%d", srv.URL, i)); err != nil {
			t.Fatal(err)
		}
	}
	// The third request is sent; the redirect's target would be the fourth.
	res, _, err := Do(context.Background(), srv.Client(), srv.URL+"/moved")
	if err != nil || len(res.Hops) != 1 || res.Status != http.StatusFound {
		t.Fatalf("redirect at the limit: %v %+v", err, res.Hops)
	}
	if _, _, err := Do(context.Background(), srv.Client(), srv.URL+"/4"); !errors.Is(err, neterr.ErrBudget) {
		t.Fatalf("over the budget: %v", err)
	}
	if hits.Load() != 3 || egress.Sent() != 3 {
		t.Errorf("server saw %d, counted %d, want 3", hits.Load(), egress.Sent())
	}
	egress.Count(5)
	if egress.Sent() != 8 {
		t.Errorf("counted %d after 5 sent outside, want 8", egress.Sent())
	}
}
