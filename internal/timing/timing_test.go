package timing

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestStartNoopWithoutLog(t *testing.T) {
	done := Start(context.Background(), "x")
	done()
	done()
}

func TestStartRecordsAndNotify(t *testing.T) {
	log := New()
	var saw []Span
	log.Notify = func(s Span) { saw = append(saw, s) }
	ctx := With(context.Background(), log)
	done := Start(ctx, "fetch", "example.test")
	time.Sleep(5 * time.Millisecond)
	done()
	done() // once
	if len(saw) != 1 || saw[0].Name != "fetch" || saw[0].Label != "example.test" {
		t.Fatalf("notify %+v", saw)
	}
	st := log.Stats()
	if len(st) != 1 || st[0].N != 1 || st[0].Max < 5*time.Millisecond {
		t.Fatalf("stats %+v", st)
	}
}

func TestReportSlowestFirst(t *testing.T) {
	log := New()
	log.add(Span{Name: "fast", Dur: time.Millisecond})
	log.add(Span{Name: "ct.crt.sh", Dur: 2 * time.Second})
	log.add(Span{Name: "fetch", Dur: 80 * time.Millisecond})
	log.add(Span{Name: "fetch", Dur: 40 * time.Millisecond})
	out := log.Report(3 * time.Second)
	if !strings.Contains(out, "took 3s") {
		t.Fatal(out)
	}
	if !strings.Contains(out, "ct.crt.sh") || !strings.Contains(out, "fetch") {
		t.Fatal(out)
	}
	if strings.Contains(out, "fast") {
		t.Fatal("tiny span in report:", out)
	}
	ct := strings.Index(out, "ct.crt.sh")
	fe := strings.Index(out, "fetch")
	if ct < 0 || fe < 0 || ct > fe {
		t.Fatal("not sorted by max:", out)
	}
	if !strings.Contains(out, "2 × max") {
		t.Fatal(out)
	}
}
