package httpcol

import "testing"

// Two inputs that reach one URL each keep its answer: the second to take it
// still gets it, and the third finds it gone.
func TestEvidenceIsKeptForEachWhoKeptIt(t *testing.T) {
	ev := &Evidence{URL: "http://h/"}
	keepEvidence("http://h/", ev)
	keepEvidence("http://h/", ev)
	for i := 0; i < 2; i++ {
		if got, ok := TakeEvidence("http://h/"); !ok || got != ev {
			t.Fatalf("take %d: %v %v", i+1, got, ok)
		}
	}
	if _, ok := TakeEvidence("http://h/"); ok {
		t.Error("kept after both took it")
	}
}
