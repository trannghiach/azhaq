package fetch

import "sync"

// Origins that have served an API description in this run (scheme://host):
// the path checks do not guess its other locations once one is known.
var (
	describedMu sync.Mutex
	described   = map[string]bool{}
)

// MarkDescribed records that origin served an API description.
func MarkDescribed(origin string) {
	describedMu.Lock()
	described[origin] = true
	describedMu.Unlock()
}

// Described reports whether origin has served an API description.
func Described(origin string) bool {
	describedMu.Lock()
	defer describedMu.Unlock()
	return described[origin]
}

func resetDescribed() {
	describedMu.Lock()
	described = map[string]bool{}
	describedMu.Unlock()
}

var (
	notesMu  sync.Mutex
	runNotes []string
)

// Note adds a line to the run's summary, for what a collector cannot keep
// in an observation: the budget drops what a task gave when it stops it.
func Note(text string) {
	notesMu.Lock()
	defer notesMu.Unlock()
	for _, n := range runNotes {
		if n == text {
			return
		}
	}
	runNotes = append(runNotes, text)
}

// Notes are the lines collectors added with Note, in the order they came.
func Notes() []string {
	notesMu.Lock()
	defer notesMu.Unlock()
	return append([]string(nil), runNotes...)
}

func resetNotes() {
	notesMu.Lock()
	runNotes = nil
	notesMu.Unlock()
}
