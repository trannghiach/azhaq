// Package pagekind says what kind of page an answer is (login, captcha,
// registration, an error page…), as httpx -kb does, with the dit classifier
// (github.com/happyhackingspace/dit, MIT) and its pretrained model.
package pagekind

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/happyhackingspace/dit"
)

// ModelURL is where the model is downloaded from. Azhaq never downloads it.
const ModelURL = dit.ModelURL

// ModelPath is the model file: $AZHAQ_DIT_MODEL, else ~/.dit/model.json (where
// dit and httpx keep it).
func ModelPath() string {
	if p := os.Getenv("AZHAQ_DIT_MODEL"); p != "" {
		return p
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".dit", "model.json")
	}
	return ""
}

var (
	once sync.Once
	clf  *dit.Classifier
	err  error
)

// Check says whether the model can be read, loading it for the run. The
// model is about 100 MB and takes a few seconds to read.
func Check() error {
	once.Do(func() {
		p := ModelPath()
		if _, e := os.Stat(p); e != nil {
			err = fmt.Errorf("the page classifier's model is not at %s: download %s there, or give its path in $AZHAQ_DIT_MODEL (azhaq downloads nothing by itself)", p, ModelURL)
			return
		}
		clf, err = dit.Load(p)
		if err != nil {
			err = fmt.Errorf("the page classifier's model at %s: %w", p, err)
		}
	})
	return err
}

// Result is the kind of a page and the forms found on it.
type Result struct {
	Type  string
	Forms any
}

// Classify reads a page. The model must have been checked.
func Classify(html string) (Result, bool) {
	if clf == nil {
		return Result{}, false
	}
	r, e := clf.ExtractPageType(html)
	if e != nil {
		return Result{}, false
	}
	out := Result{Type: fmt.Sprint(r.Type)}
	if len(r.Forms) > 0 {
		out.Forms = r.Forms
	}
	return out, true
}
