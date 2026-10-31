package egress

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Only this package opens an outbound connection. .golangci.yml says it with
// forbidigo for the names it can tell apart; this test says all of it, since
// forbidigo cannot tell an http.Client{} that builds a client from the
// *http.Client of a signature. A violation here is a request that skips the
// run's controls: build it with the Policy's clients instead.

// literals are types no code outside egress builds.
var literals = map[string]bool{
	"net/http.Client": true, "net/http.Transport": true, "net.Dialer": true, "net.Resolver": true,
	"crypto/tls.Dialer": true, "github.com/miekg/dns.Client": true,
	"golang.org/x/net/http2.Transport": true,
}

// forbidden are the names no code outside egress uses.
var forbidden = map[string]bool{
	"net/http.DefaultClient": true, "net/http.DefaultTransport": true,
	"net/http.Get": true, "net/http.Post": true, "net/http.Head": true, "net/http.PostForm": true,
	"net.Dial": true, "net.DialTimeout": true, "net.DialTCP": true, "net.DialUDP": true,
	"net.DialIP": true, "net.DialUnix": true, "net.ListenPacket": true, "net.ListenUDP": true,
	"net.LookupHost": true, "net.LookupIP": true, "net.LookupAddr": true, "net.LookupCNAME": true,
	"net.LookupMX": true, "net.LookupNS": true, "net.LookupTXT": true, "net.LookupSRV": true,
	"net.LookupPort": true, "net.DefaultResolver": true,
	"crypto/tls.Dial": true, "crypto/tls.DialWithDialer": true,
	"net/smtp.Dial": true, "net/smtp.SendMail": true,
	"github.com/chromedp/chromedp.NewExecAllocator": true, "github.com/chromedp/chromedp.NewRemoteAllocator": true,
	"github.com/lib/pq.NewConnector": true, "github.com/lib/pq.Open": true, "github.com/lib/pq.DialOpen": true,
	"database/sql.OpenDB": true,
}

// violations lists what src builds or calls that only egress may.
func violations(fset *token.FileSet, f *ast.File) []string {
	names := map[string]string{} // the name an import goes by → its path
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		n := path.Base(p)
		if p == "golang.org/x/net/http2" {
			n = "http2"
		}
		if im.Name != nil {
			n = im.Name.Name
		}
		names[n] = p
	}
	qualified := func(e ast.Expr) string {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok {
			return ""
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || id.Obj != nil { // a local variable, not a package
			return ""
		}
		if p, ok := names[id.Name]; ok {
			return p + "." + sel.Sel.Name
		}
		return ""
	}
	var out []string
	add := func(n ast.Node, what string) {
		out = append(out, fset.Position(n.Pos()).String()+": "+what)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CompositeLit:
			if q := qualified(x.Type); literals[q] {
				add(x, q+"{}: ask egress for it")
			}
		case *ast.CallExpr:
			if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "new" && len(x.Args) == 1 {
				if q := qualified(x.Args[0]); literals[q] {
					add(x, "new("+q+"): ask egress for it")
				}
			}
			if q := qualified(x.Fun); q == "database/sql.Open" && len(x.Args) > 0 {
				// A local file (sqlite) is not a connection out.
				if lit, ok := x.Args[0].(*ast.BasicLit); !ok || lit.Value != `"sqlite"` {
					add(x, "sql.Open of a driver other than sqlite: remote databases are opened by egress")
				}
			}
		case *ast.SelectorExpr:
			if q := qualified(x); forbidden[q] {
				add(x, q+": only egress opens a connection")
			}
		}
		return true
	})
	return out
}

func TestOnlyEgressOpensConnections(t *testing.T) {
	root := "../.."
	var bad []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		switch {
		case d.IsDir() && (rel == "bench" || rel == "internal/egress" || strings.HasPrefix(d.Name(), ".") && rel != "."):
			return fs.SkipDir
		case d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go"):
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			t.Errorf("%s: %v", p, err)
			return nil
		}
		for _, v := range violations(fset, f) {
			bad = append(bad, strings.Replace(v, root+"/", "", 1))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(bad)
	for _, b := range bad {
		t.Error(b)
	}
}

// The check sees what it is for.
func TestTheRuleSeesAClientBuiltOutsideEgress(t *testing.T) {
	src := `package x
import (
	"net"
	"net/http"
	"database/sql"
	cdp "github.com/chromedp/chromedp"
)
type S struct{ C *http.Client } // the type is fine
func f() {
	_ = &http.Client{}
	_ = new(http.Client)
	_ = &net.Dialer{}
	_, _ = http.Get("http://a")
	_, _ = net.Dial("tcp", "a:1")
	_, _ = sql.Open("postgres", "")
	_, _ = sql.Open("sqlite", "f")
	_ = http.DefaultTransport
	cdp.NewExecAllocator(nil)
	http := struct{ Get func() }{}
	http.Get() // a variable named like a package
}`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := violations(fset, f)
	if len(got) != 8 {
		t.Fatalf("%d violations, want 8:\n%s", len(got), strings.Join(got, "\n"))
	}
}
