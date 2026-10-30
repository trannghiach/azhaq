package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"

	"github.com/trannghiach/azhaq/internal/gallery"
)

// cmdGallery serves a workspace's screenshots to a browser on this
// machine. It reads the workspace and sends nothing to any target.
func cmdGallery(args []string) error {
	fs := newFlags("gallery")
	var dbs stringsFlag
	fs.Var(&dbs, "db", "a workspace to show (repeatable; default: the last run's)")
	dir := fs.String("workspace", "", "show every workspace (*.db) of this directory and its subdirectories, merged in one view")
	listen := fs.String("listen", "127.0.0.1:7180", "address to serve on; a loopback address answers only this machine (127.0.0.1:0 takes any free port)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return usagef("gallery takes flags only; give the workspace with -db")
	}
	paths := []string(dbs)
	if *dir != "" {
		more, err := workspaceFiles(*dir)
		if err != nil {
			return err
		}
		if len(more) == 0 {
			return fmt.Errorf("no *.db file in %s", *dir)
		}
		paths = append(paths, more...)
	}
	if len(paths) == 0 {
		last := readLastDB()
		if last == "" {
			return usagef("give -db FILE or -workspace DIR")
		}
		paths = []string{last}
	}
	g, err := gallery.Open(paths, nil)
	if err != nil {
		return err
	}
	defer g.Close()
	if g.Len() == 0 {
		return fmt.Errorf("no screenshots in %s (azhaq run -screenshots DIR or azhaq shots takes them)", strings.Join(paths, ", "))
	}
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer l.Close()
	partial := 0
	for _, w := range g.Warnings() {
		fmt.Fprintf(os.Stderr, "azhaq: gallery: %s\n", strings.TrimPrefix(w.Workspace+": ", ": ")+w.Message)
		if w.Partial {
			partial++
		}
	}
	if host, _, err := net.SplitHostPort(l.Addr().String()); err == nil {
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			fmt.Fprintf(os.Stderr, "azhaq: gallery: listening on %s: anyone who can reach it sees every page, header and console line in the workspace\n", l.Addr())
		}
	}
	fmt.Fprintf(os.Stderr, "azhaq: gallery: %d pages of %d workspace(s) at http://%s/ (reads the workspace at start; Ctrl-C stops)\n", g.Len(), len(paths), l.Addr())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := g.Run(ctx, l); err != nil {
		return err
	}
	if partial > 0 {
		return exitErr{code: exitPartial, msg: fmt.Sprintf("the gallery was partial: %d warning(s) above", partial)}
	}
	return nil
}

// workspaceFiles lists the *.db files of dir and of the directories
// directly in it, in order.
func workspaceFiles(dir string) ([]string, error) {
	st, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, usagef("-workspace takes a directory; give a single database with -db")
	}
	var out []string
	for _, pat := range []string{"*.db", "*/*.db"} {
		m, _ := filepath.Glob(filepath.Join(dir, pat))
		out = append(out, m...)
	}
	sort.Strings(out)
	return out, nil
}
