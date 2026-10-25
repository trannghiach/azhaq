package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// tool is a reference tool, pinned to a release archive and its checksum.
type tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	repo    string
	asset   string
	sha256  string
}

// Checksums are for linux/amd64 and come from each release's checksums file.
var tools = []tool{
	{"katana", "1.8.0", "projectdiscovery/katana", "katana_1.8.0_linux_amd64.zip", "cb027ae99d0757061b70c07a15c7a80f62c5a535ab52c4a329f80c4b0a7309d2"},
	{"subfinder", "2.17.0", "projectdiscovery/subfinder", "subfinder_2.17.0_linux_amd64.zip", "a39c3e5c7a26ef3c430915c4d6cbf7716a00f26769a75e9405aba796142eba37"},
	{"httpx", "1.12.0", "projectdiscovery/httpx", "httpx_1.12.0_linux_amd64.zip", "9d8439e8b6c9aa7d1e2314817a392e00d5178da3af5652f7475f88868f418f76"},
	{"dnsx", "1.3.1", "projectdiscovery/dnsx", "dnsx_1.3.1_linux_amd64.zip", "438b964653056dd51dcfe614b1a16f8bced3cc48a1d27bc07cc6fdf2ef2a9533"},
	{"naabu", "2.6.1", "projectdiscovery/naabu", "naabu_2.6.1_linux_amd64.zip", "018c4c9884dea971eda860435ede3021d1150732f34cfd245498c6726d8cab90"},
	{"gau", "2.2.4", "lc/gau", "gau_2.2.4_linux_amd64.tar.gz", "10e2e248c37cafb0be3f6d2931125296b95cd4186066d596d47fa417237529a9"},
	{"ffuf", "2.3.0", "ffuf/ffuf", "ffuf_2.3.0_linux_amd64.tar.gz", "b2a3c725fcb9da175159682f54d6e9149f2905b00d84d155e7efc5d599975ceb"},
}

func (t tool) url() string {
	return "https://github.com/" + t.repo + "/releases/download/v" + t.Version + "/" + t.asset
}

// installTools puts each pinned tool in dir, downloading only what is
// missing or at another version.
func installTools(dir string) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return fmt.Errorf("bench pins linux/amd64 builds of the reference tools; add checksums for %s/%s in bench/tools.go", runtime.GOOS, runtime.GOARCH)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, t := range tools {
		marker := filepath.Join(dir, "."+t.Name+"-"+t.Version)
		if _, err := os.Stat(marker); err == nil {
			continue
		}
		logf("installing %s %s", t.Name, t.Version)
		if err := install(t, dir); err != nil {
			return fmt.Errorf("%s: %w", t.Name, err)
		}
		if err := os.WriteFile(marker, nil, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func install(t tool, dir string) error {
	cli := &http.Client{Timeout: 5 * time.Minute}
	resp, err := cli.Get(t.url())
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", t.url(), resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != t.sha256 {
		return fmt.Errorf("checksum mismatch for %s: got %s", t.asset, got)
	}
	var bin []byte
	if strings.HasSuffix(t.asset, ".zip") {
		bin, err = fromZip(data, t.Name)
	} else {
		bin, err = fromTarGz(data, t.Name)
	}
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, t.Name), bin, 0o755)
}

func fromZip(data []byte, name string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if filepath.Base(f.Name) != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(rc)
	}
	return nil, fmt.Errorf("%s not in archive", name)
}

func fromTarGz(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("%s not in archive", name)
		}
		if err != nil {
			return nil, err
		}
		if filepath.Base(h.Name) == name && h.Typeflag == tar.TypeReg {
			return io.ReadAll(tr)
		}
	}
}
