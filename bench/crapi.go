package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// OWASP crAPI is opt-in (-crapi): it pulls about 2 GB. Only crapi-web and
// the six services it depends on start; the LLM chatbot stays off. The
// compose file comes from the pinned release, and bench/crapi-override.yaml
// pins its images by digest, since upstream tags them only as "latest".
const (
	crapiVersion = "1.1.6"
	crapiSHA256  = "ecd72b9d5abb2024b1202ae1d79e3d5ea49131c4b2427bf0617049141fd8dd82"
	crapiURL     = "http://127.0.0.1:8888/"
	crapiProject = "azhaq-bench-crapi"
)

func crapiDir() string { return filepath.Join(work, "crAPI-"+crapiVersion) }

func crapiCompose(args ...string) *exec.Cmd {
	base := []string{"compose", "-p", crapiProject,
		"-f", filepath.Join(crapiDir(), "deploy", "docker", "docker-compose.yml"),
		"-f", filepath.Join("bench", "crapi-override.yaml")}
	cmd := exec.Command("docker", append(base, args...)...)
	cmd.Env = append(os.Environ(), "LISTEN_IP=127.0.0.1")
	return cmd
}

func startCrapi() error {
	if _, err := os.Stat(crapiDir()); err != nil {
		if err := fetchCrapi(); err != nil {
			return err
		}
	}
	logf("starting crAPI (first run pulls about 2 GB)")
	if out, err := crapiCompose("up", "-d", "--wait", "crapi-web").CombinedOutput(); err != nil {
		return fmt.Errorf("crAPI compose up: %v\n%s", err, out)
	}
	return waitUp(crapiURL, 5*time.Minute)
}

func stopCrapi() { _ = crapiCompose("down").Run() }

// fetchCrapi downloads the release source and keeps the compose
// deployment and the OpenAPI document, the source of truth for routes.
func fetchCrapi() error {
	u := "https://github.com/OWASP/crAPI/archive/refs/tags/v" + crapiVersion + ".tar.gz"
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != crapiSHA256 {
		return fmt.Errorf("crAPI archive checksum mismatch: %s", got)
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	root := "crAPI-" + crapiVersion + "/"
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		name := filepath.Clean(h.Name)
		if strings.Contains(name, "..") || !strings.HasPrefix(h.Name, root) {
			continue
		}
		rel := strings.TrimPrefix(h.Name, root)
		if !strings.HasPrefix(rel, "deploy/docker/") && !strings.HasPrefix(rel, "openapi-spec/") {
			continue
		}
		dest := filepath.Join(crapiDir(), rel)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dest, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
				return err
			}
			body, err := io.ReadAll(tr)
			if err != nil {
				return err
			}
			if err := os.WriteFile(dest, body, os.FileMode(h.Mode)&0o755|0o600); err != nil {
				return err
			}
		}
	}
}

func benchCrapi() appResult {
	raw, err := os.ReadFile(filepath.Join(crapiDir(), "openapi-spec", "crapi-openapi-spec.json"))
	must(err)
	var spec struct {
		Paths map[string]any `json:"paths"`
	}
	must(json.Unmarshal(raw, &spec))
	truth := map[string]bool{}
	for p := range spec.Paths {
		truth[route(p)] = true
	}
	dir, _ := filepath.Abs(filepath.Join(work, "apps"))
	must(os.MkdirAll(dir, 0o755))
	db := filepath.Join(dir, "crapi-"+time.Now().Format("150405")+".db")
	res := appResult{Name: "crapi", URL: crapiURL}
	g, _, m := runAzhaq(crapiURL, db)
	shell := shellHash(crapiURL)
	res.Azhaq = scoreAzhaq(g, crapiURL, truth, shell, m)
	runKatanaJsluice(&res, truth, shell)
	addCheck("crapi: routes joined from constants ≥ 30/40", res.Azhaq.Truth >= 30,
		"azhaq %d/%d, katana ∪ jsluice %d/%d", res.Azhaq.Truth, len(truth), res.Union.Truth, len(truth))
	res.Browser = compareBrowsers(crapiURL, filepath.Join(dir, "crapi-browser-"+time.Now().Format("150405")+".db"), truth, shell)
	addCheck("crapi: -browser finds the known routes katana -headless finds", res.Browser.Azhaq.Truth >= res.Browser.Katana.Truth,
		"azhaq -browser %d/%d in %.0fs, katana -headless %d/%d in %.0fs", res.Browser.Azhaq.Truth, len(truth), res.Browser.Azhaq.Seconds,
		res.Browser.Katana.Truth, len(truth), res.Browser.Katana.Seconds)
	return res
}
