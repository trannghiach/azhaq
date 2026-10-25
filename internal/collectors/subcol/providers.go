package subcol

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

// ProviderPaths are read in order; the first that exists wins. Subfinder's
// file is read when Azhaq has none, so keys need not be copied.
func ProviderPaths() []string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return nil
	}
	return []string{
		filepath.Join(dir, "azhaq", "providers.yaml"),
		filepath.Join(dir, "subfinder", "provider-config.yaml"),
	}
}

// LoadProviders reads API keys per source: a YAML map from source name to
// a list of keys, the format subfinder uses. A missing file means no keys.
// The returned path is the file that was read, if any.
func LoadProviders(paths ...string) (map[string][]string, string, error) {
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, p, err
		}
		var m map[string][]string
		if err := yaml.Unmarshal(raw, &m); err != nil {
			return nil, p, err
		}
		keys := map[string][]string{}
		for name, list := range m {
			var clean []string
			for _, k := range list {
				if k = strings.TrimSpace(k); k != "" {
					clean = append(clean, k)
				}
			}
			if len(clean) > 0 {
				keys[strings.ToLower(name)] = clean
			}
		}
		return keys, p, nil
	}
	return map[string][]string{}, "", nil
}
