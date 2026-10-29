package pathscol

import (
	"encoding/json"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/trannghiach/azhaq/types"
)

// descOrder is where an API description is guessed, most likely first. The
// checks run in this order and stop at the first answer.
var descOrder = []string{
	"openapi.json", "swagger.json", "api-docs", "v3/api-docs", "v2/api-docs",
	"swagger/v1/swagger.json", "openapi.yaml", "swagger.yaml", "api/openapi.json", "api/swagger.json",
	"swagger-resources", "v3/api-docs/swagger-config", "swagger",
}

func descRank(path string) int {
	return slices.Index(descOrder, strings.Trim(path, "/"))
}

// isDescLoc says whether path is a guess of an API description's location.
func isDescLoc(path string) bool { return descRank(path) >= 0 }

var uiRE = regexp.MustCompile(`(?i)swagger-ui|SwaggerUIBundle|<redoc\b|redoc\.standalone`)

// describes says whether body is an API description (OpenAPI or Swagger
// with paths) or the Swagger UI or ReDoc page that loads one.
func describes(body []byte) bool {
	t := strings.TrimSpace(string(body))
	if t == "" {
		return false
	}
	if strings.HasPrefix(t, "<") {
		return uiRE.MatchString(t)
	}
	var d struct {
		OpenAPI string         `json:"openapi" yaml:"openapi"`
		Swagger string         `json:"swagger" yaml:"swagger"`
		Paths   map[string]any `json:"paths" yaml:"paths"`
	}
	if strings.HasPrefix(t, "{") {
		if json.Unmarshal(body, &d) != nil {
			return false
		}
	} else if yaml.Unmarshal(body, &d) != nil {
		return false
	}
	return (d.OpenAPI != "" || d.Swagger != "") && len(d.Paths) > 0
}

// Notes is the summary line for the checks a run did not send because an
// API description was already found.
func Notes(obs []types.StoredObservation) []string {
	n := 0
	for _, o := range obs {
		if o.Collector != Name || o.Kind != "note" {
			continue
		}
		var p struct {
			Skipped int `json:"skipped_checks"`
		}
		if json.Unmarshal(o.Payload, &p) == nil {
			n += p.Skipped
		}
	}
	if n == 0 {
		return nil
	}
	return []string{"path checks: " + strconv.Itoa(n) + " skipped (an API description was already found)"}
}
