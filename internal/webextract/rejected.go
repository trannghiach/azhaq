package webextract

import (
	"encoding/json"
	"time"

	"github.com/trannghiach/azhaq/types"
)

// Reasons a string that sat where a URL could be is not made one.
const (
	ReasonWildcard   = "a pattern with a wildcard, not a URL"
	ReasonOtherHost  = "on another host than the crawl's scope"
	ReasonLibrary    = "library code, not the application's"
	ReasonExpression = "an expression or a template, not a fixed path"
	ReasonJunk       = "a value no browser would request (a scanner payload, NaN, a cut-off link)"
	ReasonNotPath    = "not a path: a type name, a version, a word or a number"
	ReasonOffsite    = "a link outside the crawl's scope"
	ReasonOutOfRules = "outside the -crawl-in and -crawl-out rules"
	ReasonErrorPage  = "named in an error page (a stack trace, a not-found page), not linked"
	ReasonCatchAll   = "named in the page every unknown path gets, whose links were read from the real page"
	ReasonAsset      = "a script, style, image or data file name: listed only with -assets, not a page"
	ReasonCode       = "unquoted script code the page pattern read as a path (a.number/t.doc), not a string"
	ReasonSearched   = "a string a script searches for (indexOf, includes, replace), not a URL it requests"
)

// RejectedObs is the record of a string a collector read as a possible URL
// and kept out of the map, with why. It is not requested; crawl -rejected
// lists them, and the summary counts them.
func RejectedObs(collector, source, text, reason, via, resolved string) types.Observation {
	if len(text) > 200 {
		text = text[:200]
	}
	row := map[string]string{"string": text, "reason": reason, "via": via}
	if resolved != "" {
		row["url"] = resolved
	}
	payload, _ := json.Marshal(row)
	return types.Observation{
		Collector: collector, Source: source, Kind: "rejected",
		Payload: payload, Confidence: 0.5, ObservedAt: time.Now().UTC(),
	}
}
