package webextract

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// itemID is an identifier a path segment can carry: a number, a UUID, a
// slug; not free text.
var itemID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)

// ListingItem is the URL of the first item of a JSON listing at base:
// /api/Challenges answers [{"id":1,…},…] (or {"data":[{"id":1,…}]}), so
// /api/Challenges/1 is where the item is read, the route a REST API
// keeps for it and the object an access-control test asks for. "" when
// the answer is not a listing of objects with an id, or base already
// ends in an identifier (/users/7 answering its orders is not /users/7/5).
func ListingItem(body []byte, base *url.URL) string {
	if base == nil || base.Path == "" || strings.ContainsAny(base.Path, "{}") {
		return ""
	}
	segs := strings.Split(strings.TrimRight(base.Path, "/"), "/")
	last := segs[len(segs)-1]
	if last == "" || numSeg.MatchString(last) || uuidSeg.MatchString(last) || hexSeg.MatchString(last) || strings.Contains(last, ".") {
		return ""
	}
	var v any
	if json.Unmarshal(body, &v) != nil {
		return ""
	}
	items, ok := v.([]any)
	if m, isObj := v.(map[string]any); isObj {
		if _, own := m["id"]; own {
			return "" // an object of its own, not an envelope
		}
		found := 0
		for _, f := range m {
			if xs, isList := f.([]any); isList {
				items, found = xs, found+1
			}
		}
		ok = found == 1
	}
	if !ok {
		return ""
	}
	for _, it := range items {
		o, isObj := it.(map[string]any)
		if !isObj {
			return ""
		}
		var id string
		switch t := o["id"].(type) {
		case float64:
			if t != float64(int64(t)) {
				return ""
			}
			id = strconv.FormatInt(int64(t), 10)
		case string:
			id = t
		default:
			continue
		}
		if !itemID.MatchString(id) {
			continue
		}
		u := *base
		u.RawQuery, u.Fragment, u.RawPath = "", "", ""
		u.Path = strings.TrimRight(base.Path, "/") + "/" + url.PathEscape(id)
		return u.String()
	}
	return ""
}
