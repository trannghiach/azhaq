package webextract

import (
	"net/url"
	"strings"
)

// FillValue is what a form's field gets when a crawler fills the form in:
// the value the page gives it, else a neutral one by the field's kind
// (katana's -aff does the same with its own fake values). ok is false for
// a field a browser would not send: buttons, files, an unticked box.
func FillValue(in Input) (string, bool) {
	switch in.Type {
	case "submit", "button", "image", "reset", "file":
		return "", false
	case "checkbox", "radio":
		if !in.Checked {
			return "", false
		}
		if in.Value == "" {
			return "on", true
		}
		return in.Value, true
	case "hidden", "select":
		return in.Value, in.Name != ""
	}
	if in.Value != "" {
		return in.Value, true
	}
	switch in.Type {
	case "password":
		return "azhaqP4ssw0rd", true
	case "email":
		return "azhaq@example.org", true
	case "number", "range":
		return "1", true
	case "tel":
		return "5550100", true
	case "url":
		return "https://example.org/", true
	case "date":
		return "2026-01-01", true
	case "time":
		return "12:00", true
	case "color":
		return "#000000", true
	}
	return "azhaq", true
}

// FilledQuery is the form's fields as a URL-encoded query, in page order.
func FilledQuery(f Form) string {
	var parts []string
	for _, in := range f.Inputs {
		if v, ok := FillValue(in); ok {
			parts = append(parts, url.QueryEscape(in.Name)+"="+url.QueryEscape(v))
		}
	}
	return strings.Join(parts, "&")
}

// FilledGet is the URL a browser would ask when the form is submitted with
// FillValue's values: the action with the fields as its query. ok is false
// for a form that is not GET or has no field to send.
func FilledGet(f Form) (string, bool) {
	q := FilledQuery(f)
	if f.Method != "GET" || f.Action == "" || q == "" {
		return "", false
	}
	u, err := url.Parse(f.Action)
	if err != nil {
		return "", false
	}
	u.RawQuery, u.Fragment = q, ""
	return u.String(), true
}
