// Package azhaq holds the README, which the azhaq command prints with
// azhaq docs readme. The engine is in the packages below this one.
package azhaq

import _ "embed"

//go:embed README.md
var README string
