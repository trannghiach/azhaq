// Package docs holds the documentation the azhaq command prints with
// azhaq docs.
package docs

import "embed"

// The flag tables of the pages in commands/ are made from the binary:
// go generate ./docs rewrites them, and a test fails when one is stale.
//
//go:generate go run ../cmd/azhaq docs -flags-into commands

// Files are the documents, by file name; commands/NAME.md is the page of
// one command.
//
//go:embed ARCHITECTURE.md CONNECTOR.md OUTPUT.md MCP.md CONCEPTS.md RECIPES.md TROUBLESHOOTING.md MIGRATING.md commands/*.md
var Files embed.FS
