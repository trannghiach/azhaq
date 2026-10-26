// Package docs holds the documentation the azhaq command prints with
// azhaq docs.
package docs

import "embed"

// Files are the documents, by file name.
//
//go:embed ARCHITECTURE.md CONNECTOR.md OUTPUT.md MCP.md
var Files embed.FS
