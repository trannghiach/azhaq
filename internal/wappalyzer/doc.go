// Package wappalyzer is the passive part of projectdiscovery/wappalyzergo
// v0.3.5 (MIT, see LICENSE.md): technology fingerprints from response
// headers, cookies and HTML.
//
// Changes from upstream: a pattern's regexp compiles the first time its
// literal prefilter passes instead of at load, the parsed JSON is not kept
// after compiling, and the js and dom rules (which need a browser) are
// neither embedded nor compiled, and cdnjs no longer implies Cloudflare (a
// page loading a library from it is not behind Cloudflare). Matching is
// otherwise unchanged, so results agree with httpx -td. fingerprints_data.json is produced by
// strip.go from the upstream file.
package wappalyzer
