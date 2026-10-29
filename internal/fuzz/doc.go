// Package fuzz is ffuf's engine: a request template with keywords, wordlists
// run through it, matchers and filters over the answers, auto-calibration
// and recursion. Counts (words are spaces plus one, lines are newlines plus
// one), the match rules and the calibration follow ffuf 2.3 so a command
// line moved from ffuf gives the same results.
//
// Sending is behind Sender, so the engine runs against a fake in tests;
// NewSender sends through internal/fetch, with the run's budget and pace.
package fuzz
