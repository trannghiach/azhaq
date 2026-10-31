//go:build race

package fuzz

// raceOn: under the race detector sync.Pool drops items on purpose, so
// allocation counts say nothing.
const raceOn = true
