//go:build race

package webextract

// raceSlowdown: the race detector makes the timed tests this much slower.
const raceSlowdown = 8
