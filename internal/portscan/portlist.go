package portscan

import (
	"hash/fnv"
	"math/rand"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// Spec writes ports (ascending, no repeats) as a list the Ports function
// reads back: 22,80-82,443.
func Spec(ports []int) string {
	var b strings.Builder
	for i := 0; i < len(ports); {
		j := i
		for j+1 < len(ports) && ports[j+1] == ports[j]+1 {
			j++
		}
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(ports[i]))
		if j > i {
			b.WriteByte('-')
			b.WriteString(strconv.Itoa(ports[j]))
		}
		i = j + 1
	}
	return b.String()
}

// Exclude is ports without the ones spec names (a list as Ports reads it).
func Exclude(ports []int, spec string) ([]int, error) {
	drop, err := Ports(spec)
	if err != nil {
		return nil, err
	}
	gone := make(map[int]bool, len(drop))
	for _, p := range drop {
		gone[p] = true
	}
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if !gone[p] {
			out = append(out, p)
		}
	}
	return out, nil
}

var tiers = sync.OnceValue(func() (t struct{ top100, top1000 map[int]bool }) {
	for spec, set := range map[string]*map[int]bool{top100: &t.top100, top1000: &t.top1000} {
		ports, _ := Ports(spec)
		m := make(map[int]bool, len(ports))
		for _, p := range ports {
			m[p] = true
		}
		*set = m
	}
	return t
})

// ordered is ports in the order the scanner asks them. A tiered order is
// the same for an address whenever the seed is: repeatable, and different
// from one address to the next.
// Ordered is the order ScanEach asks ports of ip in: its first Report.Asked
// are the ones asked when a scan stopped early.
func (s *Scanner) Ordered(ip string, ports []int) []int {
	s.init()
	return s.ordered(ip, slices.Clone(ports))
}

func (s *Scanner) ordered(ip string, ports []int) []int {
	if s.Order != OrderTiered || len(ports) < 2 {
		return ports
	}
	return Tiered(ports, s.runSeed^int64(hashOf(ip)))
}

// Tiered orders ports by how common they are (nmap's top 100, then the
// rest of its top 1000, then the others), each tier shuffled by seed.
func Tiered(ports []int, seed int64) []int {
	t := tiers()
	var tier [3][]int
	for _, p := range ports {
		switch {
		case t.top100[p]:
			tier[0] = append(tier[0], p)
		case t.top1000[p]:
			tier[1] = append(tier[1], p)
		default:
			tier[2] = append(tier[2], p)
		}
	}
	rng := rand.New(rand.NewSource(seed))
	out := make([]int, 0, len(ports))
	for _, part := range tier {
		rng.Shuffle(len(part), func(i, j int) { part[i], part[j] = part[j], part[i] })
		out = append(out, part...)
	}
	return out
}

func hashOf(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return h.Sum64()
}
