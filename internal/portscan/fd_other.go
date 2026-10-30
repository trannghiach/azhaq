//go:build !unix

package portscan

func fdBudget() int { return 1000 }
