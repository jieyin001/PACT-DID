//go:build !windows

package main

import "runtime"

func processMemory() (uint64, uint64) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.Sys, m.Sys
}
