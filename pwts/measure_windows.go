//go:build windows

package main

import (
	"golang.org/x/sys/windows"
	"unsafe"
)

type pmc struct {
	Cb, PageFaultCount                                                                                                                                                     uint32
	PeakWorkingSetSize, WorkingSetSize, QuotaPeakPagedPoolUsage, QuotaPagedPoolUsage, QuotaPeakNonPagedPoolUsage, QuotaNonPagedPoolUsage, PagefileUsage, PeakPagefileUsage uintptr
}

func processMemory() (uint64, uint64) {
	var m pmc
	m.Cb = uint32(unsafe.Sizeof(m))
	dll := windows.NewLazySystemDLL("psapi.dll")
	proc := dll.NewProc("GetProcessMemoryInfo")
	r, _, _ := proc.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&m)), uintptr(m.Cb))
	if r == 0 {
		return 0, 0
	}
	return uint64(m.WorkingSetSize), uint64(m.PeakWorkingSetSize)
}
