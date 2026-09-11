//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// diskUsage 返回 path 所在盘的总容量与可用容量（字节），走 GetDiskFreeSpaceExW
func diskUsage(path string) (total, free int64, err error) {
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetDiskFreeSpaceExW")
	p16, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0, err
	}
	var freeBytes, totalBytes, totalFree uint64
	r1, _, e1 := proc.Call(
		uintptr(unsafe.Pointer(p16)),
		uintptr(unsafe.Pointer(&freeBytes)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFree)),
	)
	if r1 == 0 {
		return 0, 0, e1
	}
	return int64(totalBytes), int64(freeBytes), nil
}
