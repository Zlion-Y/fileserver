//go:build windows

package main

import (
	"runtime"
	"syscall"
	"unsafe"
)

// diskUsage 返回 path 所在盘的总容量、可用容量与已用容量（字节），走 GetDiskFreeSpaceExW。
// path 必须是目录：传文件时该 API 会失败（返回 0 并带错误），调用方按「拿不到」处理
func diskUsage(path string) (total, free, used int64, err error) {
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetDiskFreeSpaceExW")
	p16, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0, 0, err
	}
	var freeBytes, totalBytes, totalFree uint64
	// LazyProc.Call 是普通 Go 函数而非 syscall.Syscall 那样的编译器内建，
	// 「参数在调用期间存活」的安全豁免并不严格成立：这些指针指向的变量
	// 必须显式 KeepAlive 到调用之后，否则理论上可能在 Call 期间被 GC 回收
	r1, _, e1 := proc.Call(
		uintptr(unsafe.Pointer(p16)),
		uintptr(unsafe.Pointer(&freeBytes)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFree)),
	)
	runtime.KeepAlive(p16)
	runtime.KeepAlive(&freeBytes)
	runtime.KeepAlive(&totalBytes)
	runtime.KeepAlive(&totalFree)
	if r1 == 0 {
		return 0, 0, 0, e1
	}
	total = int64(totalBytes)
	free = int64(freeBytes)
	// totalFree 是「含保留在内的总空闲」，freeBytes 才是当前用户可用；
	// 已用按总容量减总空闲算，与 Unix 侧同口径（不把保留区算成已用）
	used = total - int64(totalFree)
	return total, free, used, nil
}
