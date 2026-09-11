//go:build linux || darwin

package main

import "syscall"

// diskUsage 返回 path 所在文件系统的总容量与可用容量（字节）
func diskUsage(path string) (total, free int64, err error) {
	var st syscall.Statfs_t
	if err = syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	total = int64(st.Blocks) * int64(st.Bsize)
	free = int64(st.Bavail) * int64(st.Bsize) // 普通用户可用（扣除 root 保留块）
	return total, free, nil
}
