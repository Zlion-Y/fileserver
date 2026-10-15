//go:build linux || darwin

package main

import "syscall"

// diskUsage 返回 path 所在文件系统的总容量、普通用户可用容量与已用容量（字节）。
// used 必须单独算：free 取 Bavail（已扣除 root 保留块），若让调用方用
// total-free 反推，就会把 ext4 那 5% 保留块也算成「已用」，磁盘水位显示偏高，
// 而 XFS/btrfs 等没有保留块的文件系统又不会偏 —— 同一套 UI 在不同盘上口径不一致
func diskUsage(path string) (total, free, used int64, err error) {
	var st syscall.Statfs_t
	if err = syscall.Statfs(path, &st); err != nil {
		return 0, 0, 0, err
	}
	bs := int64(st.Bsize)
	total = int64(st.Blocks) * bs
	free = int64(st.Bavail) * bs
	// 逐项转 int64 再相减：darwin 的 Blocks/Bfree 是 uint32 而 Bavail 是有符号的，
	// 直接 st.Blocks-st.Bfree 在两个平台上的类型不一致，交叉编译时会编不过
	used = (int64(st.Blocks) - int64(st.Bfree)) * bs
	return total, free, used, nil
}
