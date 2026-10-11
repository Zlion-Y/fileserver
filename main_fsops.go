package main

import (
	"archive/zip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func absEqual(a, b string) bool {
	if a == b {
		return true
	}
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.EqualFold(a, b)
	}
	return false
}

func absPrefix(parent, child string) bool {
	p := parent + string(filepath.Separator)
	if strings.HasPrefix(child, p) {
		return true
	}
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.HasPrefix(strings.ToLower(child), strings.ToLower(p))
	}
	return false
}

// pathWithin 判断 child 是否等于或位于 root 之内。
// 旧的字符串前缀判定 root+sep 在 root 为盘符根（C:\、/）时拼出双分隔符，
// 任何子路径都判不进 —— 整盘共享场景下所有请求被误拒
func pathWithin(root, child string) bool {
	if root == child {
		return true
	}
	trimmed := strings.TrimSuffix(root, string(filepath.Separator))
	if trimmed == "" { // Unix 根目录 "/"
		return true
	}
	return strings.HasPrefix(child, trimmed+string(filepath.Separator))
}

func safeJoin(root, rel string) (string, error) {
	clean := strings.TrimPrefix(filepath.FromSlash(rel), string(filepath.Separator))
	rootAbs, _ := filepath.Abs(root)
	target, _ := filepath.Abs(filepath.Join(rootAbs, clean))
	// 用 filepath.Rel 做包含性判定：对盘符根、根目录等边界一致成立，
	// 且天然拒绝 "../" 逃逸（Rel 结果以 .. 开头即出界）
	relPath, err := filepath.Rel(rootAbs, target)
	if err != nil || relPath == ".." || strings.HasPrefix(relPath, ".."+string(filepath.Separator)) {
		return "", errors.New("非法路径")
	}
	return target, nil
}

// realPathInside 校验「已存在的路径」的真实路径（解析完所有符号链接后）仍在 root 内。
// safeJoin 只做字符串前缀检查，root 内的 symlink 指向 root 外时会直接放行，
// 导致下载/删除/分享能越过根目录读写外部文件。此函数兜底：
//   - root 无法解析 → 拒绝（安全优先）
//   - target 不存在 → 放行（新建场景，后续由创建流程决定）
//   - target 已存在 → 必须 EvalSymlinks 后仍在 root 内
func realPathInside(root, target string) bool {
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false
	}
	tReal, err := filepath.EvalSymlinks(target)
	if err != nil {
		// 区分「不存在」与「无法解析」：不存在放行（新建场景，后续创建流程兜底）；
		// ELOOP/EACCES 等无法解析的错误安全优先拒绝 —— 旧的 fail-open 会让
		// root 内越界链接绕过包含性校验
		if _, stErr := os.Lstat(target); stErr != nil && os.IsNotExist(stErr) {
			return true
		}
		return false
	}
	return pathWithin(rootReal, tReal)
}

// ensureCreatableInside 「新建」路径的符号链接兜底。
// realPathInside 对不存在的 target 一律放行，于是当 target 的某个已存在祖先
// 是 root 内指向外部的 symlink 时，MkdirAll/CreateTemp/Rename 会把内容写到 root 外
// （实测：root/link -> /etc，上传到 link/newdir 即在 root 外建目录并落文件）。
// 这里自 target 逐级上溯，对第一个「已存在」的祖先做 EvalSymlinks 后判定仍在 root 内。
func ensureCreatableInside(root, target string) bool {
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false
	}
	p := target
	for i := 0; i < 256; i++ {
		if _, err := os.Lstat(p); err == nil {
			real, err := filepath.EvalSymlinks(p)
			if err != nil {
				return false // 悬空链接等无法解析的情况：安全优先，拒绝
			}
			return pathWithin(rootReal, real)
		}
		parent := filepath.Dir(p)
		if parent == p {
			return false
		}
		p = parent
	}
	return false
}

// ---------------- 回收站 ----------------
//
// 删除不再直接 RemoveAll，而是移入 <root>/.trash/（同文件系统 rename 原子完成，
// 跨盘也不会失败），附带 .meta.json 记录原路径供恢复；过期自动清理。
// .trash 位于 root 内会被列目录/搜索/分享/WebDAV 一致排除。

const trashDirName = ".trash"

// trashRoot 回收站根目录（懒创建）
func trashRoot(root string) string {
	dir := filepath.Join(root, trashDirName)
	_ = os.MkdirAll(dir, 0o755)
	return dir
}

// inTrashRel 相对路径是否指向回收站内部（或回收站本身）
//
// 必须先把路径归一化再比较：原始字符串前缀比较会被 `./.trash/x`、
// `a/../.trash/x`、`//.trash/x` 这类等价写法绕过（实测可列出/下载已删除文件），
// Windows/macOS 这类大小写不敏感的文件系统上 `.TRASH` 也能绕过。
func inTrashRel(rel string) bool {
	rel = path.Clean("/" + filepath.ToSlash(strings.TrimSpace(rel)))
	rel = strings.TrimPrefix(rel, "/")
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		// 大小写不敏感文件系统：.TRASH 与 .trash 是同一个目录，必须一并拦下
		rel = strings.ToLower(rel)
	}
	return rel == trashDirName || strings.HasPrefix(rel, trashDirName+"/")
}

// validTrashEntry 回收站条目名必须是「纯名字」：不能为空、不能是 . / .. 、
// 不能含路径分隔符，且必须等于自身的 filepath.Base。
// 否则 filepath.Join(回收站, entry) 会被 Clean 折叠到回收站之外 ——
// entry=".." 折叠成根目录（RemoveAll 直接删库），entry="." 折叠成回收站自身。
func validTrashEntry(entry string) bool {
	return entry != "" && entry != "." && entry != ".." &&
		!strings.ContainsAny(entry, `/\`) && entry == filepath.Base(entry)
}

// trashEntry 回收站条目
type trashEntry struct {
	Name    string `json:"name"` // 回收站内条目名（时间戳_原名）
	Orig    string `json:"orig"` // 删除前的相对路径
	IsDir   bool   `json:"isDir"`
	Size    int64  `json:"size"`
	Deleted int64  `json:"deleted"` // 删除时间（毫秒）
}

// moveToTrash 把 root 内的 target 移入回收站；返回回收站内条目名。
// 条目名格式：时间戳_随机短码_原名——同秒删除同名文件（尤其并发时）
// 也不会撞名：os.Rename 在 Linux 上会静默覆盖同目标名，旧方案两个
// 并发删除会在 Lstat 检测窗口内双双通过，后到者覆盖先到者造成文件丢失
func moveToTrash(root, target string) (string, error) {
	name := filepath.Base(target)
	stamp := time.Now().Format("20060102-150405")
	tdir := trashRoot(root)
	var rnd [2]byte
	_, _ = rand.Read(rnd[:])
	entry := fmt.Sprintf("%s_%x_%s", stamp, rnd[:], name)
	for i := 1; ; i++ {
		if _, err := os.Lstat(filepath.Join(tdir, entry)); os.IsNotExist(err) {
			break
		}
		entry = fmt.Sprintf("%s_%x_%d_%s", stamp, rnd[:], i, name)
	}
	if err := os.Rename(target, filepath.Join(tdir, entry)); err != nil {
		return "", err
	}
	// 旁挂元数据：记录原始相对路径，供「恢复」用；失败不阻断删除但必须留痕
	rel := filepath.ToSlash(strings.TrimPrefix(strings.TrimPrefix(target, root), string(filepath.Separator)))
	meta, _ := json.Marshal(map[string]any{"orig": rel, "at": time.Now().UnixMilli()})
	if err := os.WriteFile(filepath.Join(tdir, entry+".meta.json"), meta, 0o600); err != nil {
		log.Printf("[回收站] 元数据写入失败（%s），恢复时原路径将退化为条目名: %v", entry, err)
	}
	return entry, nil
}

// trashList 列出回收站条目（按删除时间倒序）
func trashList(root string) []trashEntry {
	tdir := filepath.Join(root, trashDirName)
	items, err := os.ReadDir(tdir)
	if err != nil {
		return []trashEntry{}
	}
	out := []trashEntry{}
	for _, it := range items {
		name := it.Name()
		// 元数据判定：必须「去掉 .meta.json 后缀仍存在对应条目」才算 meta 文件。
		// 仅按后缀判断会把用户删除的 x.meta.json 条目误判成元数据而在列表里消失
		if strings.HasSuffix(name, ".meta.json") {
			if stem := strings.TrimSuffix(name, ".meta.json"); stem != "" {
				if _, err := os.Lstat(filepath.Join(tdir, stem)); err == nil {
					continue // 确实是某条目的旁挂元数据
				}
			}
		}
		info, err := it.Info()
		if err != nil {
			continue
		}
		e := trashEntry{Name: name, IsDir: it.IsDir()}
		// 删除时间取文件名前缀的时间戳 —— 与 trashSweep 的过期判定同一口径。
		// 旧的用内容 mtime（rename 保留的是文件原修改时间），列表排序和
		// 「剩余天数」与实际清扫时间对不上
		if t, perr := time.ParseInLocation("20060102-150405", strings.SplitN(name, "_", 2)[0], time.Local); perr == nil {
			e.Deleted = t.UnixMilli()
		} else {
			e.Deleted = info.ModTime().UnixMilli()
		}
		if !it.IsDir() {
			e.Size = info.Size()
		}
		// 原路径从旁挂元数据读取；缺失时从条目名截取（去掉 时间戳[_序号]_ 前缀）
		e.Orig = trashOrigFromName(name)
		if b, err := os.ReadFile(filepath.Join(tdir, name+".meta.json")); err == nil {
			var m struct {
				Orig string `json:"orig"`
			}
			if json.Unmarshal(b, &m) == nil && m.Orig != "" {
				e.Orig = m.Orig
			}
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Deleted > out[j].Deleted })
	return out
}

// trashOrigFromName 从「时间戳[_随机码[_序号]]_原名」恢复出原名；
// 兼容 v1.1.0/1.1.1 旧格式「时间戳_原名」与「时间戳_序号_原名」
func trashOrigFromName(entry string) string {
	parts := strings.Split(entry, "_")
	if len(parts) < 2 || len(parts[0]) != 15 || parts[0][8] != '-' {
		return entry // 无法识别的格式原样返回
	}
	// 新格式：时间戳_随机码_原名（3 段）或冲突重试含序号（4 段）
	// 旧格式：时间戳_原名（2 段）或时间戳_序号_原名（3 段）
	// 区分：第 2 段是 4 位 hex 随机码（新）还是原名/序号（旧）。
	// 旧序号是纯数字，旧原名几乎不会恰好是 4 位 hex；优先新格式解读
	rest := parts[1:]
	if len(rest) >= 2 && isHex4(rest[0]) {
		// 冲突重试的新格式「时间戳_随机码_序号_原名」要跳过中间的序号段，
		// 否则恢复出的文件名会多出 "1_" 前缀
		if len(rest) >= 3 && isAllDigits(rest[1]) {
			return strings.Join(rest[2:], "_")
		}
		return strings.Join(rest[1:], "_")
	}
	// 旧格式：余下全部（序号_原名 或 原名含下划线的情形）——序号无法与
	// 原名可靠区分，直接拼回；仅当恰好两段且第二段是纯数字时跳过序号
	if len(rest) == 2 && isAllDigits(rest[0]) {
		return rest[1]
	}
	return strings.Join(rest, "_")
}

func isHex4(s string) bool {
	if len(s) != 4 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// trashRestore 把回收站条目恢复到原路径；原位置被占用时自动加 (1)(2)… 后缀
func trashRestore(root, entry string) (string, error) {
	if !validTrashEntry(entry) {
		return "", errors.New("条目名不合法")
	}
	tdir := trashRoot(root)
	src := filepath.Join(tdir, entry)
	if _, err := os.Lstat(src); err != nil {
		return "", errors.New("回收站内不存在该条目")
	}
	orig := trashOrigFromName(entry)
	if b, err := os.ReadFile(src + ".meta.json"); err == nil {
		var m struct {
			Orig string `json:"orig"`
		}
		if json.Unmarshal(b, &m) == nil && m.Orig != "" {
			orig = m.Orig
		}
	}
	orig = filepath.ToSlash(orig)
	if inTrashRel(orig) || strings.Contains(orig, "..") {
		return "", errors.New("原路径不合法")
	}
	dst, err := safeJoin(root, orig)
	if err != nil {
		return "", err
	}
	// 回收站内容可能恢复进「root 内 symlink 指向的外部目录」：与上传/移动
	// 同一威胁模型，必须走 ensureCreatableInside 校验已存在祖先
	if !ensureCreatableInside(root, dst) {
		return "", errors.New("原路径不合法")
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", fmt.Errorf("创建原目录失败: %w", err)
	}
	// 目标被占用 → 同名自动加后缀，与上传一致
	if _, err := os.Lstat(dst); err == nil {
		ext := filepath.Ext(dst)
		stem := strings.TrimSuffix(dst, ext)
		for i := 1; ; i++ {
			cand := fmt.Sprintf("%s(%d)%s", stem, i, ext)
			if _, err := os.Lstat(cand); os.IsNotExist(err) {
				dst = cand
				break
			}
		}
	}
	if err := os.Rename(src, dst); err != nil {
		return "", err
	}
	_ = os.Remove(src + ".meta.json")
	return filepath.ToSlash(strings.TrimPrefix(strings.TrimPrefix(dst, root), string(filepath.Separator))), nil
}

// trashPurge 彻底删除回收站内单个条目（连带其元数据）
func trashPurge(root, entry string) error {
	tdir := trashRoot(root)
	// 必须是纯条目名：仅挡住斜杠还不够 —— entry=".." 会被 filepath.Join 的 Clean
	// 折叠成 <root>，紧接着的 os.RemoveAll 就把整个根目录删了（实测可复现）；
	// entry="." 则会折叠成回收站自身。统一用 validTrashEntry 判定。
	if !validTrashEntry(entry) {
		return errors.New("条目名不合法")
	}
	if err := os.RemoveAll(filepath.Join(tdir, entry)); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(tdir, entry+".meta.json"))
	return nil
}

// trashSweep 清理超过保留期的回收站条目；条目时间取自文件名前缀的时间戳（确定性，
// 不依赖 rename 保留的 mtime）。返回清理数量。
func trashSweep(root string) int {
	trashDays := envInt("TRASH_DAYS", 7)
	if trashDays <= 0 {
		return 0 // 0 = 永久保留
	}
	cutoff, _ := time.ParseInLocation("20060102-150405", time.Now().AddDate(0, 0, -trashDays).Format("20060102-150405"), time.Local)
	tdir := filepath.Join(root, trashDirName)
	items, err := os.ReadDir(tdir)
	if err != nil {
		return 0
	}
	removed := 0
	for _, it := range items {
		name := it.Name()
		stamp := strings.SplitN(name, "_", 2)[0]
		t, err := time.ParseInLocation("20060102-150405", stamp, time.Local)
		if err != nil || t.After(cutoff) {
			continue
		}
		if trashPurge(root, name) == nil {
			removed++
		}
	}
	return removed
}

// reservedName 是否为系统保留名（回收站目录名）。大小写不敏感文件系统上
// .TRASH 与 .trash 是同一个目录，上传名为 .TRASH 的文件同样会瘫痪删除功能
func reservedName(name string) bool {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.EqualFold(name, trashDirName)
	}
	return name == trashDirName
}

func sanitizeName(name string) string {
	name = filepath.Base(filepath.FromSlash(name))
	name = strings.Map(func(r rune) rune {
		switch r {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|':
			return '_'
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	// Windows 保留设备名（含带扩展名形式如 CON.txt）无法正常创建/删除：
	// 仅检查主名部分，命中时加前缀避让（保留原扩展名）
	stem := name
	if i := strings.IndexByte(stem, '.'); i >= 0 {
		stem = stem[:i]
	}
	upper := strings.ToUpper(stem)
	for _, reserved := range []string{"CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"} {
		if upper == reserved {
			name = "_" + name
			break
		}
	}
	if name == "" || name == "." || name == ".." {
		name = "unnamed_" + strconv.FormatInt(time.Now().UnixMilli(), 10)
	}
	return name
}
func handleList(w http.ResponseWriter, r *http.Request, root string) {
	rel := r.URL.Query().Get("path")
	if inTrashRel(rel) {
		writeJSON(w, 400, map[string]any{"error": "回收站内容请从回收站页面管理"})
		return
	}
	dir, err := safeJoin(root, rel)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if !realPathInside(root, dir) {
		writeJSON(w, 400, map[string]any{"error": "非法路径"})
		return
	}
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		writeJSON(w, 400, map[string]any{"error": "目录不存在"})
		return
	}
	items, err := os.ReadDir(dir)
	if err != nil {
		// 静默返回空列表会让人误以为目录是空的（进而执行删除/重建等危险操作），
		// 必须把读取失败显式抛给前端（错误串脱敏，不回传绝对路径）
		writeJSON(w, 500, map[string]any{"error": fsErr("读取目录 "+rel, err)})
		return
	}
	entries := []map[string]any{}
	for _, it := range items {
		// 根目录下的回收站不进入常规列表（回收站有专页）
		if it.Name() == trashDirName && rel == "" {
			continue
		}
		// 分片上传的临时文件对列表不可见（完成前是半成品）
		if isUploadTemp(it.Name()) {
			continue
		}
		info, err := it.Info()
		if err != nil {
			continue
		}
		size := info.Size()
		if it.IsDir() {
			size = 0
		}
		entries = append(entries, map[string]any{
			"name":  it.Name(),
			"isDir": it.IsDir(),
			"size":  size,
			"mtime": info.ModTime().UnixMilli(),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		di := entries[i]["isDir"].(bool)
		dj := entries[j]["isDir"].(bool)
		if di != dj {
			return di
		}
		return strings.ToLower(entries[i]["name"].(string)) < strings.ToLower(entries[j]["name"].(string))
	})
	q := r.URL.Query()
	// 服务端筛选：filter（all/file/dir）+ size（gt-100mb/gt-1gb/lt-1mb），
	// 仅在带 limit 的分页请求时生效（分页必须先筛选后切片，否则前端筛选会漏数据）
	if q.Get("limit") != "" {
		entries = listApplyFilter(entries, q.Get("filter"), q.Get("size"))
		entries = listApplySort(entries, q.Get("sort"))
	} else {
		// 兼容旧调用：仅按上面默认的「文件夹在前 + 名称升序」返回
	}
	total := len(entries)
	hasMore := false
	if ls := q.Get("limit"); ls != "" {
		limit, err1 := strconv.Atoi(ls)
		offset, err2 := strconv.Atoi(q.Get("offset"))
		if err1 == nil && limit > 0 {
			if err2 != nil || offset < 0 {
				offset = 0
			}
			// 上限保护：单页最多 5000，防止 offset+limit 构造出巨型切片
			if limit > 5000 {
				limit = 5000
			}
			if offset > total {
				offset = total
			}
			end := offset + limit
			if end > total {
				end = total
			}
			hasMore = end < total
			entries = entries[offset:end]
		} else {
			writeJSON(w, 400, map[string]any{"error": "limit 参数不合法"})
			return
		}
	}
	parent := ""
	if rel != "" {
		parent = filepath.ToSlash(filepath.Dir(rel))
		if parent == "." {
			parent = ""
		}
	}
	writeJSON(w, 200, map[string]any{
		"rootDir": root, "path": rel, "parent": parent, "entries": entries,
		"total": total, "hasMore": hasMore,
	})
}

// listApplySort 与前端下拉同步的排序（文件夹始终在前；sort 为空时默认按修改时间倒序）
func listApplySort(entries []map[string]any, mode string) []map[string]any {
	if mode == "" {
		mode = "time-desc"
	}
	byName := func(i, j int) bool {
		return strings.ToLower(entries[i]["name"].(string)) < strings.ToLower(entries[j]["name"].(string))
	}
	bySize := func(i, j int) bool {
		return entries[i]["size"].(int64) < entries[j]["size"].(int64)
	}
	byTime := func(i, j int) bool {
		return entries[i]["mtime"].(int64) < entries[j]["mtime"].(int64)
	}
	var less func(i, j int) bool
	var asc bool
	switch mode {
	case "name-asc":
		less, asc = byName, true
	case "name-desc":
		less, asc = byName, false
	case "size-asc":
		less, asc = bySize, true
	case "size-desc":
		less, asc = bySize, false
	case "time-asc":
		less, asc = byTime, true
	default: // time-desc 及未知值
		less, asc = byTime, false
	}
	sort.SliceStable(entries, func(i, j int) bool {
		di := entries[i]["isDir"].(bool)
		dj := entries[j]["isDir"].(bool)
		if di != dj {
			return di
		}
		if asc {
			return less(i, j)
		}
		return less(j, i)
	})
	return entries
}

// listApplyFilter 与前端下拉同步的类型/大小筛选
func listApplyFilter(entries []map[string]any, filter, size string) []map[string]any {
	out := entries[:0:0]
	const MB = 1024 * 1024
	for _, e := range entries {
		isDir := e["isDir"].(bool)
		if filter == "file" && isDir {
			continue
		}
		if filter == "dir" && !isDir {
			continue
		}
		if !isDir {
			sz := e["size"].(int64)
			if size == "gt-100mb" && sz <= 100*MB {
				continue
			}
			if size == "gt-1gb" && sz <= 1024*MB {
				continue
			}
			if size == "lt-1mb" && sz >= MB {
				continue
			}
		}
		out = append(out, e)
	}
	return out
}

func handleMkdir(w http.ResponseWriter, r *http.Request, root string) {
	relParam := r.URL.Query().Get("path")
	if inTrashRel(relParam) {
		writeJSON(w, 400, map[string]any{"error": "不能在回收站内创建目录"})
		return
	}
	dir, err := safeJoin(root, relParam)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if !ensureCreatableInside(root, dir) {
		writeJSON(w, 400, map[string]any{"error": "非法路径"})
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := decodeStrict(w, r, &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "请求参数错误: " + err.Error()})
		return
	}
	name := sanitizeName(body.Name)
	if name == "" {
		writeJSON(w, 400, map[string]any{"error": "名称不能为空"})
		return
	}
	if reservedName(name) {
		writeJSON(w, 400, map[string]any{"error": "该名称为系统保留"})
		return
	}
	target := filepath.Join(dir, name)
	if _, err := os.Stat(target); err == nil {
		writeJSON(w, 400, map[string]any{"error": "已存在同名文件夹"})
		return
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		writeJSON(w, 500, map[string]any{"error": fsErr("创建目录", err)})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// decodeStrict 严格 JSON 解码：语法错误或含未知字段都报错。
// 避免手写 API 时字段名拼错被静默忽略（如把 expireSeconds 写成
// expireHours，过期时间丢失、链接静默变成永久有效）。
//
// 解析细节只记服务端日志；对外统一返回固定文案——原始解析错误
// （json: cannot unmarshal ... 等）会向客户端暴露后端语言与内部
// 结构体定义，属于信息泄露。
//
// 请求体套 MaxBytesReader 封顶 1 MiB：/api/login 在认证前就可达，
// 不限的话客户端可流式灌入超大 JSON 把内存吃爆。
func handleUpload(w http.ResponseWriter, r *http.Request, root string) {
	relParam := r.URL.Query().Get("path")
	if inTrashRel(relParam) {
		writeJSON(w, 400, map[string]any{"error": "不能上传到回收站"})
		return
	}
	dir, err := safeJoin(root, relParam)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	// 目标子目录可能还不存在，realPathInside 对不存在的路径直接放行，
	// 因此这里必须用 ensureCreatableInside 逐级校验已存在的祖先，挡住 symlink 逃逸
	if !ensureCreatableInside(root, dir) {
		writeJSON(w, 400, map[string]any{"error": "非法路径"})
		return
	}
	// 文件夹上传：目标子目录可能不存在，自动逐级创建（MkdirAll 幂等）
	if err := os.MkdirAll(dir, 0o755); err != nil {
		writeJSON(w, 400, map[string]any{"error": "目标目录不存在或不可创建"})
		return
	}
	// 流式解析：逐 part 直接写目标文件，不经过 ParseMultipartForm 的临时盘中转，
	// 大文件不会"系统 tmp + 目标目录"双份写，也不再受 32MB 内存缓冲阈值影响
	mr, err := r.MultipartReader()
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "解析上传数据失败"})
		return
	}
	var maxBytes int64 // 单文件上限（0 = 不限制）
	if flagMaxMB > 0 {
		maxBytes = flagMaxMB * 1024 * 1024
	}
	saved := []map[string]any{}
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			// 已经落盘的文件不会因为后续失败而回滚，必须把 saved 告诉客户端，
			// 否则用户只看到「失败」却不知道磁盘上多了哪些文件
			if isMaxBytesErr(err) {
				writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
					"ok": false, "files": saved,
					"error": fmt.Sprintf("上传内容超过 %dMB 限制", flagMaxMB)})
			} else {
				writeJSON(w, 400, map[string]any{
					"ok": false, "files": saved, "error": "解析上传数据失败"})
			}
			return
		}
		filename := part.FileName()
		if filename == "" { // 普通表单字段，忽略
			part.Close()
			continue
		}
		// 上传名为 .trash 的文件会在 root 下生成普通文件，之后所有删除
		// （API/WebDAV）rename 进「它」都会 500，删除功能整体瘫痪；
		// 与 handleMkdir 的保留名检查对齐，必须在落盘前拒绝
		if reservedName(sanitizeName(filename)) {
			writeJSON(w, 400, map[string]any{
				"ok": false, "files": saved, "failed": sanitizeName(filename),
				"error": "该文件名为系统保留，不能使用"})
			return
		}
		// 排他式保存：同名冲突（含并发上传）自动加 (1)/(2)… 后缀，
		// 不再依赖「先 Stat 后 Create」的 uniquePath（存在 TOCTOU 覆盖窗口）
		size, target, err := saveStreamExcl(dir, sanitizeName(filename), part, maxBytes)
		part.Close()
		if err != nil {
			// saveStreamExcl 已负责清理半成品文件
			if err == errFileTooLarge {
				writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
					"ok": false, "files": saved, "failed": sanitizeName(filename),
					"error": fmt.Sprintf("文件超过 %dMB 限制", flagMaxMB)})
			} else if isMaxBytesErr(err) {
				writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
					"ok": false, "files": saved, "failed": sanitizeName(filename),
					"error": fmt.Sprintf("上传内容超过 %dMB 限制", flagMaxMB)})
			} else {
				writeJSON(w, 500, map[string]any{
					"ok": false, "files": saved, "failed": sanitizeName(filename),
					"error": fsErr("保存上传文件", err)})
			}
			return
		}
		saved = append(saved, map[string]any{"name": filepath.Base(target), "path": target, "size": size})
	}
	writeJSON(w, 200, map[string]any{"ok": true, "files": saved})
}

// errFileTooLarge 单文件超过 --max-upload-mb（由 saveStreamExcl 判定）
var errFileTooLarge = errors.New("文件大小超过限制")

// ---------------- 分片断点续传上传 ----------------
//
// 大文件走「init → 逐片 PUT 追加 → complete 原子改名」三步：
//   - 分片文件落在目标目录内（.fup-<id>.part），保证 complete 时同盘 rename 原子生效；
//   - 每片必须从「当前已收字节数」处顺序追加，重试/重放不会写坏偏移；
//   - 会话在内存里，服务重启后客户端重新 init 即可；init 时顺带清理同目录
//     超 24h 的孤儿分片（崩溃/放弃上传留下的），不额外跑全盘扫描。

type uploadSession struct {
	ID         string
	Dir        string // 绝对路径（init 时已校验）
	DirRel     string // 相对根目录路径，用于每次追加前复查目录是否被移入回收站
	Name       string
	Size       int64
	Received   int64
	Created    time.Time
	LastActive time.Time
	mu         sync.Mutex // 串行化「校验偏移→追加→推进 Received」，并发/重试分片不会交错写入
}

func isUploadTemp(name string) bool {
	return strings.HasPrefix(name, uploadTempPrefix) && strings.HasSuffix(name, uploadTempSuffix)
}

// handleUploadInit POST /api/upload/init {dir,name,size} → {id}
func handleUploadInit(w http.ResponseWriter, r *http.Request, root string) {
	var body struct {
		Dir  string `json:"dir"`
		Name string `json:"name"`
		Size int64  `json:"size"`
	}
	if err := decodeStrict(w, r, &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "请求参数错误: " + err.Error()})
		return
	}
	if body.Size <= 0 {
		// size=0 会让 complete 的长度校验（sess.Size>0 才比对）被跳过，
		// 只传一片也能 200，静默产出截断文件；空文件走普通上传路径
		writeJSON(w, 400, map[string]any{"error": "size 不合法（分片上传不支持空文件）"})
		return
	}
	if flagMaxMB > 0 && body.Size > flagMaxMB*1024*1024 {
		writeJSON(w, http.StatusRequestEntityTooLarge,
			map[string]any{"error": fmt.Sprintf("文件超过 %dMB 限制", flagMaxMB)})
		return
	}
	if inTrashRel(body.Dir) {
		writeJSON(w, 400, map[string]any{"error": "不能上传到回收站"})
		return
	}
	dir, err := safeJoin(root, body.Dir)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if !ensureCreatableInside(root, dir) {
		writeJSON(w, 400, map[string]any{"error": "非法路径"})
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		writeJSON(w, 400, map[string]any{"error": "目标目录不存在或不可创建"})
		return
	}
	name := sanitizeName(body.Name)
	if name == "" {
		writeJSON(w, 400, map[string]any{"error": "文件名不能为空"})
		return
	}
	if reservedName(name) {
		writeJSON(w, 400, map[string]any{"error": "该文件名为系统保留，不能使用"})
		return
	}
	// 顺带清理同目录里超过 TTL 的孤儿分片（崩溃/放弃上传遗留）
	if items, err := os.ReadDir(dir); err == nil {
		for _, it := range items {
			if !isUploadTemp(it.Name()) {
				continue
			}
			if info, err := it.Info(); err == nil && time.Since(info.ModTime()) > uploadTempTTL {
				_ = os.Remove(filepath.Join(dir, it.Name()))
			}
		}
	}
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	id := hex.EncodeToString(buf)
	part := filepath.Join(dir, uploadTempPrefix+id+uploadTempSuffix)
	f, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": fsErr("创建分片文件", err)})
		return
	}
	_ = f.Close()
	now := time.Now()
	// DirRel 由 init 时的绝对路径反推：后续追加用它复查目录是否已被移入回收站
	dirRel := filepath.ToSlash(strings.TrimPrefix(strings.TrimPrefix(dir, root), string(filepath.Separator)))
	sess := &uploadSession{ID: id, Dir: dir, DirRel: dirRel, Name: name,
		Size: body.Size, Created: now, LastActive: now}
	upSessMu.Lock()
	upSessMap[id] = sess
	upSessMu.Unlock()
	writeJSON(w, 200, map[string]any{"ok": true, "id": id})
}

// handleUploadChunk PUT /api/upload/chunk?id=&offset= —— body 为原始分片字节
func handleUploadChunk(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	offset, _ := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
	upSessMu.Lock()
	sess := upSessMap[id]
	upSessMu.Unlock()
	if sess == nil {
		writeJSON(w, 404, map[string]any{"error": "上传会话不存在（可能服务已重启），请重新初始化", "code": "NO_SESSION"})
		return
	}
	// 「校验偏移 → 追加 → 推进 Received」必须在会话锁内一次完成：
	// 全局锁只护 map，两个重试分片同时越过偏移检查会交错追加，文件即损坏
	sess.mu.Lock()
	defer sess.mu.Unlock()
	// 上传中途目录被删除/移入回收站：追加必须终止，否则文件会写进回收站副本
	if inTrashRel(sess.DirRel) {
		writeJSON(w, 404, map[string]any{"error": "目标目录已被删除或移动", "code": "NO_DIR"})
		return
	}
	if offset != sess.Received {
		// 追加偏移不匹配：把服务端实际进度还给客户端，便于从正确位置续传
		writeJSON(w, http.StatusConflict, map[string]any{"error": "分片偏移不匹配", "received": sess.Received})
		return
	}
	// 单片上限取「64MB」与「距总上限的剩余量+1」的较小者；
	// 只用总上限做 LimitReader 时，大配额下单片可绕过 64MB 约束
	var limit int64 = uploadChunkMax + 1
	if flagMaxMB > 0 {
		if rem := flagMaxMB*1024*1024 - sess.Received + 1; rem < limit {
			limit = rem
		}
	}
	part := filepath.Join(sess.Dir, uploadTempPrefix+sess.ID+uploadTempSuffix)
	f, err := os.OpenFile(part, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	// 手动区分「读错误」（客户端断连）与「写错误」（磁盘满等）：
	// 两者都不删会话——已写入的字节数推进 Received 后状态依然一致，
	// 客户端从新偏移续传即可；只有「超限」这类终止性失败才整体作废。
	// 旧的统一 fail() 会把几十 GB 断点续传进度直接清零
	var n int64
	var readErr, writeErr error
	{
		lr := io.LimitReader(r.Body, limit)
		buf := make([]byte, 64<<10)
		for {
			nr, er := lr.Read(buf)
			if nr > 0 {
				nw, ew := f.Write(buf[:nr])
				n += int64(nw) // 部分写入时只累计实际落盘的字节数
				if ew != nil {
					writeErr = ew
					break
				}
				if nw != nr {
					writeErr = io.ErrShortWrite
					break
				}
			}
			if er == io.EOF {
				break
			}
			if er != nil {
				readErr = er
				break
			}
		}
	}
	closeErr := f.Close()
	// 终止性失败（单片超限/总量超限）：字节已追加进分片文件，Received 与
	// 文件大小从此错位，必须整体作废（删文件+删会话），绝不能带病续传
	fail := func(code int, msg string) {
		_ = os.Remove(part)
		upSessMu.Lock()
		delete(upSessMap, id)
		upSessMu.Unlock()
		writeJSON(w, code, map[string]any{"error": msg, "code": "ABORTED"})
	}
	if closeErr != nil {
		// Close 失败时缓冲区数据是否落盘未知，只能作废
		fail(500, "分片写入失败")
		return
	}
	if writeErr != nil {
		sess.Received += n
		log.Printf("[上传] 分片写入中断（%s @ %d）: %v", sess.Name, sess.Received, writeErr)
		writeJSON(w, http.StatusInsufficientStorage, map[string]any{
			"error": "写入失败（磁盘满或权限问题），已保留已传进度", "received": sess.Received})
		return
	}
	if readErr != nil {
		// 客户端断连：保留分片与会话，进度照常累计，重连后从 Received 续传
		sess.Received += n
		sess.LastActive = time.Now()
		writeJSON(w, http.StatusRequestTimeout, map[string]any{
			"error": "连接中断，已保留上传进度", "received": sess.Received})
		return
	}
	if n == uploadChunkMax+1 {
		fail(http.StatusRequestEntityTooLarge, "单片超过 64MB 上限")
		return
	}
	if flagMaxMB > 0 && sess.Received+n > flagMaxMB*1024*1024 {
		fail(http.StatusRequestEntityTooLarge,
			fmt.Sprintf("文件超过 %dMB 限制", flagMaxMB))
		return
	}
	sess.Received += n
	sess.LastActive = time.Now()
	writeJSON(w, 200, map[string]any{"ok": true, "received": sess.Received})
}

// handleUploadComplete POST /api/upload/complete?id= → 校验长度后原子改名为最终文件
func handleUploadComplete(w http.ResponseWriter, r *http.Request, root string) {
	id := r.URL.Query().Get("id")
	upSessMu.Lock()
	sess := upSessMap[id]
	upSessMu.Unlock()
	if sess == nil {
		writeJSON(w, 404, map[string]any{"error": "上传会话不存在"})
		return
	}
	// 与分片追加互斥：最后一个分片还在写时不允许改名
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if inTrashRel(sess.DirRel) {
		upSessMu.Lock()
		delete(upSessMap, id)
		upSessMu.Unlock()
		_ = os.Remove(filepath.Join(sess.Dir, uploadTempPrefix+sess.ID+uploadTempSuffix))
		writeJSON(w, 404, map[string]any{"error": "目标目录已被删除或移动", "code": "NO_DIR"})
		return
	}
	part := filepath.Join(sess.Dir, uploadTempPrefix+sess.ID+uploadTempSuffix)
	st, err := os.Stat(part)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "分片文件丢失"})
		return
	}
	if sess.Size > 0 && st.Size() != sess.Size {
		// 不删除会话：客户端补齐缺失分片后可直接再次 complete
		writeJSON(w, 400, map[string]any{
			"error":    fmt.Sprintf("分片不完整：已收 %d / 共 %d 字节", st.Size(), sess.Size),
			"received": st.Size()})
		return
	}
	if flagMaxMB > 0 && st.Size() > flagMaxMB*1024*1024 {
		upSessMu.Lock()
		delete(upSessMap, id)
		upSessMu.Unlock()
		_ = os.Remove(part)
		writeJSON(w, http.StatusRequestEntityTooLarge,
			map[string]any{"error": fmt.Sprintf("文件超过 %dMB 限制", flagMaxMB)})
		return
	}
	// 最终名占用（含并发完成）时与普通上传一致加 (1)(2) 后缀
	final, err := exclusiveName(sess.Dir, sess.Name)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": fsErr("分配最终文件名", err)})
		return
	}
	if err := os.Rename(part, final); err != nil {
		writeJSON(w, 500, map[string]any{"error": fsErr("分片改名", err)})
		return
	}
	upSessMu.Lock()
	delete(upSessMap, id)
	upSessMu.Unlock()
	writeJSON(w, 200, map[string]any{"ok": true, "files": []map[string]any{
		{"name": filepath.Base(final), "path": final, "size": st.Size()},
	}})
}

// exclusiveName 在 dir 内为 name 找一个不冲突的名字（name、name(1).ext、name(2).ext…）
func exclusiveName(dir, name string) (string, error) {
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := 0; ; i++ {
		cand := name
		if i > 0 {
			cand = fmt.Sprintf("%s(%d)%s", stem, i, ext)
		}
		p := filepath.Join(dir, cand)
		if _, err := os.Lstat(p); os.IsNotExist(err) {
			return p, nil
		} else if err != nil {
			return "", err
		}
	}
}

// handleUploadStatus GET /api/upload/status?id= → {received,size}（页面刷新后续传）
func handleUploadStatus(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	upSessMu.Lock()
	sess := upSessMap[id]
	upSessMu.Unlock()
	if sess == nil {
		writeJSON(w, 404, map[string]any{"error": "上传会话不存在", "code": "NO_SESSION"})
		return
	}
	// Received 由分片追加在 sess.mu 内改写，这里必须持同一把锁读快照，
	// 否则与并发分片写入构成数据竞争（go test -race 可复现）
	sess.mu.Lock()
	recv, size := sess.Received, sess.Size
	sess.mu.Unlock()
	writeJSON(w, 200, map[string]any{"ok": true, "received": recv, "size": size})
}

// handleUploadAbort DELETE /api/upload/chunk?id= —— 放弃上传并删除分片
func handleUploadAbort(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	upSessMu.Lock()
	sess := upSessMap[id]
	delete(upSessMap, id)
	upSessMu.Unlock()
	if sess != nil {
		sess.mu.Lock() // 与追加互斥，避免删掉正在写入的分片
		_ = os.Remove(filepath.Join(sess.Dir, uploadTempPrefix+sess.ID+uploadTempSuffix))
		sess.mu.Unlock()
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// gcUploadSessions 回收超时上传会话（由每小时清理任务调用）。
// 按最后活跃时间判定：慢速链路上的超大文件只要还在传就不误杀
func gcUploadSessions() {
	cutoff := time.Now().Add(-uploadTempTTL)
	upSessMu.Lock()
	var stale []*uploadSession
	for id, s := range upSessMap {
		if s.LastActive.Before(cutoff) {
			stale = append(stale, s)
			delete(upSessMap, id)
		}
	}
	upSessMu.Unlock()
	for _, s := range stale {
		s.mu.Lock()
		_ = os.Remove(filepath.Join(s.Dir, uploadTempPrefix+s.ID+uploadTempSuffix))
		s.mu.Unlock()
	}
}

// isMaxBytesErr 判断是否是 http.MaxBytesReader 触发的长度超限
func isMaxBytesErr(err error) bool {
	var mb *http.MaxBytesError
	return errors.As(err, &mb)
}

// saveStreamExcl 排他式流式写入：以 O_CREATE|O_EXCL 原子创建文件，
// 名字被占用（含并发上传同时命中同名）时自动尝试 (1)/(2)… 后缀重试，
// 消除 uniquePath「先 Stat 后 Create」的 TOCTOU 互相覆盖窗口；
// maxBytes>0 时超过即返回 errFileTooLarge，两者都会清理半成品文件。
func saveStreamExcl(dir, name string, src io.Reader, maxBytes int64) (int64, string, error) {
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := 0; ; i++ {
		cand := name
		if i > 0 {
			cand = fmt.Sprintf("%s(%d)%s", stem, i, ext)
		}
		path := filepath.Join(dir, cand)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			if os.IsExist(err) {
				continue // 已被占用 → 下一个候选名
			}
			return 0, path, err
		}
		var rd io.Reader = src
		if maxBytes > 0 {
			rd = io.LimitReader(src, maxBytes+1) // 多读 1 字节用于判定超限
		}
		n, copyErr := io.Copy(f, rd)
		closeErr := f.Close()
		if copyErr != nil || closeErr != nil {
			os.Remove(path)
			if copyErr != nil {
				return n, path, copyErr
			}
			return n, path, closeErr
		}
		if maxBytes > 0 && n > maxBytes {
			os.Remove(path)
			return n, path, errFileTooLarge
		}
		return n, path, nil
	}
}

// ---------------- 流式 ZIP 打包 ----------------
//
// 分享文件夹 / 多选打包下载共用：边压缩边传输，磁盘上不产生中间 zip 文件。

// zipAdd 把 abs（文件或目录）以 name 加入 zip 流；目录递归打入全部子项。
// root 非空时，根目录下的回收站（.trash）绝不打入——已删除的文件不能借打包外泄
func zipAdd(zw *zip.Writer, root, abs, name string) error {
	info, err := os.Lstat(abs)
	if err != nil {
		return err
	}
	// 符号链接绝不入包：os.Open 会跟随链接，把 root 外文件内容
	// 打进公开分享的 zip（本地攻击者预放链接即可借道外泄任意文件）。
	// 指向目录的链接同样在此拦截（Lstat 的 symlink 不算 IsDir）
	if info.Mode()&os.ModeSymlink != 0 {
		log.Printf("[打包] 跳过符号链接 %s", abs)
		return nil
	}
	// 双保险：即便链接在打包窗口期被替换，解析后的真实路径越界也要拦
	if root != "" {
		rootReal, rerr := filepath.EvalSymlinks(root)
		real, aerr := filepath.EvalSymlinks(abs)
		// 条目解析失败（悬空/环）交给后续 os.Open 自然报错；解析成功就必须在根内
		if rerr == nil && aerr == nil && !pathWithin(rootReal, real) {
			log.Printf("[打包] 跳过越界条目 %s", abs)
			return nil
		}
	}
	if info.IsDir() {
		h := &zip.FileHeader{Name: name + "/", Method: zip.Store}
		h.SetMode(info.Mode())
		h.Modified = info.ModTime()
		if _, err := zw.CreateHeader(h); err != nil {
			return err
		}
		items, err := os.ReadDir(abs)
		if err != nil {
			return err
		}
		for _, it := range items {
			// 根级回收站排除：分享/打包根目录时不能把回收站内容（可能含
			// 用户已删除的敏感文件）混进 zip；子目录内用户自建的 .trash 不受影响
			if root != "" && abs == root && it.Name() == trashDirName {
				continue
			}
			// 分片上传的半成品同样不得借打包外泄
			if isUploadTemp(it.Name()) {
				continue
			}
			if err := zipAdd(zw, root, filepath.Join(abs, it.Name()), name+"/"+it.Name()); err != nil {
				return err
			}
		}
		return nil
	}
	h := &zip.FileHeader{Name: name, Method: zip.Deflate}
	h.SetMode(info.Mode())
	h.Modified = info.ModTime()
	w, err := zw.CreateHeader(h)
	if err != nil {
		return err
	}
	f, err := os.Open(abs)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(w, f)
	return err
}

// serveZipStream 把多个 abs 路径打包成 zip 流式写出（zipName 不含 .zip 后缀）
// 所有路径必须已通过 safeJoin/realPathInside 校验
func serveZipStream(w http.ResponseWriter, r *http.Request, root string, paths []string, zipName string) {
	// 先统一校验存在性：流开始后出错无法再改状态码
	for _, p := range paths {
		if _, err := os.Lstat(p); err != nil {
			writeJSON(w, 404, map[string]any{"error": "文件不存在: " + filepath.Base(p)})
			return
		}
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", contentDisposition("attachment", zipName)+".zip")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
	zw := zip.NewWriter(w)
	defer zw.Close()
	for _, p := range paths {
		if err := zipAdd(zw, root, p, filepath.Base(p)); err != nil {
			return // 流已开始，只能中断
		}
	}
}

func handleDelete(w http.ResponseWriter, r *http.Request, root string) {
	target, err := safeJoin(root, r.URL.Query().Get("path"))
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if !realPathInside(root, target) {
		writeJSON(w, 400, map[string]any{"error": "非法路径"})
		return
	}
	if target == root {
		writeJSON(w, 400, map[string]any{"error": "不能删除根目录"})
		return
	}
	// 回收站内部及回收站本身不允许再「移入回收站」：彻底删除走回收站页面的专用接口
	if inTrashRel(r.URL.Query().Get("path")) {
		writeJSON(w, 400, map[string]any{"error": "回收站内文件请从回收站页面恢复或彻底删除"})
		return
	}
	if _, err := os.Stat(target); err != nil {
		writeJSON(w, 404, map[string]any{"error": "文件不存在"})
		return
	}
	// 删除 = 移入回收站（同盘 rename，原子且廉价），可在回收站页面恢复
	if _, err := moveToTrash(root, target); err != nil {
		writeJSON(w, 500, map[string]any{"error": fsErr("移入回收站", err)})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "trashed": true})
}

// handleZipDownload 多选打包：POST {paths:["a/b.txt","dir"]} → 流式 zip
func handleZipDownload(w http.ResponseWriter, r *http.Request, root string) {
	var body struct {
		Paths []string `json:"paths"`
	}
	if err := decodeStrict(w, r, &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "请求参数错误: " + err.Error()})
		return
	}
	if len(body.Paths) == 0 {
		writeJSON(w, 400, map[string]any{"error": "paths 不能为空"})
		return
	}
	if len(body.Paths) > 2000 {
		writeJSON(w, 400, map[string]any{"error": "单次打包最多 2000 项"})
		return
	}
	abs := make([]string, 0, len(body.Paths))
	for _, rel := range body.Paths {
		if inTrashRel(rel) {
			writeJSON(w, 400, map[string]any{"error": "不能打包回收站内容"})
			return
		}
		p, err := safeJoin(root, rel)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		if !realPathInside(root, p) {
			writeJSON(w, 400, map[string]any{"error": "非法路径"})
			return
		}
		abs = append(abs, p)
	}
	name := "files"
	if len(abs) == 1 {
		name = filepath.Base(abs[0])
	}
	serveZipStream(w, r, root, abs, name)
}

// handleTrashRestore 恢复：POST {name:"回收站内条目名"}
func handleTrashRestore(w http.ResponseWriter, r *http.Request, root string) {
	var body struct {
		Name string `json:"name"`
	}
	if err := decodeStrict(w, r, &body); err != nil || strings.TrimSpace(body.Name) == "" {
		writeJSON(w, 400, map[string]any{"error": "请求参数错误"})
		return
	}
	rel, err := trashRestore(root, body.Name)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "path": rel})
}

// handleTrashPurge 彻底删除：POST {name} 或 clear=true 清空
func handleTrashPurge(w http.ResponseWriter, r *http.Request, root string, clear bool) {
	if clear {
		removed := 0
		for _, it := range trashList(root) {
			if trashPurge(root, it.Name) == nil {
				removed++
			}
		}
		writeJSON(w, 200, map[string]any{"ok": true, "removed": removed})
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := decodeStrict(w, r, &body); err != nil || strings.TrimSpace(body.Name) == "" {
		writeJSON(w, 400, map[string]any{"error": "请求参数错误"})
		return
	}
	if err := trashPurge(root, body.Name); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// handleLogin 登录页提交：验证账号密码（复用防爆破），签发 Cookie 会话
func handleMove(w http.ResponseWriter, r *http.Request, root string) {
	var body struct {
		From string `json:"from"`
		To   string `json:"to"`
	}
	if err := decodeStrict(w, r, &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "请求参数错误: " + err.Error()})
		return
	}
	fromAbs, err := safeJoin(root, body.From)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	toAbs, err := safeJoin(root, body.To)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	// symlink 兜底：源文件必须真实位于 root 内；目标（通常尚不存在）校验其父目录，
	// 必须用 ensureCreatableInside —— realPathInside 对不存在的父目录直接放行，
	// 下面 os.MkdirAll 会跟随 symlink 把目录建到 root 外
	if !realPathInside(root, fromAbs) {
		writeJSON(w, 400, map[string]any{"error": "非法路径"})
		return
	}
	if !ensureCreatableInside(root, filepath.Dir(toAbs)) {
		writeJSON(w, 400, map[string]any{"error": "非法目标路径"})
		return
	}
	if fromAbs == root || toAbs == root {
		writeJSON(w, 400, map[string]any{"error": "非法目标路径"})
		return
	}
	// 回收站路径双向禁止：不能把文件移进回收站，也不能从回收站往外移
	// （回收站条目的恢复走专用接口，会同时处理元数据）
	if inTrashRel(body.From) || inTrashRel(body.To) {
		writeJSON(w, 400, map[string]any{"error": "回收站内容请从回收站页面操作"})
		return
	}
	if fromAbs == toAbs || absEqual(fromAbs, toAbs) {
		writeJSON(w, 400, map[string]any{"error": "源与目标是同一路径"})
		return
	}
	// 自嵌套校验：不能把文件夹移动到它自己的子目录里。
	// 前端已拦截，但 API 层必须兜底，否则只能靠 os.Rename 报 500
	if absPrefix(fromAbs, toAbs) {
		writeJSON(w, 400, map[string]any{"error": "不能移动到自身或其子目录下"})
		return
	}
	if _, err := os.Stat(fromAbs); err != nil {
		writeJSON(w, 404, map[string]any{"error": "源文件不存在"})
		return
	}
	if tf, err := os.Lstat(toAbs); err == nil {
		// Windows/macOS 大小写不敏感文件系统上「仅改变大小写」的目标与源
		// 指向同一个文件，Lstat 命中不能一概判为冲突
		if sf, err2 := os.Lstat(fromAbs); err2 == nil && os.SameFile(tf, sf) {
			writeJSON(w, 400, map[string]any{"error": "源与目标是同一路径"})
			return
		}
		writeJSON(w, 400, map[string]any{"error": "目标位置已存在同名文件或文件夹"})
		return
	}
	// 目标目录必须已存在（不隐式创建，避免误操作堆出目录树）
	if st, err := os.Stat(filepath.Dir(toAbs)); err != nil || !st.IsDir() {
		writeJSON(w, 400, map[string]any{"error": "目标目录不存在"})
		return
	}
	if err := os.Rename(fromAbs, toAbs); err != nil {
		writeJSON(w, 500, map[string]any{"error": fsErr("移动/重命名", err)})
		return
	}
	// 同步修正引用旧路径的分享记录，链接不断。
	// 匹配必须覆盖被移动目录内的所有子路径（前缀匹配），
	// 否则移动一个含已分享文件的目录后，目录内所有分享链接会 404
	changed := moveShareSync(root, fromAbs, toAbs)
	writeJSON(w, 200, map[string]any{"ok": true, "to": body.To, "sharesUpdated": changed})
}

// moveShareSync 移动/重命名后同步分享记录（含目录内子文件的前缀替换），返回是否有修改
func moveShareSync(root, fromAbs, toAbs string) bool {
	newRel := filepath.ToSlash(strings.TrimPrefix(strings.TrimPrefix(toAbs, root), string(filepath.Separator)))
	changed := false
	shareMu.Lock()
	for _, s := range shares {
		if absEqual(s.AbsPath, fromAbs) { // 被移动的文件/目录本身
			s.AbsPath = toAbs
			s.RelPath = newRel
			s.Name = filepath.Base(toAbs)
			changed = true
		} else if absPrefix(fromAbs, s.AbsPath) {
			// 目录内子文件的分享：前缀整体替换，RelPath 基于新 AbsPath 重算
			s.AbsPath = toAbs + strings.TrimPrefix(s.AbsPath, fromAbs)
			s.RelPath = filepath.ToSlash(strings.TrimPrefix(strings.TrimPrefix(s.AbsPath, root), string(filepath.Separator)))
			changed = true
		}
	}
	shareMu.Unlock()
	if changed {
		saveShares()
	}
	return changed
}

// handleSearch 递归搜索文件名（限定根目录内，限量防止大目录卡死）
func handleSearch(w http.ResponseWriter, r *http.Request, root string) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	limit := envInt("SEARCH_LIMIT", 200)
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	results := []map[string]any{}
	scanTruncated := false
	if q != "" {
		scanned := 0
		var walk func(dir, rel string) bool // false = 提前终止
		walk = func(dir, rel string) bool {
			items, err := os.ReadDir(dir)
			if err != nil {
				return true
			}
			for _, it := range items {
				name := it.Name()
				if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "$") || isUploadTemp(name) {
					continue
				}
				scanned++
				if scanned > 200000 {
					// 扫描上限触发的提前终止必须让前端知道，
					// 否则界面显示「完整结果」，用户误判文件不存在
					scanTruncated = true
					return false
				}
				childRel := name
				if rel != "" {
					childRel = rel + "/" + name
				}
				if strings.Contains(strings.ToLower(name), q) {
					var size, mtime int64
					if info, e1 := it.Info(); e1 == nil {
						size = info.Size()
						mtime = info.ModTime().UnixMilli()
					}
					results = append(results, map[string]any{
						"path": childRel, "name": name, "isDir": it.IsDir(),
						"size": size, "mtime": mtime,
					})
					if len(results) >= limit {
						return false
					}
				}
				if it.IsDir() && !walk(filepath.Join(dir, name), childRel) {
					return false
				}
			}
			return true
		}
		walk(root, "")
	}
	writeJSON(w, 200, map[string]any{"results": results, "truncated": len(results) >= limit || scanTruncated})
}

// ---------------- WebDAV（Class 1 最小子集） ----------------
//
// 面向 Salt Player / foobar2000 / N_player 等音乐播放器与常规 WebDAV 客户端：
// OPTIONS / PROPFIND / GET / HEAD / PUT / MKCOL / DELETE / MOVE / PROPPATCH。
// 不实现 LOCK/UNLOCK（Class 2），Windows 资源管理器「映射网络驱动器」需要锁，不受支持。
// 鉴权：Basic（用户名/密码同管理端）或登录会话 Cookie；未启用认证时开放访问。
// 根路径即文件根目录：/dav/ = 根，/dav/音乐/a.mp3 = 根内相对路径。
