package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

func builtinChangelog() string {
	if strings.TrimSpace(changelogB64) == "" {
		return ""
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(changelogB64))
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return ""
	}
	// 防注入截断：CI 用 base64 -w0（不换行），若含换行说明内容异常，容忍处理
	return s
}

type ghRelease struct {
	TagName string `json:"tag_name"`
	Body    string `json:"body"`
	HTMLURL string `json:"html_url"`
}

// ghCompare GitHub compare API 的提交列表
type ghCompare struct {
	Commits []struct {
		SHA    string `json:"sha"`
		Commit struct {
			Message string `json:"message"`
		} `json:"commit"`
	} `json:"commits"`
}

func verNums(v string) [3]int {
	var out [3]int
	for i, part := range strings.SplitN(strings.TrimPrefix(strings.TrimSpace(v), "v"), ".", 3) {
		if i > 2 {
			break
		}
		if n, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
			out[i] = n
		}
	}
	return out
}

// verGreater 判断 a 是否比 b 更新（按数字段逐位比较）
func verGreater(a, b string) bool {
	av, bv := verNums(a), verNums(b)
	for i := 0; i < 3; i++ {
		if av[i] != bv[i] {
			return av[i] > bv[i]
		}
	}
	return false
}

// curVersion 统一成带单个 v 前缀的当前版本号
func curVersion() string {
	return "v" + strings.TrimPrefix(version, "v")
}

// isReleaseVersion 当前版本是否为正式发布版本（形如 v1.2.3）。
// 容器镜像/自构建常注入 "docker"、"dev" 这类非数字版本号，verNums 会解析成 [0,0,0]，
// 导致任何 Release 都被判定为「有更新」，并诱导用户在容器里替换二进制 + exec 重启。
// 非发布版本一律视为不可在线更新。
func isReleaseVersion() bool {
	v := strings.TrimPrefix(strings.TrimSpace(version), "v")
	if v == "" {
		return false
	}
	if _, err := strconv.Atoi(strings.SplitN(v, ".", 2)[0]); err != nil {
		return false
	}
	return true
}

// checkLatestRelease 查 GitHub 最新 Release（带缓存；服务端代理，规避浏览器跨域）。
// HTTP 请求在锁外完成：锁内发 6s 超时的请求会让并发「检查更新」串行阻塞
func checkLatestRelease(force bool) (*ghRelease, error) {
	updMu.Lock()
	now := time.Now().UnixMilli()
	if !force && updCheckedAt > 0 && now-updCheckedAt < updateCacheTTL {
		// 返回副本而非 &updCache：调用方在锁外读 TagName/Body/HTMLURL，
		// 直接交出全局指针会与并发 force 查询的 updCache = rel 赋值竞争
		snapshot := updCache
		updMu.Unlock()
		return &snapshot, nil
	}
	updMu.Unlock()

	req, err := http.NewRequest("GET",
		fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", updateRepo), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	client := &http.Client{Timeout: updateTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("无法连接 GitHub: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub API 返回 %d", resp.StatusCode)
	}
	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	if rel.TagName == "" {
		return nil, errors.New("GitHub 未返回版本号")
	}
	updMu.Lock()
	updCache = rel
	updCheckedAt = time.Now().UnixMilli()
	updMu.Unlock()
	return &rel, nil
}

func versionJSON(forceCheck bool) map[string]any {
	out := map[string]any{
		"version":   curVersion(),
		"commit":    commit,
		"buildTime": buildTime,
		"repo":      updateRepo,
		"goos":      runtime.GOOS,
		"goarch":    runtime.GOARCH,
		"goarm":     goarmVersion(),
		"asset":     assetName(),
	}
	if rel, err := checkLatestRelease(forceCheck); err != nil {
		out["checkOk"] = false
		out["checkError"] = err.Error()
	} else {
		out["checkOk"] = true
		out["latest"] = rel.TagName
		out["hasUpdate"] = isReleaseVersion() && verGreater(rel.TagName, curVersion())
		out["notes"] = enrichNotes(rel.TagName, rel.Body)
		out["releaseUrl"] = rel.HTMLURL
		out["assetUrl"] = fmt.Sprintf("https://github.com/%s/releases/download/%s/%s",
			updateRepo, rel.TagName, assetName())
	}
	// 当前版本的更新说明：优先用构建时注入的 changelog（离线可用、且是权威的
	// 提交清单）；未注入（本地 go build / docker）时退回 GitHub API 查 Release body。
	// 前者优先：GitHub 自动生成的说明只有 Full Changelog 链接时价值很低，
	// 而内置清单不依赖服务器能连上 GitHub
	out["releaseVersion"] = isReleaseVersion()
	if notes := builtinChangelog(); notes != "" {
		out["currentNotes"] = notes
		out["currentNotesSource"] = "builtin"
	} else if isReleaseVersion() {
		if notes, err := releaseNotesOf(curVersion()); err == nil {
			out["currentNotes"] = notes
		}
	}
	return out
}

// releaseNotesOf 查询指定 tag 的 Release 说明（带内存缓存，失败不影响主流程）。
// GitHub 自动生成的说明往往只有一行 Full Changelog 链接，可读性很差，
// 因此这里会在缺内容时用两个版本之间的提交记录补全。
func releaseNotesOf(tag string) (string, error) {
	notesMu.Lock()
	if v, ok := notesCache[tag]; ok {
		notesMu.Unlock()
		return v, nil
	}
	notesMu.Unlock() // HTTP 在锁外（同 checkLatestRelease），并发查询不串行阻塞
	var rel ghRelease
	if err := ghGetJSON(fmt.Sprintf("https://api.github.com/repos/%s/releases/tags/%s",
		updateRepo, url.PathEscape(tag)), &rel); err != nil {
		return "", err
	}
	notes := enrichNotes(tag, rel.Body)
	notesMu.Lock()
	notesCache[tag] = notes
	notesMu.Unlock()
	return notes, nil
}

// ghGetJSON 带超时与 Accept 头的 GitHub API GET（服务端代理，规避浏览器跨域）
func ghGetJSON(apiURL string, v any) error {
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	client := &http.Client{Timeout: updateTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("无法连接 GitHub: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("GitHub API 返回 %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// isAutoNotes Release 说明是否只是 GitHub 自动生成的占位内容
func isAutoNotes(body string) bool {
	for _, ln := range strings.Split(body, "\n") {
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "**Full Changelog**") ||
			strings.HasPrefix(t, "**Full Changelog**:") || strings.HasPrefix(t, "## What's Changed") {
			continue
		}
		return false
	}
	return true
}

// stripAutoFooter 去掉 GitHub 自动说明尾部的 **Full Changelog** 链接。
// 它是 compare 链接的 markdown 原文，在更新页里渲染成纯文本噪音
func stripAutoFooter(body string) string {
	lines := strings.Split(body, "\n")
	out := make([]string, 0, len(lines))
	for _, ln := range lines {
		if strings.HasPrefix(strings.TrimSpace(ln), "**Full Changelog**") {
			continue
		}
		out = append(out, ln)
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}

// enrichNotes 说明缺内容时，用本版本相对上一版本的提交记录补出可读的更新内容
func enrichNotes(tag, body string) string {
	body = stripAutoFooter(body)
	if !isAutoNotes(body) {
		return body
	}
	var out string
	if base := prevTagOf(tag); base != "" {
		if cs, err := commitsBetween(base, tag); err == nil && strings.TrimSpace(cs) != "" {
			out = "本次更新的提交：\n" + cs
		}
	} else {
		// 没有上一个版本可比（仓库首个发布）：列出该 tag 自身包含的提交。
		// 否则首版只会显示 GitHub 自动生成的「**Full Changelog**: …」原始文本
		if cs, err := commitsOfRef(tag); err == nil && strings.TrimSpace(cs) != "" {
			out = "本次发布包含的提交：\n" + cs
		}
	}
	if strings.TrimSpace(out) == "" {
		return body
	}
	if t := strings.TrimSpace(body); t != "" {
		out += "\n" + t
	}
	return out
}

// prevTagOf 在 Release 列表（按时间倒序）里找到 tag 的上一个版本
func prevTagOf(tag string) string {
	var list []ghRelease
	if err := ghGetJSON(fmt.Sprintf("https://api.github.com/repos/%s/releases?per_page=10", updateRepo), &list); err != nil {
		return ""
	}
	for i := 0; i+1 < len(list); i++ {
		if list[i].TagName == tag {
			return list[i+1].TagName
		}
	}
	return ""
}

// writeCommitNote 把一条提交渲染成「- 标题 + 缩进正文」；返回 false 表示无有效内容。
// 此前只取标题行，提交正文里的详细修复清单全部丢失，更新日志因此「显示不完全」；
// 正文逐行缩进展示（跳过签名与空行），单条最多 12 行防刷屏
func writeCommitNote(b *strings.Builder, msg string) bool {
	lines := strings.Split(strings.TrimSpace(msg), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return false
	}
	b.WriteString("- " + strings.TrimSpace(lines[0]) + "\n")
	shown := 0
	for _, ln := range lines[1:] {
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "Signed-off-by:") {
			continue
		}
		if shown >= 12 {
			b.WriteString("  …\n")
			break
		}
		b.WriteString("  " + t + "\n")
		shown++
	}
	return true
}

// commitsBetween 取两个 tag 之间的提交记录（旧 -> 新，最多 30 条，含说明正文）
func commitsBetween(base, head string) (string, error) {
	var cmp ghCompare
	if err := ghGetJSON(fmt.Sprintf("https://api.github.com/repos/%s/compare/%s...%s",
		updateRepo, url.PathEscape(base), url.PathEscape(head)), &cmp); err != nil {
		return "", err
	}
	var b strings.Builder
	n := 0
	for i := len(cmp.Commits) - 1; i >= 0 && n < 30; i-- {
		if writeCommitNote(&b, cmp.Commits[i].Commit.Message) {
			n++
		}
	}
	return b.String(), nil
}

// commitsOfRef 取某个 ref（tag / 分支）上的提交记录（旧 -> 新，最多 30 条，含说明正文）。
// 用于没有「上一个版本」可比的首个发布：这样首版的「检查更新」页也能看到
// 实际的提交清单，而不是 GitHub 自动生成的 Full Changelog 链接
func commitsOfRef(ref string) (string, error) {
	var list []struct {
		Commit struct {
			Message string `json:"message"`
		} `json:"commit"`
	}
	if err := ghGetJSON(fmt.Sprintf("https://api.github.com/repos/%s/commits?sha=%s&per_page=30",
		updateRepo, url.PathEscape(ref)), &list); err != nil {
		return "", err
	}
	var b strings.Builder
	n := 0
	for i := len(list) - 1; i >= 0 && n < 30; i-- {
		if writeCommitNote(&b, list[i].Commit.Message) {
			n++
		}
	}
	return b.String(), nil
}

// ---------------- 自更新：服务器上直接完成下载与替换 ----------------

// updStatus: idle -> downloading -> replacing -> restarting -> (进程重启后回到 idle)
func setUpd(status, msg string) {
	updStatusMu.Lock()
	updStatus, updMsg = status, msg
	updStatusMu.Unlock()
}

// setUpdProg 带下载进度的状态写入
func setUpdProg(status, msg string, done, total int64) {
	updStatusMu.Lock()
	updStatus, updMsg = status, msg
	updDone, updTotal = done, total
	updStatusMu.Unlock()
}

func getUpd() (status, msg string, done, total int64) {
	updStatusMu.Lock()
	defer updStatusMu.Unlock()
	return updStatus, updMsg, updDone, updTotal
}

func updCancelled() bool { return atomic.LoadInt32(&updCancel) == 1 }

var errUpdateCancelled = errors.New("更新已取消")

// assetName 依据当前运行平台映射 Release 产物名（与 build.sh 命名一致）
func assetName() string {
	name := "fileserver_" + runtime.GOOS + "_" + runtime.GOARCH
	switch {
	case runtime.GOOS == "windows":
		name += ".exe"
	case runtime.GOARCH == "arm":
		v := goarmVersion()
		if v == "" {
			v = "5" // 手动 go build 未注入时按 Go 工具链默认 GOARM 命名
		}
		name += "v" + v
	}
	return name
}

// goarmBuild 编译时由 build.sh 通过 -ldflags "-X main.goarmBuild=7" 注入。
// 注意：GOARM 不是 runtime 包的公开 API（公开的只有 GOOS/GOARCH/GOROOT），
// 任何平台都无法直接引用 runtime.GOARM，只能走构建期注入。
var goarmBuild string

// goarmVersion 返回编译时注入的 GOARM 版本；仅在 GOARCH=arm 构建时有值，
// 其他架构返回空串（版本接口的 goarm 字段为空即表示不适用，前端不拼接 vN）
func goarmVersion() string {
	return goarmBuild
}

// downloadToFile 流式下载并校验（大小下限 + 可执行文件魔数）。
// onProg 定期上报 (已下载, 总量)；cancelled 返回 true 时中止并删除半成品文件。
func downloadToFile(url, dest string, onProg func(done, total int64), cancelled func() bool) error {
	// 30 分钟总时长上限：5 分钟对慢链路上的大体积二进制偏短，中途必然失败
	client := &http.Client{Timeout: 30 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("无法连接 GitHub: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("下载返回 HTTP %d（产物 %s 可能不存在）", resp.StatusCode, filepath.Base(dest))
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	total := resp.ContentLength // 未知为 -1
	buf := make([]byte, 64*1024)
	var done int64
	lastReport := time.Now()
	abort := func(rerr error) error {
		f.Close()
		os.Remove(dest)
		return rerr
	}
	for {
		if cancelled != nil && cancelled() {
			return abort(errUpdateCancelled)
		}
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if done+int64(n) > maxReleaseBytes {
				return abort(fmt.Errorf("下载超过 %d MB 体积上限，已中止", maxReleaseBytes>>20))
			}
			if _, werr := f.Write(buf[:n]); werr != nil {
				return abort(werr)
			}
			done += int64(n)
			if onProg != nil && time.Since(lastReport) >= 200*time.Millisecond {
				onProg(done, total)
				lastReport = time.Now()
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return abort(rerr)
		}
	}
	closeErr := f.Close()
	if closeErr != nil {
		os.Remove(dest)
		return closeErr
	}
	if onProg != nil {
		onProg(done, total)
	}
	if done < 1<<20 {
		os.Remove(dest)
		return fmt.Errorf("下载内容仅 %d 字节，疑似错误页", done)
	}
	return validateBinary(dest, done)
}

// validateBinary 校验候选二进制：大小下限 + 可执行文件魔数，失败即删除。
// size 是实际收到的字节数：一个 "MZ" 开头的几 KB 小文件也过得了魔数检查，
// 却足以把正在运行的服务覆盖成起不来的垃圾，必须用大小下限再拦一道
func validateBinary(path string, size int64) error {
	if size > 0 && size < 1<<20 {
		os.Remove(path)
		return errors.New("文件过小（不足 1MB），不可能是完整的程序二进制，已取消替换")
	}
	head := make([]byte, 2)
	if hf, err := os.Open(path); err == nil {
		_, _ = io.ReadFull(hf, head)
		hf.Close()
	}
	// ELF (\x7fELF) / PE (MZ) / Mach-O (feedface 系或 \xcf\xfa\xfe\xed)
	if !(bytes.HasPrefix(head, []byte{0x7f, 'E'}) || bytes.Equal(head, []byte("MZ")) ||
		bytes.Equal(head, []byte{0xcf, 0xfa}) || bytes.Equal(head, []byte{0xce, 0xfa})) {
		os.Remove(path)
		return errors.New("文件格式校验失败（需要 ELF/PE/Mach-O 二进制），已取消替换")
	}
	return nil
}

// replaceBinary 原子替换正在运行的二进制
func replaceBinary(src, dst string) error {
	mode := os.FileMode(0o755)
	if info, err := os.Stat(dst); err == nil {
		mode = info.Mode()
	}
	if err := os.Chmod(src, mode); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		// Windows 下运行中的 exe 无法覆盖：旧文件改名让位
		old := dst + ".old"
		_ = os.Remove(old)
		if err := os.Rename(dst, old); err != nil {
			return fmt.Errorf("旧程序改名失败（可能被占用）: %w", err)
		}
		if err := os.Rename(src, dst); err != nil {
			_ = os.Rename(old, dst) // 回滚
			return err
		}
		return nil
	}
	// Linux/macOS：rename 原子替换，运行中的进程继续使用旧 inode，不受影响
	return os.Rename(src, dst)
}

// updAcquire 抢占「同一时刻只有一个更新任务」的名额，返回本次任务的代号。
// 名额必须带代号才能释放（见 updRelease）：光靠 CAS 挡不住陈旧的清零者
func updAcquire() (int64, bool) {
	if !atomic.CompareAndSwapInt32(&updBusy, 0, 1) {
		return 0, false
	}
	return atomic.AddInt64(&updEpoch, 1), true
}

// updRelease 只有当前持有者才能释放名额。
// 此前 updBusy 由两处无条件置 0：runSelfUpdate 返回时的 defer，以及
// scheduleRestart 里那个 1.5 秒后的协程。后者会把期间开始的第二个任务的名额
// 一起抹掉，于是第三个请求可以挤进来 —— 两个任务同时 os.Create(exe+".new")
// 交叉写同一个文件，而 validateBinary 只查体积和魔数，混装了新版本的文件照样
// 通过校验、替换到正在运行的二进制上并被 exec，服务从此起不来且无法自救
func updRelease(epoch int64) {
	if atomic.LoadInt64(&updEpoch) != epoch {
		return
	}
	atomic.StoreInt32(&updBusy, 0)
}

// scheduleRestart 延迟重启：systemd 环境走 systemctl；否则 exec 自身（加载新二进制）。
// epoch 由调用方交接：armed 之后名额归本函数持有，直到确认「没有重启成功」才释放，
// 在途窗口内新任务一律 409，避免与 exec/替换过程叠加
func scheduleRestart(epoch int64) {
	go func() {
		time.Sleep(1500 * time.Millisecond)
		if runtime.GOOS != "windows" {
			if os.Getenv("INVOCATION_ID") != "" { // systemd 服务内
				if err := exec.Command("systemctl", "restart", "fileserver").Run(); err == nil {
					return // restart 会终止本进程，不会走到 return 之后
				}
			}
			if exe, err := os.Executable(); err == nil {
				// rename 替换二进制后 /proc/self/exe 会变成 "… (deleted)"，
				// 原样 exec 必然 ENOENT；剥掉后缀才能指向新文件
				if strings.HasSuffix(exe, " (deleted)") {
					exe = strings.TrimSuffix(exe, " (deleted)")
				}
				// exec 前自己先关监听并刷盘：syscall.Exec 直接换掉进程映像，
				// srv.Shutdown 与 flushSharesOnExit 都不会执行 —— 每次自更新
				// 都会丢掉最多 30 秒尚未落盘的分享访问日志，在途请求也被硬切
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				shutdownServer(ctx)
				cancel()
				flushSharesOnExit()
				// exec 失败必须如实上报：吞掉错误后无条件报「完成」，
				// 实际进程还跑在旧二进制上，用户会被假状态误导
				if errno := syscall.Exec(exe, os.Args, os.Environ()); errno != nil {
					setUpd("error", "重启失败（"+errno.Error()+"），二进制已替换，请手动重启服务进程")
					updRelease(epoch)
					return
				}
				return // exec 成功：进程映像已被替换，无需释放名额
			} else {
				setUpd("error", "重启失败（无法获取程序路径），二进制已替换，请手动重启服务进程")
				updRelease(epoch)
				return
			}
		}
		setUpd("done", "二进制已更新，Windows 请手动重启服务进程")
		// 没有真正重启（Windows/手动路径）：释放忙碌标志，允许再次发起更新
		updRelease(epoch)
	}()
}

// runSelfUpdate 后台执行完整更新流程
// getReleaseByTag 查询指定 tag 的 Release（用于「更新到指定版本」）
func getReleaseByTag(tag string) (*ghRelease, error) {
	var rel ghRelease
	err := ghGetJSON(fmt.Sprintf("https://api.github.com/repos/%s/releases/tags/%s",
		updateRepo, url.PathEscape(tag)), &rel)
	if err != nil {
		return nil, err
	}
	if rel.TagName == "" {
		return nil, errors.New("未找到该版本的 Release: " + tag)
	}
	return &rel, nil
}

// updateHTTPClient 元数据与校验文件的请求都用它；
// 大文件下载另用带 30 分钟总时长上限的专用 client
var updateHTTPClient = &http.Client{Timeout: 60 * time.Second}

// maxReleaseBytes 自更新产物的体积上限：正常资产十几 MB，给足余量到 512MB。
// 没有上限时，一个超大资产（或被重定向到的超大目标）会把二进制所在分区写满，
// 而 .new/.old 落在系统盘上，之后连清理都困难
const maxReleaseBytes = 512 << 20

// minFreeForUpdate 替换前要求目标目录至少还有这么多空闲：产物 + .old 备份 +
// 一点余量，磁盘真的写满时报错也比留下一半截强
const minFreeForUpdate = 128 << 20

// safeTagName GitHub 标签必须只含 URL 路径段安全的字符。
// tag 来自 API 响应（getReleaseByTag 时还来自请求参数），会被原样拼进下载地址，
// 含 / ? # 等即可把下载指向非预期的目标
func safeTagName(s string) bool {
	if s == "" || len(s) > 100 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-', r == '+':
		default:
			return false
		}
	}
	return true
}

// releaseDigestMatches 用同一 Release 的 SHA256SUMS 核对已下载的产物。
// 返回 checked=false 表示该 Release 根本没有 SHA256SUMS（历史版本/手工构建），
// 此时如实告警后继续；有 sums 而对不上则绝不替换
func releaseDigestMatches(tag, asset, path string) (ok bool, checked bool) {
	sumsURL := fmt.Sprintf("https://github.com/%s/releases/download/%s/SHA256SUMS", updateRepo, tag)
	resp, err := updateHTTPClient.Get(sumsURL)
	if err != nil {
		log.Printf("[更新] 取 SHA256SUMS 失败（%v），本次不做完整性校验", err)
		return true, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("[更新] Release %s 没有 SHA256SUMS（HTTP %d），本次不做完整性校验", tag, resp.StatusCode)
		return true, false
	}
	want := ""
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 1<<20))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// 常见格式 "<hex>  <name>"，也容忍 "<hex> *<name>"
		f := strings.Fields(line)
		if len(f) < 2 || !strings.EqualFold(strings.TrimPrefix(f[1], "*"), asset) {
			continue
		}
		want = strings.ToLower(f[0])
		break
	}
	if want == "" {
		log.Printf("[更新] SHA256SUMS 里没有 %s，不做完整性校验", asset)
		return true, false
	}
	hf, err := os.Open(path)
	if err != nil {
		return false, true
	}
	h := sha256.New()
	if _, err := io.Copy(h, hf); err != nil {
		hf.Close()
		return false, true
	}
	hf.Close()
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, want) {
		log.Printf("[更新] %s 摘要不符：期望 %s，实得 %s", asset, want, got)
		return false, true
	}
	log.Printf("[更新] %s 摘要校验通过", asset)
	return true, true
}

func runSelfUpdate(epoch int64, target string) {
	// armed 后名额交给 scheduleRestart：在「二进制已换、进程还没重启」的窗口里
	// 必须继续挡住新任务，否则下一次更新会与即将 exec 的这次叠在一起
	armed := false
	defer func() {
		if !armed {
			updRelease(epoch)
		}
	}()
	atomic.StoreInt32(&updCancel, 0) // 新任务清空取消标志
	setUpdProg("downloading", "查询最新版本…", 0, -1)
	// 指定目标版本时按 tag 精确取 Release，而不是无条件拉最新
	// （此前 target 参数被忽略，无论传什么都更新到最新版）
	if target != "" && !safeTagName(target) {
		setUpd("error", "版本标签不合法")
		return
	}
	var rel *ghRelease
	var err error
	if target != "" {
		rel, err = getReleaseByTag(target)
	} else {
		rel, err = checkLatestRelease(true)
	}
	if err != nil {
		setUpd("error", "查询失败: "+err.Error())
		return
	}
	if updCancelled() {
		setUpd("idle", "已取消更新")
		return
	}
	if !safeTagName(rel.TagName) {
		setUpd("error", "版本标签不合法，已取消")
		return
	}
	if target != "" && rel.TagName != target {
		// API 返回了别的 tag（大小写或跳转），不能拿它去拼下载地址
		setUpd("error", "服务端返回的版本与请求不一致，已取消")
		return
	}
	// 指定版本允许平级重装与回退（旧版本往往才是用户想要的版本），
	// 只有「更新到最新」时才要求版本号必须递增
	if target == "" && !verGreater(rel.TagName, curVersion()) {
		setUpd("idle", "已是最新版本 "+curVersion())
		return
	}
	asset := assetName()
	dlURL := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", updateRepo, rel.TagName, asset)
	exe, err := os.Executable()
	if err != nil {
		setUpd("error", "获取程序路径失败: "+err.Error())
		return
	}
	exe, _ = filepath.Abs(exe)
	// 落盘前先看空间：diskUsage 在整个项目里原本只被 /api/state 调过一次，
	// 从没在写二进制前查过，磁盘满时下载会一路 ENOSPC 并把目录搞脏
	if _, free, _, derr := diskUsage(filepath.Dir(exe)); derr == nil && free < minFreeForUpdate {
		setUpd("error", fmt.Sprintf("目标分区剩余空间不足（%d MB），请先清理后再更新", free>>20))
		return
	}
	tmp := exe + ".new"
	setUpdProg("downloading", "下载 "+asset+" …", 0, -1)
	err = downloadToFile(dlURL, tmp,
		func(done, total int64) { setUpdProg("downloading", "下载 "+asset, done, total) },
		updCancelled)
	if err == errUpdateCancelled {
		setUpd("idle", "已取消更新")
		return
	}
	if err != nil {
		setUpd("error", "下载失败: "+err.Error())
		return
	}
	if updCancelled() {
		_ = os.Remove(tmp)
		setUpd("idle", "已取消更新")
		return
	}
	// 下载完先对摘要：validateBinary 只看体积和魔数，挡不住
	// 「Release 资产被替换」或「中间人交来的另一份可执行文件」
	if ok, _ := releaseDigestMatches(rel.TagName, asset, tmp); !ok {
		_ = os.Remove(tmp)
		setUpd("error", "SHA256SUMS 校验不通过，已取消替换")
		return
	}
	setUpd("replacing", "替换二进制…")
	if err := replaceBinary(tmp, exe); err != nil {
		_ = os.Remove(tmp)
		setUpd("error", "替换失败: "+err.Error())
		return
	}
	setUpd("restarting", "已更新到 "+rel.TagName+"，服务重启中…")
	armed = true
	scheduleRestart(epoch)
}

func selfUpdateJSON() map[string]any {
	s, m, done, total := getUpd()
	return map[string]any{
		"status": s, "message": m,
		"done": done, "total": total,
		"cancelable": s == "downloading",
		"version":    curVersion(), "asset": assetName(),
	}
}

// handleSelfUpdateUpload 手动上传更新包：服务器连不上 GitHub 时的本地替代路径。
// 接收 multipart 的 file 字段 -> 落盘 -> 校验魔数 -> 原子替换 -> 重启。
func handleSelfUpdateUpload(w http.ResponseWriter, r *http.Request) {
	epoch, okUpd := updAcquire()
	if !okUpd {
		s, _, _, _ := getUpd()
		writeJSON(w, http.StatusConflict, map[string]any{"error": "已有更新任务在进行中（" + s + "）"})
		return
	}
	// armed 后名额交给 scheduleRestart；其余路径必须释放，
	// 否则之后所有 selfupdate 请求永久 409
	armed := false
	defer func() {
		if !armed {
			updRelease(epoch)
		}
	}()
	fail := func(code int, msg string) {
		updRelease(epoch)
		setUpd("idle", "")
		writeJSON(w, code, map[string]any{"error": msg})
	}
	exe, err := os.Executable()
	if err != nil {
		fail(500, "获取程序路径失败: "+err.Error())
		return
	}
	exe, _ = filepath.Abs(exe)
	mr, err := r.MultipartReader()
	if err != nil {
		fail(400, "需要 multipart 文件上传")
		return
	}
	setUpd("downloading", "接收上传的更新包…")
	var part io.Reader
	for {
		p, e := mr.NextPart()
		if e == io.EOF {
			break
		}
		if e != nil {
			fail(400, "上传解析失败: "+e.Error())
			return
		}
		if p.FormName() == "file" {
			part = p
			break
		}
	}
	if part == nil {
		fail(400, "缺少名为 file 的文件字段")
		return
	}
	tmp := exe + ".new"
	f, err := os.Create(tmp)
	if err != nil {
		fail(500, "写盘失败: "+err.Error())
		return
	}
	n, copyErr := io.Copy(f, io.LimitReader(part, 256<<20)) // 上限 256MB
	closeErr := f.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(tmp)
		msg := "接收失败"
		if copyErr != nil {
			msg += ": " + copyErr.Error()
		} else {
			msg += ": " + closeErr.Error()
		}
		fail(500, msg)
		return
	}
	if n == 256<<20 {
		_ = os.Remove(tmp)
		fail(400, "文件超过 256MB 上限，请确认上传的是程序二进制而非数据包")
		return
	}
	if err := validateBinary(tmp, n); err != nil {
		updRelease(epoch)
		setUpd("error", "校验失败: "+err.Error())
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	setUpd("replacing", "替换二进制…")
	if err := replaceBinary(tmp, exe); err != nil {
		_ = os.Remove(tmp)
		updRelease(epoch)
		setUpd("error", "替换失败: "+err.Error())
		writeJSON(w, 500, map[string]any{"error": "替换失败: " + err.Error()})
		return
	}
	setUpd("restarting", "二进制已更新，服务重启中…")
	armed = true
	scheduleRestart(epoch)
	writeJSON(w, 200, map[string]any{"started": true})
}
