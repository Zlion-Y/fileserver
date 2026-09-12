// 自建文件服务 —— 单文件 Go 实现（零第三方依赖，可交叉编译为单个可执行文件）
//
// 构建:
//
//	go build -trimpath -ldflags "-s -w" -o fileserver .
//
// 运行:
//
//	./fileserver --port 8080 --dir /data/files
//	./fileserver --port 8080 --dir /data/files --user admin --pass 123456
package main

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"
)

//go:embed public
var publicFS embed.FS

// ---------------- 全局配置 ----------------
var (
	flagPort    int
	flagHost    string
	flagDir     string
	flagDataDir string
	flagUser    string
	flagPass    string
	flagProxy   bool
	flagMaxMB   int64
	flagLog     bool

	cfg   config
	cfgMu sync.Mutex

	shares  = map[string]*Share{}
	shareMu sync.Mutex
)

// 注意：必须是 var 而非 const，否则 -ldflags "-X main.version=..." 注入不会生效
var (
	version   = "1.3.1"
	commit    = "unknown" // 构建时由 -ldflags 注入
	buildTime = "unknown"
	// changelogB64 当前版本更新日志（base64）。CI 构建时把上一 tag 到本 tag 的
	// 提交清单编码后注入：base64 纯 ASCII，规避 -X 对换行/引号/中文的解析问题；
	// 运行期在 versionJSON 内解码。注入后「检查更新」页离线也能展示更新内容
	changelogB64 = ""
)

// builtinChangelog 解码构建时注入的更新日志；空串表示未注入（本地构建/容器）
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

const (
	updateRepo     = "Zlion-Y/fileserver"
	updateCacheTTL = 10 * 60 * 1000 // 检查结果缓存 10 分钟
	updateTimeout  = 6 * time.Second

	// uploadSlackBytes 上传请求整体 body 相对「单文件上限」的余量：
	// 留给 multipart 边界、其它表单字段与多文件场景的开销
	uploadSlackBytes = 8 << 20 // 8MB
)

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

var (
	updCache     ghRelease
	updCheckedAt int64
	updMu        sync.Mutex

	notesCache = map[string]string{} // tag -> Release 说明
	notesMu    sync.Mutex
)

// verNums 把 "v1.2.3" 解析成 [1,2,3]（无法解析的段按 0 处理）
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

// checkLatestRelease 查 GitHub 最新 Release（带缓存；服务端代理，规避浏览器跨域）
func checkLatestRelease(force bool) (*ghRelease, error) {
	updMu.Lock()
	defer updMu.Unlock()
	now := time.Now().UnixMilli()
	if !force && updCheckedAt > 0 && now-updCheckedAt < updateCacheTTL {
		// 返回副本而非 &updCache：调用方在锁外读 TagName/Body/HTMLURL，
		// 直接交出全局指针会与并发 force 查询的 updCache = rel 赋值竞争
		snapshot := updCache
		return &snapshot, nil
	}
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
	updCache = rel
	updCheckedAt = now
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
	defer notesMu.Unlock()
	if v, ok := notesCache[tag]; ok {
		return v, nil
	}
	var rel ghRelease
	if err := ghGetJSON(fmt.Sprintf("https://api.github.com/repos/%s/releases/tags/%s",
		updateRepo, url.PathEscape(tag)), &rel); err != nil {
		return "", err
	}
	notes := enrichNotes(tag, rel.Body)
	notesCache[tag] = notes
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

// enrichNotes 说明缺内容时，用本版本相对上一版本的提交记录补出可读的更新内容
func enrichNotes(tag, body string) string {
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

// commitsBetween 取两个 tag 之间的提交记录（旧 -> 新，最多 30 条）
func commitsBetween(base, head string) (string, error) {
	var cmp ghCompare
	if err := ghGetJSON(fmt.Sprintf("https://api.github.com/repos/%s/compare/%s...%s",
		updateRepo, url.PathEscape(base), url.PathEscape(head)), &cmp); err != nil {
		return "", err
	}
	var b strings.Builder
	n := 0
	for i := len(cmp.Commits) - 1; i >= 0 && n < 30; i-- {
		msg := strings.TrimSpace(strings.SplitN(cmp.Commits[i].Commit.Message, "\n", 2)[0])
		if msg == "" {
			continue
		}
		b.WriteString("- " + msg + "\n")
		n++
	}
	return b.String(), nil
}

// commitsOfRef 取某个 ref（tag / 分支）上的提交记录（旧 -> 新，最多 30 条）。
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
		msg := strings.TrimSpace(strings.SplitN(list[i].Commit.Message, "\n", 2)[0])
		if msg == "" {
			continue
		}
		b.WriteString("- " + msg + "\n")
		n++
	}
	return b.String(), nil
}

// ---------------- 自更新：服务器上直接完成下载与替换 ----------------

// updStatus: idle -> downloading -> replacing -> restarting -> (进程重启后回到 idle)
var (
	updStatusMu sync.Mutex
	updStatus   = "idle"
	updMsg      = ""
	updBusy     int32
	updCancel   int32 // 置 1 请求取消（仅 downloading 阶段有效）
	updDone     int64 // 已下载字节数
	updTotal    int64 // 总字节数（Content-Length；未知为 -1）
)

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
	client := &http.Client{Timeout: 5 * time.Minute}
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

// validateBinary 校验候选二进制：大小下限 + 可执行文件魔数，失败即删除
func validateBinary(path string, size int64) error {
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

// scheduleRestart 延迟重启：systemd 环境走 systemctl；否则 exec 自身（加载新二进制）
func scheduleRestart() {
	go func() {
		time.Sleep(1500 * time.Millisecond)
		if runtime.GOOS != "windows" {
			if os.Getenv("INVOCATION_ID") != "" { // systemd 服务内
				if err := exec.Command("systemctl", "restart", "fileserver").Run(); err == nil {
					return // restart 会终止本进程，不会走到 return 之后
				}
			}
			if exe, err := os.Executable(); err == nil {
				_ = syscall.Exec(exe, os.Args, os.Environ())
			}
		}
		setUpd("done", "二进制已更新，Windows 请手动重启服务进程")
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

func runSelfUpdate(target string) {
	defer atomic.StoreInt32(&updBusy, 0)
	atomic.StoreInt32(&updCancel, 0) // 新任务清空取消标志
	setUpdProg("downloading", "查询最新版本…", 0, -1)
	// 指定目标版本时按 tag 精确取 Release，而不是无条件拉最新
	// （此前 target 参数被忽略，无论传什么都更新到最新版）
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
	// 指定版本允许平级重装与回退（旧版本往往才是用户想要的版本），
	// 只有「更新到最新」时才要求版本号必须递增
	if target == "" && !verGreater(rel.TagName, curVersion()) {
		setUpd("idle", "已是最新版本 "+curVersion())
		return
	}
	asset := assetName()
	url := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", updateRepo, rel.TagName, asset)
	exe, err := os.Executable()
	if err != nil {
		setUpd("error", "获取程序路径失败: "+err.Error())
		return
	}
	exe, _ = filepath.Abs(exe)
	tmp := exe + ".new"
	setUpdProg("downloading", "下载 "+asset+" …", 0, -1)
	err = downloadToFile(url, tmp,
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
	setUpd("replacing", "替换二进制…")
	if err := replaceBinary(tmp, exe); err != nil {
		_ = os.Remove(tmp)
		setUpd("error", "替换失败: "+err.Error())
		return
	}
	setUpd("restarting", "已更新到 "+rel.TagName+"，服务重启中…")
	scheduleRestart()
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
	if !atomic.CompareAndSwapInt32(&updBusy, 0, 1) {
		s, _, _, _ := getUpd()
		writeJSON(w, http.StatusConflict, map[string]any{"error": "已有更新任务在进行中（" + s + "）"})
		return
	}
	fail := func(code int, msg string) {
		atomic.StoreInt32(&updBusy, 0)
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
		atomic.StoreInt32(&updBusy, 0)
		setUpd("error", "校验失败: "+err.Error())
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	setUpd("replacing", "替换二进制…")
	if err := replaceBinary(tmp, exe); err != nil {
		_ = os.Remove(tmp)
		atomic.StoreInt32(&updBusy, 0)
		setUpd("error", "替换失败: "+err.Error())
		writeJSON(w, 500, map[string]any{"error": "替换失败: " + err.Error()})
		return
	}
	setUpd("restarting", "二进制已更新，服务重启中…")
	scheduleRestart()
	writeJSON(w, 200, map[string]any{"started": true})
}

type config struct {
	RootDir      string `json:"rootDir"`
	AuthPassHash string `json:"authPassHash,omitempty"` // 网页「安全与会话」修改后的管理密码哈希（优先于 -pass/AUTH_PASS）
	TidyEnabled  *bool  `json:"tidyEnabled,omitempty"`  // nil = 默认开启自动清理
	TidyHours    int    `json:"tidyHours,omitempty"`    // >0 时优先于 TIDY_HOURS 环境变量
}

// ShareLog 分享访问日志（每条分享最多保留 50 条）
type ShareLog struct {
	At   int64  `json:"at"`
	IP   string `json:"ip"`
	UA   string `json:"ua"`
	OK   bool   `json:"ok"`
	Note string `json:"note,omitempty"` // 失败原因：过期 / 次数用完 / 密码错误 / 文件不存在
}

// Share 分享记录
type Share struct {
	Token          string `json:"token"`
	Name           string `json:"name"`
	RelPath        string `json:"relPath"`
	AbsPath        string `json:"absPath"`
	Size           int64  `json:"size"`
	MaxDownloads   int    `json:"maxDownloads"`
	Downloads      int    `json:"downloads"`
	CreatedAt      int64  `json:"createdAt"`
	ExpiresAt      int64  `json:"expiresAt"` // 0 = 永久
	Scheme         string `json:"scheme"`
	Host           string `json:"host"`
	LastDownloadAt int64  `json:"lastDownloadAt,omitempty"`
	// PasswordEnc AES-GCM(主密钥) 加密后的分享密码，管理端回显时解密；
	// 不再把明文直接写进 shares.json（该文件 0644，备份/volume 泄露会连带交出所有分享密码）
	PasswordEnc    string     `json:"passwordEnc,omitempty"`
	LegacyPassword string     `json:"password,omitempty"`     // 兼容旧版本遗留明文，加载时迁移后清空，不再落盘
	Password       string     `json:"-"`                      // 仅内存字段：管理端回显用，绝不持久化
	PasswordHash   string     `json:"passwordHash,omitempty"` // PBKDF2 口令哈希，空 = 无密码
	Mode           string     `json:"mode,omitempty"`         // "" = 直链下载（兼容旧记录），"page" = 确认页
	Alias          string     `json:"alias,omitempty"`        // 自定义链接别名：/s/<alias>，对外发布更好看
	Hotlink        bool       `json:"hotlink,omitempty"`      // 防盗链：带 Referer 且来源域名非本站时拒绝
	Log            []ShareLog `json:"log,omitempty"`
}

type sharePublic struct {
	Share
	Alive    bool   `json:"alive"`
	HasPw    bool   `json:"hasPw"`
	Password string `json:"password,omitempty"` // 解密后的明文，仅 /api/shares 等管理端接口返回
}

func envStr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
func envBool(k string, def bool) bool {
	if v := os.Getenv(k); v != "" {
		return v == "1" || strings.EqualFold(v, "true")
	}
	return def
}

// ---------------- 持久化 ----------------
func dataPath(name string) string {
	os.MkdirAll(flagDataDir, 0o755)
	return filepath.Join(flagDataDir, name)
}
func loadConfig() {
	b, err := os.ReadFile(dataPath("config.json"))
	if err == nil {
		_ = json.Unmarshal(b, &cfg)
	}
}
func saveConfig() {
	// 全程持 cfgMu：marshal 和写盘都在锁内完成。此前 Marshal 无锁读 cfg，
	// 与 POST /api/config 等写操作并发构成数据竞争（go test -race 可复现）；
	// 若写盘放在锁外，两个并发保存者还会互相覆盖（旧快照后写，丢更新）。
	cfgMu.Lock()
	b, _ := json.MarshalIndent(cfg, "", "  ")
	// 0600：config.json 里有管理密码哈希，任何备份/协作者都不应默认可读
	tmp := dataPath("config.json") + ".tmp"
	_ = os.WriteFile(tmp, b, 0o600)
	_ = os.Rename(tmp, dataPath("config.json"))
	cfgMu.Unlock()
}
func loadShares() {
	b, err := os.ReadFile(dataPath("shares.json"))
	if err != nil {
		return
	}
	var m map[string]*Share
	if json.Unmarshal(b, &m) == nil && m != nil {
		// 手工编辑/损坏的 shares.json 可能出现 "token": null，
		// 任何后续遍历（publicOne/runTidy/moveShareSync）解引用都会 panic，这里直接剔除
		for k, s := range m {
			if s == nil {
				delete(m, k)
			}
		}
		shares = m
	}
	// 迁移：把 v1.0.15 及以前遗留的明文密码转成加密存储，并按需解密回内存
	migrated := false
	for _, s := range shares {
		if s == nil {
			continue
		}
		if s.PasswordEnc != "" {
			s.Password, _ = decryptPw(s.PasswordEnc)
			continue
		}
		if s.LegacyPassword != "" {
			if enc, err := encryptPw(s.LegacyPassword); err == nil {
				s.PasswordEnc = enc
				s.Password = s.LegacyPassword
				s.LegacyPassword = ""
				migrated = true
			} else {
				log.Printf("[安全] 迁移旧明文分享密码失败（%s）: %v", s.Token, err)
			}
		}
	}
	if migrated {
		saveShares()
		log.Printf("[安全] 已将历史分享密码从明文迁移为加密存储")
	}
}
func saveShares() {
	tmp := dataPath("shares.json") + ".tmp"
	// 全程持锁：如果在 Marshal 之后才释放锁又重新取快照，并发修改会被后写者覆盖丢失。
	// 注意所有调用点都必须先 Unlock 才能调用本函数（Go 互斥锁不可重入）
	shareMu.Lock()
	b, _ := json.MarshalIndent(shares, "", "  ")
	// 0600：shares.json 含加密后的分享密码与访问日志，不应默认全局可读
	_ = os.WriteFile(tmp, b, 0o600)
	_ = os.Rename(tmp, dataPath("shares.json"))
	shareMu.Unlock()
}

// ---------------- 工具 ----------------
func writeJSON(w http.ResponseWriter, code int, v any) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write(b)
}
func getRoot() (string, error) {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	if cfg.RootDir == "" {
		return "", errors.New("尚未设置文件目录")
	}
	abs, _ := filepath.Abs(cfg.RootDir)
	if st, err := os.Stat(abs); err != nil || !st.IsDir() {
		return "", errors.New("目录不存在")
	}
	return abs, nil
}
func safeJoin(root, rel string) (string, error) {
	clean := strings.TrimPrefix(filepath.FromSlash(rel), string(filepath.Separator))
	rootAbs, _ := filepath.Abs(root)
	target, _ := filepath.Abs(filepath.Join(rootAbs, clean))
	if target != rootAbs && !strings.HasPrefix(target, rootAbs+string(filepath.Separator)) {
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
		// 目标不存在或无法解析：后续 os.Stat/os.Create 自会失败，无需在此拦截
		return true
	}
	if tReal != rootReal && !strings.HasPrefix(tReal, rootReal+string(filepath.Separator)) {
		return false
	}
	return true
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
	sep := string(filepath.Separator)
	p := target
	for i := 0; i < 256; i++ {
		if _, err := os.Lstat(p); err == nil {
			real, err := filepath.EvalSymlinks(p)
			if err != nil {
				return false // 悬空链接等无法解析的情况：安全优先，拒绝
			}
			return real == rootReal || strings.HasPrefix(real, rootReal+sep)
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
	// 旁挂元数据：记录原始相对路径，供「恢复」用；失败不阻断删除
	rel := filepath.ToSlash(strings.TrimPrefix(strings.TrimPrefix(target, root), string(filepath.Separator)))
	meta, _ := json.Marshal(map[string]any{"orig": rel, "at": time.Now().UnixMilli()})
	_ = os.WriteFile(filepath.Join(tdir, entry+".meta.json"), meta, 0o600)
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
		e := trashEntry{Name: name, IsDir: it.IsDir(), Deleted: info.ModTime().UnixMilli()}
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
	_ = os.MkdirAll(filepath.Dir(dst), 0o755)
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
func newToken() string {
	b := make([]byte, 9)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// normalizeAlias 归一化并校验分享别名：字母/数字/中划线/下划线/Unicode 字母（中文可），
// 1~40 个字符；返回空串表示不合法。别名进 URL 路径段，不允许空格与分隔符类字符。
func normalizeAlias(a string) string {
	a = strings.TrimSpace(a)
	if a == "" || len([]rune(a)) > 40 {
		return ""
	}
	for _, r := range a {
		switch {
		case r == '-' || r == '_':
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case unicode.IsLetter(r): // 中文等 Unicode 字母
		default:
			return ""
		}
	}
	return a
}

// aliasTaken 别名是否已被占用（等于任何现有 token，或等于其他分享的别名）。
// 别名在 /s/<x> 里优先于 token 匹配，因此不允许与任何 token 重合造成遮蔽。
func aliasTaken(alias, exceptToken string) bool {
	shareMu.Lock()
	defer shareMu.Unlock()
	for tok, s := range shares {
		if tok == alias && tok != exceptToken {
			return true
		}
		if tok != exceptToken && s != nil && s.Alias == alias {
			return true
		}
	}
	return false
}
func aliveShare(s *Share) bool {
	if s == nil {
		return false
	}
	if s.ExpiresAt > 0 && time.Now().UnixMilli() > s.ExpiresAt {
		return false
	}
	if s.MaxDownloads > 0 && s.Downloads >= s.MaxDownloads {
		return false
	}
	return true
}

// 对外输出时抹掉服务器绝对路径、密码哈希与访问日志，避免泄露；
// 明文密码单独解密回显（Password 在 Share 上是 json:"-"，必须在外层字段显式输出）
func publicOne(s *Share) sharePublic {
	c := *s
	c.AbsPath = ""
	c.PasswordHash = ""
	c.LegacyPassword = ""
	c.Log = nil
	pw := c.Password
	if pw == "" && c.PasswordEnc != "" {
		pw, _ = decryptPw(c.PasswordEnc)
	}
	c.Password = ""
	return sharePublic{Share: c, Alive: aliveShare(s), HasPw: s.PasswordHash != "", Password: pw}
}

// setSharePassword 统一写入分享密码：密文明文双份（明文仅在内存） + PBKDF2 哈希
func setSharePassword(s *Share, pw string) {
	s.Password = pw
	s.PasswordHash = hashSharePw(pw)
	if enc, err := encryptPw(pw); err == nil {
		s.PasswordEnc = enc
		s.LegacyPassword = ""
	} else {
		log.Printf("[安全] 分享密码加密失败，本次不持久化明文：%v", err)
	}
}

// clearSharePassword 清除分享密码保护
func clearSharePassword(s *Share) {
	s.Password = ""
	s.PasswordEnc = ""
	s.LegacyPassword = ""
	s.PasswordHash = ""
}

/* ---------------- 口令哈希：PBKDF2-HMAC-SHA256 ---------------- */
//
// SHA-256 单次哈希太快，shares.json / config.json 一旦泄露（备份、Docker volume、
// 误暴露的目录）可被高速字典爆破。改用 PBKDF2 加随机盐与高迭代次数。
// 标准库没有 crypto/pbkdf2（Go 1.23 才加入），这里用 crypto/hmac 自行实现，
// 保持「零第三方依赖」的前提。

const (
	pbkdf2Prefix = "pbkdf2$"
	authIter     = 100000 // 管理端密码：登录频率极低，可以用较高迭代
	shareIter    = 50000  // 分享密码：每次下载都要校验，路由器等弱设备上适度下调
	// 各命名空间前缀，避免管理密码与分享密码的存储串可互换
	nsAuth  = "fs-auth:"
	nsShare = "fs-pw:"
)

// pbkdf2Key 标准 PBKDF2(HMAC-SHA256) 实现
func pbkdf2Key(pw, salt []byte, iter, keyLen int) []byte {
	hLen := sha256.Size
	numBlocks := (keyLen + hLen - 1) / hLen
	buf := make([]byte, 0, numBlocks*hLen)
	mac := hmac.New(sha256.New, pw) // 外层复用 pool 语义，长度 <64 的密码不会被补齐影响结果
	for block := 1; block <= numBlocks; block++ {
		mac.Reset()
		ctr := make([]byte, 4)
		binary.BigEndian.PutUint32(ctr, uint32(block))
		mac.Write(salt)
		mac.Write(ctr)
		u := mac.Sum(nil)
		t := make([]byte, hLen)
		copy(t, u)
		for i := 1; i < iter; i++ {
			mac.Reset()
			mac.Write(u)
			u = mac.Sum(nil)
			for j := 0; j < hLen; j++ {
				t[j] ^= u[j]
			}
		}
		buf = append(buf, t...)
	}
	return buf[:keyLen]
}

// newPwHash 生成存储串：pbkdf2$迭代次数$saltHex$keyHex
func newPwHash(ns, pw string, iter int) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return ""
	}
	key := pbkdf2Key([]byte(ns+pw), salt, iter, 32)
	return fmt.Sprintf("%s%d$%x$%x", pbkdf2Prefix, iter, salt, key)
}

// verifyPwHash 校验口令；第二个返回值表示记录仍是旧的「单次 sha256」格式（应升级）
func verifyPwHash(ns, pw, rec string) (bool, bool) {
	if strings.HasPrefix(rec, pbkdf2Prefix) {
		parts := strings.Split(rec, "$")
		if len(parts) != 4 {
			return false, false
		}
		iter, err := strconv.Atoi(parts[1])
		if err != nil {
			return false, false
		}
		salt, err1 := hex.DecodeString(parts[2])
		want, err2 := hex.DecodeString(parts[3])
		if err1 != nil || err2 != nil || iter <= 0 {
			return false, false
		}
		got := pbkdf2Key([]byte(ns+pw), salt, iter, len(want))
		return subtle.ConstantTimeCompare(got, want) == 1, false
	}
	// 旧记录：sha256(ns+pw)，升级前必须继续校验通过，否则用户会被锁在门外
	sum := sha256.Sum256([]byte(ns + pw))
	return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(rec)) == 1, true
}

// hashSharePw 分享访问密码的存储串
func hashSharePw(pw string) string { return newPwHash(nsShare, pw, shareIter) }

// hashAuthPw 管理端密码的存储串（网页修改后持久化到 config.json）
func hashAuthPw(pw string) string { return newPwHash(nsAuth, pw, authIter) }

// checkPass 校验管理端密码：网页改过密（config.json 有哈希）则比对哈希，否则比对启动时的 -pass/AUTH_PASS
func checkPass(pw string) bool {
	h := authRecord()
	if h != "" {
		ok, legacy := verifyPwHash(nsAuth, pw, h)
		if ok && legacy {
			// 旧格式哈希校验通过 → 静默升级为 PBKDF2，用户无感知
			if up := hashAuthPw(pw); up != "" {
				cfgMu.Lock()
				cfg.AuthPassHash = up
				cfgMu.Unlock()
				saveConfig()
				log.Printf("[安全] 管理密码哈希已升级为 PBKDF2(%d 轮)", authIter)
			}
		}
		return ok
	}
	// 未通过网页改过密码时仍用启动参数里的明文：直接比较明文会泄漏长度
	// （ConstantTimeCompare 长度不等立即返回），故两侧都先定长哈希再比较
	a := sha256.Sum256([]byte(nsAuth + pw))
	b := sha256.Sum256([]byte(nsAuth + flagPass))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// authRecord 读取当前生效的管理密码哈希
func authRecord() string {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	return cfg.AuthPassHash
}

/* ---------------- 分享密码的可恢复加密存储 ---------------- */
//
// 管理端要能回显已设置的密码，就必须存可解密形式；但明文写进 shares.json（0644）
// 意味着任何备份泄露 / volume 配置失误都会直接交出全部分享密码。
// 折中：AES-GCM 加密后入库，密钥独立于数据文件存放。

const masterKeyFile = ".masterkey"

var (
	masterKeyOnce sync.Once
	masterKeyVal  []byte
	masterKeyErr  error
)

// pwMasterKey 返回分享密码加密主密钥：优先 FS_MASTER_KEY 环境变量，
// 否则在 data 目录维护一个 0600 的随机密钥文件
func pwMasterKey() ([]byte, error) {
	masterKeyOnce.Do(func() {
		masterKeyVal, masterKeyErr = loadOrCreateMasterKey()
	})
	return masterKeyVal, masterKeyErr
}

func loadOrCreateMasterKey() ([]byte, error) {
	if v := os.Getenv("FS_MASTER_KEY"); v != "" {
		if k, err := hex.DecodeString(v); err == nil && len(k) == 32 {
			return k, nil
		}
		sum := sha256.Sum256([]byte(v))
		return sum[:], nil
	}
	p := dataPath(masterKeyFile)
	if b, err := os.ReadFile(p); err == nil {
		if k, err := hex.DecodeString(strings.TrimSpace(string(b))); err == nil && len(k) == 32 {
			return k, nil
		}
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, []byte(hex.EncodeToString(k)), 0o600); err != nil {
		return nil, fmt.Errorf("无法写入主密钥文件 %s: %w", p, err)
	}
	log.Printf("[安全] 已生成分享密码加密主密钥 %s（0600），迁移服务器时请一并保留，否则已保存的分享密码将无法回显", p)
	return k, nil
}

// encryptPw AES-GCM 加密分享密码
func encryptPw(plain string) (string, error) {
	k, err := pwMasterKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(append(nonce, ct...)), nil
}

// decryptPw 解密分享密码（密钥缺失或密文损坏时返回空串）
func decryptPw(enc string) (string, error) {
	if enc == "" {
		return "", nil
	}
	k, err := pwMasterKey()
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("密文长度不足")
	}
	pt, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}
func clientScheme(r *http.Request) string {
	if flagProxy {
		if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
			return strings.TrimSpace(strings.Split(p, ",")[0])
		}
	}
	return "http"
}
func clientHost(r *http.Request) string {
	if flagProxy {
		if h := r.Header.Get("X-Forwarded-Host"); h != "" {
			return strings.TrimSpace(strings.Split(h, ",")[0])
		}
	}
	return r.Host
}

// ---------------- 认证 ----------------

// ---------- 防爆破：失败超限封禁 IP ----------
type authAttempt struct {
	count        int
	windowStart  int64
	blockedUntil int64
}

var (
	authFails  = map[string]*authAttempt{}
	authFailMu sync.Mutex
)

const (
	failWindowMs  = 5 * 60 * 1000  // 统计窗口：5 分钟
	failMaxTries  = 10             // 窗口内最多失败次数
	banDurationMs = 15 * 60 * 1000 // 封禁时长：15 分钟
)

// clientIP 取真实来源 IP（反代模式下优先 X-Forwarded-For）
func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = h
	}
	// X-Forwarded-For 可被任意客户端伪造。仅当直连来源本身是环回或内网地址时
	// （即确实处在反向代理之后）才采信，否则端口直接暴露在公网时
	// 伪造 XFF 就能绕过防爆破并污染访问日志。
	if flagProxy && isTrustedProxyPeer(host) {
		if h := r.Header.Get("X-Forwarded-For"); h != "" {
			return strings.TrimSpace(strings.Split(h, ",")[0])
		}
	}
	return host
}

// isTrustedProxyPeer 判断直连来源是否可信（环回 / 私有地址段 / 本机链路地址）
func isTrustedProxyPeer(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

// banRemaining 返回剩余封禁毫秒数，>0 表示仍在封禁中；顺带清理过期记录
func banRemaining(ip string) int64 {
	authFailMu.Lock()
	defer authFailMu.Unlock()
	now := time.Now().UnixMilli()
	a, ok := authFails[ip]
	if !ok {
		return 0
	}
	if a.blockedUntil > now {
		return a.blockedUntil - now
	}
	if (a.blockedUntil > 0 && a.blockedUntil <= now) || now-a.windowStart > failWindowMs {
		delete(authFails, ip)
	}
	return 0
}

func recordAuthFail(ip string) {
	authFailMu.Lock()
	defer authFailMu.Unlock()
	now := time.Now().UnixMilli()
	a, ok := authFails[ip]
	if !ok || (a.blockedUntil > 0 && a.blockedUntil <= now) || now-a.windowStart > failWindowMs {
		a = &authAttempt{windowStart: now}
		authFails[ip] = a
	}
	a.count++
	if a.count >= failMaxTries {
		a.blockedUntil = now + banDurationMs
		log.Printf("[防爆破] IP %s 认证失败 %d 次，封禁 15 分钟", ip, a.count)
	}
}

// startBanGC 定期清理过期记录，防止 map 无限增长
func startBanGC() {
	go func() {
		for range time.Tick(10 * time.Minute) {
			authFailMu.Lock()
			now := time.Now().UnixMilli()
			for ip, a := range authFails {
				if a.blockedUntil <= now && now-a.windowStart > failWindowMs {
					delete(authFails, ip)
				}
			}
			authFailMu.Unlock()
			// 分享密码失败记录同样需要 GC：key 是 token|ip，
			// 扫过一遍就再不访问的链接会把记录永久留在内存里
			sharePwMu.Lock()
			for k, f := range sharePwFails {
				if f.blockedUntil <= now && now-f.firstAt > sharePwWindowMs {
					delete(sharePwFails, k)
				}
			}
			sharePwMu.Unlock()
			// 下载授权 ticket 同样需要回收，否则长期运行会无限堆积
			gcDlTickets()
		}
	}()
}

// ---------------- 会话（登录页 + Cookie）----------------

type sessInfo struct {
	User      string `json:"user"`
	IP        string `json:"ip,omitempty"` // 登录时来源 IP
	CreatedAt int64  `json:"createdAt"`
	ExpiresAt int64  `json:"expiresAt"`
}

var (
	sessMu   sync.Mutex
	sessions = map[string]*sessInfo{}
)

const sessionCookie = "fs_session"

func sessionTTL() time.Duration {
	return time.Duration(envInt("SESSION_DAYS", 7)) * 24 * time.Hour
}

func loadSessions() {
	b, err := os.ReadFile(dataPath("sessions.json"))
	if err != nil {
		return
	}
	var m map[string]*sessInfo
	if json.Unmarshal(b, &m) == nil && m != nil {
		sessions = m
	}
	// 清掉已过期的历史会话
	now := time.Now().UnixMilli()
	sessMu.Lock()
	for k, s := range sessions {
		if s.ExpiresAt > 0 && s.ExpiresAt < now {
			delete(sessions, k)
		}
	}
	sessMu.Unlock()
}

func saveSessions() {
	// 序列化与写盘必须都在锁内：若写盘在锁外，并发新会话时后完成的
	// 旧快照会覆盖先落盘的新数据（与 saveShares 同类问题）
	sessMu.Lock()
	b, _ := json.MarshalIndent(sessions, "", "  ")
	tmp := dataPath("sessions.json") + ".tmp"
	_ = os.WriteFile(tmp, b, 0o600)
	_ = os.Rename(tmp, dataPath("sessions.json"))
	sessMu.Unlock()
}

func newSession(user, ip string) (token string, expMs int64) {
	expMs = time.Now().Add(sessionTTL()).UnixMilli()
	token = newToken() + newToken() // 36 字符，加大熵
	sessMu.Lock()
	sessions[token] = &sessInfo{User: user, IP: ip, CreatedAt: time.Now().UnixMilli(), ExpiresAt: expMs}
	sessMu.Unlock()
	saveSessions()
	return token, expMs
}

func validSession(token string) bool {
	sessMu.Lock()
	defer sessMu.Unlock()
	s, ok := sessions[token]
	if !ok {
		return false
	}
	if s.ExpiresAt > 0 && s.ExpiresAt < time.Now().UnixMilli() {
		delete(sessions, token)
		return false
	}
	return true
}

func delSession(token string) {
	sessMu.Lock()
	delete(sessions, token)
	sessMu.Unlock()
	saveSessions()
}

func checkAuth(w http.ResponseWriter, r *http.Request) bool {
	if flagUser == "" {
		return true
	}
	p := r.URL.Path
	// WebDAV：必须鉴权（Basic 认证原生兼容各类客户端），失败时返回
	// WWW-Authenticate 让客户端弹密码框（浏览器路径不带此头，由前端跳登录页）
	if strings.HasPrefix(p, "/dav") {
		if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" && validSession(c.Value) {
			return true
		}
		u, pw, hasBasic := r.BasicAuth()
		if hasBasic &&
			subtle.ConstantTimeCompare([]byte(u), []byte(flagUser)) == 1 &&
			checkPass(pw) {
			return true
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="fileserver", charset="UTF-8"`)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "WebDAV 需要登录（用户名/密码同管理端）"})
		return false
	}
	// 分享链接、健康检查免密；登录流程自身免密；静态页面公开（数据全部走 API，页面本身无敏感内容）
	if strings.HasPrefix(p, "/s/") || p == "/healthz" ||
		p == "/login" || p == "/api/login" || p == "/api/logout" ||
		!strings.HasPrefix(p, "/api/") {
		return true
	}
	ip := clientIP(r)
	if ms := banRemaining(ip); ms > 0 {
		w.Header().Set("Retry-After", strconv.FormatInt(ms/1000+1, 10))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error": fmt.Sprintf("失败次数过多，该 IP 已被临时封禁，请 %d 分钟后再试", ms/60000+1),
		})
		return false
	}
	// 1) Cookie 会话
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" && validSession(c.Value) {
		return true
	}
	// 2) Basic 认证兼容（curl / 脚本场景）
	u, pw, hasBasic := r.BasicAuth()
	if hasBasic &&
		subtle.ConstantTimeCompare([]byte(u), []byte(flagUser)) == 1 &&
		checkPass(pw) {
		return true
	}
	// 只有「带了凭据但凭据错误」才计失败，纯未登录（浏览器首次进入）不计，避免误封访客
	if hasBasic {
		recordAuthFail(ip)
	}
	// 不带 WWW-Authenticate：浏览器不弹认证框，由前端跳转登录页
	writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "未登录或会话已过期", "code": "AUTH"})
	return false
}

// ---------------- 下载授权 ticket（区分「真续传」与「伪造 Range」） ----------------

const (
	dlTicketCookie = "fs_dl"       // Cookie 名（Path 按 /s/<token> 精确限定，互不干扰）
	dlTicketTTL    = 6 * time.Hour // ticket 有效期：够长时间断点续传，又不至于永久有效
)

type dlTicketRec struct {
	Token string
	Exp   int64
	// Served 本 ticket 至今已实际下发的字节数。
	// 用来区分「上一次传输确实没传完」与「已经完整传过一次」：
	// 没有它的话，一次正常下载拿到 ticket 之后，反复带 Range: bytes=1-
	// 每次都能取到接近完整的文件而永不计数（实测可复现），maxDownloads 形同虚设。
	Served int64
}

var (
	dlTicketMu sync.Mutex
	dlTickets  = map[string]dlTicketRec{}
)

// newDlTicket 签发随机 ticket 并绑定分享 token
func newDlTicket(token string) string {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	ticket := hex.EncodeToString(buf)
	dlTicketMu.Lock()
	dlTickets[ticket] = dlTicketRec{Token: token, Exp: time.Now().Add(dlTicketTTL).UnixMilli()}
	dlTicketMu.Unlock()
	return ticket
}

// rangeStartPositive 判断请求是否为「续传片段」：Range 头存在且起始字节 > 0
func rangeStartPositive(r *http.Request) bool {
	rg := r.Header.Get("Range")
	if rg == "" {
		return false
	}
	rg = strings.TrimPrefix(rg, "bytes=")
	parts := strings.Split(rg, "-")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		return false
	}
	start, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
	return err == nil && start > 0
}

// condRequestNotModified 判断条件请求是否「真的」会命中 304。
// 与 http.ServeContent 的判定保持一致：本服务不下发 ETag，因此 If-None-Match
// 只有 `*` 才可能命中；If-Modified-Since 需要文件确实未被修改（秒级比较）。
//
// 旧实现只要请求头里出现这两个字段就一律免计次，于是任何人加一个
// `If-Modified-Since: Thu, 01 Jan 1970 00:00:00 GMT` 就能带着完整文件响应
// 反复下载而不消耗 maxDownloads（实测可复现）。
func condRequestNotModified(r *http.Request, modtime time.Time) bool {
	ims := r.Header.Get("If-Modified-Since")
	inm := r.Header.Get("If-None-Match")
	if ims == "" && inm == "" {
		return false
	}
	if inm != "" {
		return strings.TrimSpace(inm) == "*"
	}
	t, err := http.ParseTime(ims)
	if err != nil {
		return false
	}
	return !modtime.Truncate(time.Second).After(t)
}

// dlTicketOf 取本次请求携带的下载授权 ticket（无则空串）
func dlTicketOf(r *http.Request) string {
	c, err := r.Cookie(dlTicketCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

// dlTicketServed 某 ticket 已下发的字节数
func dlTicketServed(ticket string) int64 {
	if ticket == "" {
		return 0
	}
	dlTicketMu.Lock()
	defer dlTicketMu.Unlock()
	return dlTickets[ticket].Served
}

// dlTicketAddServed 累加某 ticket 已下发的字节数
func dlTicketAddServed(ticket string, n int64) {
	if ticket == "" || n <= 0 {
		return
	}
	dlTicketMu.Lock()
	if rec, ok := dlTickets[ticket]; ok {
		rec.Served += n
		dlTickets[ticket] = rec
	}
	dlTicketMu.Unlock()
}

// countingWriter 统计一次响应实际写出的字节数（累加到 ticket 的 Served）
type countingWriter struct {
	http.ResponseWriter
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.ResponseWriter.Write(p)
	c.n += int64(n)
	return n, err
}

// Flush 透传，保证流式响应（大文件/zip 打包）不被缓冲卡住
func (c *countingWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// dlTicketValid 读取请求里的下载授权 Cookie，校验其是否有效且属于该分享
func dlTicketValid(r *http.Request, token string) bool {
	c, err := r.Cookie(dlTicketCookie)
	if err != nil || c.Value == "" {
		return false
	}
	dlTicketMu.Lock()
	rec, ok := dlTickets[c.Value]
	dlTicketMu.Unlock()
	if !ok || rec.Token != token {
		return false
	}
	return time.Now().UnixMilli() < rec.Exp
}

// setDlTicketCookie 首次计数下载后下发 ticket，后续 Range 续传凭此免计次；
// 返回本次签发的 ticket（空串表示失败），供调用方把已下发字节数记到它头上
func setDlTicketCookie(w http.ResponseWriter, token string) string {
	ticket := newDlTicket(token)
	if ticket == "" {
		return ""
	}
	http.SetCookie(w, &http.Cookie{
		Name:     dlTicketCookie,
		Value:    ticket,
		Path:     "/s/" + token, // 精确作用域：不带入其他接口，也不与其他分享冲突
		MaxAge:   int(dlTicketTTL / time.Second),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return ticket
}

// gcDlTickets 回收过期 ticket（由 startBanGC 定期调用）
func gcDlTickets() {
	now := time.Now().UnixMilli()
	dlTicketMu.Lock()
	for k, rec := range dlTickets {
		if now >= rec.Exp {
			delete(dlTickets, k)
		}
	}
	dlTicketMu.Unlock()
}

// ---------------- 下载 ----------------
// 计次判定在调用方（handleShareGet）发送前完成；这里只负责流式发送文件

// contentDisposition 构造 RFC 5987 的 Content-Disposition 值。
// 注意 filename* 的 ext-value 只允许百分号编码，不能用 url.QueryEscape ——
// 它会把空格编码成 '+'，浏览器保存文件时 '+' 会被原样保留（"a b.txt" → "a+b.txt"）。
func contentDisposition(kind, name string) string {
	var b strings.Builder
	if kind == "inline" {
		b.WriteString("inline; filename*=UTF-8''")
	} else {
		b.WriteString("attachment; filename*=UTF-8''")
	}
	for _, r := range []byte(name) {
		// RFC 5987 attr-char + UTF-8 明文字节直接放行，其余逐字节百分号编码
		if r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' ||
			strings.IndexByte("-_.!~*'()", r) >= 0 {
			b.WriteByte(r)
		} else {
			fmt.Fprintf(&b, "%%%02X", r)
		}
	}
	return b.String()
}

func serveDownload(w http.ResponseWriter, r *http.Request, filePath, name string) {
	f, err := os.Open(filePath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Disposition", contentDisposition("attachment", name))
	// 禁止缓存：同一链接再次下载必须命中服务器，否则浏览器用本地缓存副本
	// 保存「新下载」，既绕过计数也绕过次数限制
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, name, st.ModTime(), f)
}

// serveInline 内联返回文件（浏览器直接显示/播放，而非强制下载）：
// 分享链接的媒体预览用。Content-Type 按扩展名给出，Range 拖动由 ServeContent 处理。
// 注意：仅限 mediaKindOf 白名单内的类型调用（SVG 被排除——同源内联渲染 SVG
// 会执行其中脚本，等于存储型 XSS）
func serveInline(w http.ResponseWriter, r *http.Request, filePath, name string) {
	f, err := os.Open(filePath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		http.NotFound(w, r)
		return
	}
	ct := "application/octet-stream"
	if t := mime.TypeByExtension(strings.ToLower(filepath.Ext(name))); t != "" {
		ct = t
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition", contentDisposition("inline", name))
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, name, st.ModTime(), f)
}

// mediaKindOf 判断文件名是否为浏览器可直接渲染的媒体类型（返回 img/vid/aud，非媒体返回 ""）。
// 刻意收紧：只效入浏览器原生支持目能安全内联的扩展名（SVG/HEIC/AVI/WMV 等不在内）
func mediaKindOf(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico":
		return "img"
	case ".mp4", ".webm", ".mov", ".m4v", ".mkv":
		return "vid"
	case ".mp3", ".m4a", ".aac", ".flac", ".wav", ".ogg", ".opus":
		return "aud"
	}
	return ""
}

// ---------------- 路由 ----------------
func handler(w http.ResponseWriter, r *http.Request) {
	if !checkAuth(w, r) {
		return
	}
	if flagLog {
		defer func() {
			log.Printf("%s %s %s", r.Method, r.URL.Path, r.RemoteAddr)
		}()
	}
	p := r.URL.Path
	// 上传大小限制：只作用于上传接口（不影响登录、自更新等接口的正常请求），
	// 并用 MaxBytesReader 兜底 —— 仅靠 ContentLength 判断时，
	// chunked 编码（ContentLength == -1）会让限制完全失效。
	if r.Method == http.MethodPost && flagMaxMB > 0 && p == "/api/upload" {
		limit := flagMaxMB*1024*1024 + uploadSlackBytes
		if r.ContentLength > limit {
			writeJSON(w, http.StatusRequestEntityTooLarge,
				map[string]any{"error": fmt.Sprintf("上传内容超过 %dMB 限制", flagMaxMB)})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
	}
	// 安全响应头：防止 MIME 嗅探、点击劫持、外链泄露 referrer
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	switch {
	case p == "/healthz":
		writeJSON(w, 200, map[string]any{"ok": true, "ts": time.Now().UnixMilli()})
	case strings.HasPrefix(p, "/api/"):
		handleAPI(w, r)
	case strings.HasPrefix(p, "/s/"):
		handleShareGet(w, r)
	case p == "/dav" || strings.HasPrefix(p, "/dav/"):
		handleDAV(w, r)
	case p == "/login":
		serveLoginPage(w, r)
	default:
		serveStatic(w, r)
	}
}

func serveLoginPage(w http.ResponseWriter, r *http.Request) {
	data, err := publicFS.ReadFile("public/login.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(data)
}

func serveStatic(w http.ResponseWriter, r *http.Request) {
	up := r.URL.Path
	if up == "/" {
		up = "/index.html"
	}
	name := strings.TrimPrefix(up, "/")
	data, err := publicFS.ReadFile("public/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ct := "application/octet-stream"
	switch strings.ToLower(filepath.Ext(name)) {
	case ".html":
		ct = "text/html; charset=utf-8"
	case ".js":
		ct = "text/javascript; charset=utf-8"
	case ".css":
		ct = "text/css; charset=utf-8"
	case ".svg":
		ct = "image/svg+xml"
	case ".json":
		ct = "application/json; charset=utf-8"
	case ".webmanifest":
		ct = "application/manifest+json; charset=utf-8"
	case ".png":
		ct = "image/png"
	case ".ico":
		ct = "image/x-icon"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	// 禁止缓存 html/js/css：版本升级后浏览器若用旧缓存，新旧前后端混搭会直接把页面搞挂
	w.Header().Set("Cache-Control", "no-cache")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(data)
}

func handleAPI(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	q := r.URL.Query()

	switch {
	// 登录 / 登出（无需已登录）
	case p == "/api/login" && r.Method == http.MethodPost:
		handleLogin(w, r)
	case p == "/api/logout" && r.Method == http.MethodPost:
		if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
			delSession(c.Value)
		}
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
		writeJSON(w, 200, map[string]any{"ok": true})
	// 版本（?force=1 跳过 10 分钟缓存，前端「检查更新」按钮使用）
	case p == "/api/version":
		writeJSON(w, 200, versionJSON(r.URL.Query().Get("force") == "1"))
	// 定时清理：GET 统计 / POST 立即执行 / PUT 配置
	case p == "/api/tidy" && r.Method == http.MethodPost:
		removed, grace := runTidy()
		writeJSON(w, 200, map[string]any{"ok": true, "removed": removed, "graceHours": grace, "pending": tidyPending()})
	case p == "/api/tidy/config" && r.Method == http.MethodPost:
		var body struct {
			Enabled *bool `json:"enabled"`
			Hours   int   `json:"hours"`
		}
		if err := decodeStrict(r, &body); err != nil {
			writeJSON(w, 400, map[string]any{"error": "请求参数错误: " + err.Error()})
			return
		}
		if body.Hours != 0 && (body.Hours < 1 || body.Hours > 87600) {
			writeJSON(w, 400, map[string]any{"error": "保留时长需在 1 ~ 87600 小时之间"})
			return
		}
		cfgMu.Lock()
		if body.Enabled != nil {
			cfg.TidyEnabled = body.Enabled
		}
		if body.Hours > 0 {
			cfg.TidyHours = body.Hours
		}
		cfgMu.Unlock()
		saveConfig()
		writeJSON(w, 200, map[string]any{"ok": true, "enabled": tidyEnabled(), "graceHours": tidyGrace()})
	case p == "/api/tidy":
		writeJSON(w, 200, map[string]any{"pending": tidyPending(), "graceHours": tidyGrace(), "enabled": tidyEnabled()})
	// 下载统计：分享访问日志按天聚合最近 30 天（数据已在内存日志里，仅一次线性扫描）
	case p == "/api/stats" && r.Method == http.MethodGet:
		type dayStat struct {
			Date      string `json:"date"`
			Downloads int    `json:"downloads"`
			Previews  int    `json:"previews"`
			Fails     int    `json:"fails"`
		}
		days := make([]dayStat, 30)
		now := time.Now().Local()
		for i := range days {
			days[i].Date = now.AddDate(0, 0, -(29 - i)).Format("01-02")
		}
		midnight := func(t time.Time) time.Time {
			t = t.Local()
			return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
		}
		today0 := midnight(now)
		shareMu.Lock()
		for _, s := range shares {
			if s == nil {
				continue
			}
			for _, l := range s.Log {
				diff := int(today0.Sub(midnight(time.UnixMilli(l.At))).Hours() / 24)
				if diff < 0 || diff > 29 {
					continue
				}
				i := 29 - diff
				switch {
				case !l.OK:
					days[i].Fails++
				case l.Note == "预览":
					days[i].Previews++
				default:
					days[i].Downloads++
				}
			}
		}
		shareMu.Unlock()
		writeJSON(w, 200, map[string]any{"days": days})
	// 安全与会话：会话列表 / 踢出会话 / 修改管理密码
	case p == "/api/sessions" && r.Method == http.MethodGet:
		handleSessionsList(w, r)
	case p == "/api/sessions/kick" && r.Method == http.MethodPost:
		handleSessionKick(w, r)
	case p == "/api/password" && r.Method == http.MethodPost:
		handlePasswordChange(w, r)
	case p == "/api/selfupdate" && r.Method == http.MethodPost:
		// multipart = 手动上传更新包（服务器连不上 GitHub 时的本地替代路径）
		if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
			handleSelfUpdateUpload(w, r)
			return
		}
		var body struct {
			To string `json:"to"` // 可选：指定目标版本（如 v1.0.4），空 = 最新
		}
		if err := decodeStrict(r, &body); err != nil {
			writeJSON(w, 400, map[string]any{"error": "请求参数错误: " + err.Error()})
			return
		}
		if !atomic.CompareAndSwapInt32(&updBusy, 0, 1) {
			s, _, _, _ := getUpd()
			writeJSON(w, http.StatusConflict, map[string]any{"error": "已有更新任务在进行中（" + s + "）"})
			return
		}
		go runSelfUpdate(strings.TrimSpace(body.To))
		writeJSON(w, 200, map[string]any{"started": true})
	case p == "/api/selfupdate/cancel" && r.Method == http.MethodPost:
		s, _, _, _ := getUpd()
		if s != "downloading" {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "当前阶段（" + s + "）不可取消"})
			return
		}
		atomic.StoreInt32(&updCancel, 1)
		writeJSON(w, 200, map[string]any{"ok": true})
	case p == "/api/selfupdate" && r.Method == http.MethodGet:
		writeJSON(w, 200, selfUpdateJSON())
	case p == "/api/state":
		home, _ := os.UserHomeDir()
		cwd, _ := os.Getwd()
		// cfg.RootDir 会被 POST /api/config 在 cfgMu 下改写，这里必须持锁读快照，
		// 否则并发修改配置时构成数据竞争（go test -race 可复现）
		cfgMu.Lock()
		rootDir := cfg.RootDir
		cfgMu.Unlock()
		hasDir := false
		if rootDir != "" {
			if st, err := os.Stat(rootDir); err == nil && st.IsDir() {
				hasDir = true
			}
		}
		out := map[string]any{
			"initialized": rootDir != "",
			"rootDir":     rootDir,
			"platform":    runtime.GOOS,
			"hasDir":      hasDir,
			"auth":        flagUser != "",
			"quick": map[string]string{
				"__desktop__":   filepath.Join(home, "Desktop"),
				"__downloads__": filepath.Join(home, "Downloads"),
				"__docs__":      filepath.Join(home, "Documents"),
				"__cwd__":       cwd,
			},
		}
		if hasDir {
			if total, free, err := diskUsage(rootDir); err == nil {
				out["disk"] = map[string]int64{"total": total, "free": free}
			}
		}
		writeJSON(w, 200, out)

	// 设置 / 修改根目录
	case p == "/api/config" && r.Method == http.MethodPost:
		var body struct {
			RootDir string `json:"rootDir"`
		}
		if err := decodeStrict(r, &body); err != nil {
			writeJSON(w, 400, map[string]any{"error": "请求参数错误: " + err.Error()})
			return
		}
		if body.RootDir == "" {
			writeJSON(w, 400, map[string]any{"error": "目录不能为空"})
			return
		}
		abs, _ := filepath.Abs(body.RootDir)
		st, err := os.Stat(abs)
		if err != nil || !st.IsDir() {
			writeJSON(w, 400, map[string]any{"error": "目录不存在或不是文件夹"})
			return
		}
		cfgMu.Lock()
		cfg.RootDir = abs
		cfgMu.Unlock()
		saveConfig()
		writeJSON(w, 200, map[string]any{"ok": true, "rootDir": abs})

	// 服务端目录浏览
	case p == "/api/browse":
		handleBrowse(w, r)

	default:
		// 以下接口均需要已设置根目录
		root, err := getRoot()
		if err != nil {
			writeJSON(w, 409, map[string]any{"error": err.Error(), "code": "NO_ROOT"})
			return
		}

		switch {
		case p == "/api/list":
			handleList(w, r, root)
		case p == "/api/mkdir" && r.Method == http.MethodPost:
			handleMkdir(w, r, root)
		case p == "/api/upload" && r.Method == http.MethodPost:
			handleUpload(w, r, root)
		// 分片断点续传上传
		case p == "/api/upload/init" && r.Method == http.MethodPost:
			handleUploadInit(w, r, root)
		case p == "/api/upload/complete" && r.Method == http.MethodPost:
			handleUploadComplete(w, r, root)
		case p == "/api/upload/chunk" && r.Method == http.MethodPut:
			handleUploadChunk(w, r)
		case p == "/api/upload/chunk" && r.Method == http.MethodDelete:
			handleUploadAbort(w, r)
		case p == "/api/upload/status" && r.Method == http.MethodGet:
			handleUploadStatus(w, r)
		case p == "/api/item" && r.Method == http.MethodDelete:
			handleDelete(w, r, root)
		case p == "/api/download":
			dlRel := q.Get("path")
			if inTrashRel(dlRel) {
				writeJSON(w, 400, map[string]any{"error": "回收站内容不支持直接下载"})
				return
			}
			target, err := safeJoin(root, dlRel)
			if err != nil {
				writeJSON(w, 400, map[string]any{"error": err.Error()})
				return
			}
			if !realPathInside(root, target) {
				writeJSON(w, 400, map[string]any{"error": "非法路径"})
				return
			}
			st, err := os.Stat(target)
			if err != nil || st.IsDir() {
				writeJSON(w, 404, map[string]any{"error": "文件不存在"})
				return
			}
			serveDownload(w, r, target, filepath.Base(target))
		case p == "/api/share" && r.Method == http.MethodPost:
			handleShareCreate(w, r, root)
		case p == "/api/shares":
			shareMu.Lock()
			list := make([]sharePublic, 0, len(shares))
			for _, s := range shares {
				list = append(list, publicOne(s))
			}
			shareMu.Unlock()
			sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt > list[j].CreatedAt })
			writeJSON(w, 200, map[string]any{"shares": list})
		case p == "/api/share/update" && r.Method == http.MethodPost:
			handleShareUpdate(w, r)
		case p == "/api/share" && r.Method == http.MethodDelete:
			token := q.Get("token")
			shareMu.Lock()
			_, ok := shares[token]
			delete(shares, token)
			shareMu.Unlock()
			if !ok {
				writeJSON(w, 404, map[string]any{"error": "分享不存在"})
				return
			}
			saveShares()
			writeJSON(w, 200, map[string]any{"ok": true})
		case p == "/api/sharelog":
			token := q.Get("token")
			shareMu.Lock()
			rec := shares[token]
			var log []ShareLog
			if rec != nil {
				log = append(log, rec.Log...) // 拷贝后带出，避免锁内序列化
			}
			shareMu.Unlock()
			if rec == nil {
				writeJSON(w, 404, map[string]any{"error": "分享不存在"})
				return
			}
			if log == nil {
				log = []ShareLog{}
			}
			writeJSON(w, 200, map[string]any{"token": token, "log": log})
		case p == "/api/move" && r.Method == http.MethodPost:
			handleMove(w, r, root)
		case p == "/api/search":
			handleSearch(w, r, root)
		// 多选打包下载：POST {paths:[相对路径...]} → 流式 zip
		case p == "/api/zip" && r.Method == http.MethodPost:
			handleZipDownload(w, r, root)
		// 回收站：列表 / 恢复 / 彻底删除 / 清空
		case p == "/api/trash" && r.Method == http.MethodGet:
			writeJSON(w, 200, map[string]any{"items": trashList(root), "retentionDays": envInt("TRASH_DAYS", 7)})
		case p == "/api/trash/restore" && r.Method == http.MethodPost:
			handleTrashRestore(w, r, root)
		case p == "/api/trash/purge" && r.Method == http.MethodPost:
			handleTrashPurge(w, r, root, false)
		case p == "/api/trash/clear" && r.Method == http.MethodPost:
			handleTrashPurge(w, r, root, true)
		default:
			writeJSON(w, 404, map[string]any{"error": "接口不存在"})
		}
	}
}

func handleBrowse(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query().Get("path")
	if p == "" && runtime.GOOS == "windows" {
		// 必须初始化为空切片，否则 JSON 会序列化成 null，前端 .length 报错
		drives := []map[string]string{}
		for c := 'C'; c <= 'Z'; c++ {
			d := string(c) + ":\\"
			if _, err := os.Stat(d); err == nil {
				drives = append(drives, map[string]string{"name": d, "path": d})
			}
		}
		writeJSON(w, 200, map[string]any{"path": "", "parent": nil, "entries": drives, "isRoot": true})
		return
	}
	if p == "" {
		p = "/"
	}
	items, err := os.ReadDir(p)
	if err != nil {
		writeJSON(w, 200, map[string]any{"path": p, "parent": filepath.Dir(p), "entries": []any{}, "error": "无法读取该目录"})
		return
	}
	entries := []map[string]string{}
	for _, it := range items {
		if !it.IsDir() {
			continue
		}
		name := it.Name()
		if strings.HasPrefix(name, "$") || name == "System Volume Information" {
			continue
		}
		entries = append(entries, map[string]string{"name": name, "path": filepath.Join(p, name)})
	}
	sort.Slice(entries, func(i, j int) bool {
		return strings.ToLower(entries[i]["name"]) < strings.ToLower(entries[j]["name"])
	})
	writeJSON(w, 200, map[string]any{"path": p, "parent": filepath.Dir(p), "entries": entries, "isRoot": false})
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
		// 必须把读取失败显式抛给前端
		writeJSON(w, 500, map[string]any{"error": "读取目录失败: " + err.Error()})
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
	dir, err := safeJoin(root, r.URL.Query().Get("path"))
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
	if err := decodeStrict(r, &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "请求参数错误: " + err.Error()})
		return
	}
	name := sanitizeName(body.Name)
	if name == "" {
		writeJSON(w, 400, map[string]any{"error": "名称不能为空"})
		return
	}
	if name == trashDirName {
		writeJSON(w, 400, map[string]any{"error": "该名称为系统保留"})
		return
	}
	target := filepath.Join(dir, name)
	if _, err := os.Stat(target); err == nil {
		writeJSON(w, 400, map[string]any{"error": "已存在同名文件夹"})
		return
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// decodeStrict 严格 JSON 解码：语法错误或含未知字段都报错。
// 避免手写 API 时字段名拼错被静默忽略（如把 expireSeconds 写成
// expireHours，过期时间丢失、链接静默变成永久有效）。
func decodeStrict(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

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
					"error": err.Error()})
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

const (
	uploadTempPrefix = ".fup-"
	uploadTempSuffix = ".part"
	uploadChunkMax   = 64 << 20 // 单片上限 64MB，防恶意大 body
	uploadTempTTL    = 24 * time.Hour
)

type uploadSession struct {
	ID       string
	Dir      string
	Name     string
	Size     int64
	Received int64
	Created  time.Time
}

var (
	upSessMu  sync.Mutex
	upSessMap = map[string]*uploadSession{}
)

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
	if err := decodeStrict(r, &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "请求参数错误: " + err.Error()})
		return
	}
	if body.Size < 0 {
		writeJSON(w, 400, map[string]any{"error": "size 不合法"})
		return
	}
	if flagMaxMB > 0 && body.Size > flagMaxMB*1024*1024 {
		writeJSON(w, http.StatusRequestEntityTooLarge,
			map[string]any{"error": fmt.Sprintf("文件超过 %dMB 限制", flagMaxMB)})
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
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	_ = f.Close()
	sess := &uploadSession{ID: id, Dir: dir, Name: name, Size: body.Size, Created: time.Now()}
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
	if offset != sess.Received {
		// 追加偏移不匹配：把服务端实际进度还给客户端，便于从正确位置续传
		writeJSON(w, http.StatusConflict, map[string]any{"error": "分片偏移不匹配", "received": sess.Received})
		return
	}
	var src io.Reader = io.LimitReader(r.Body, uploadChunkMax+1)
	if flagMaxMB > 0 {
		src = io.LimitReader(r.Body, flagMaxMB*1024*1024-sess.Received+1)
	}
	part := filepath.Join(sess.Dir, uploadTempPrefix+sess.ID+uploadTempSuffix)
	f, err := os.OpenFile(part, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	n, err := io.Copy(f, src)
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		writeJSON(w, 500, map[string]any{"error": "分片写入失败"})
		return
	}
	if n == uploadChunkMax+1 {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "单片超过 64MB 上限"})
		return
	}
	if flagMaxMB > 0 && sess.Received+n > flagMaxMB*1024*1024 {
		writeJSON(w, http.StatusRequestEntityTooLarge,
			map[string]any{"error": fmt.Sprintf("文件超过 %dMB 限制", flagMaxMB)})
		return
	}
	upSessMu.Lock()
	sess.Received += n
	upSessMu.Unlock()
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
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	if err := os.Rename(part, final); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	upSessMu.Lock()
	delete(upSessMap, id)
	upSessMu.Unlock()
	_ = root // root 仅用于与其它接口签名一致；写盘路径已由会话校验过
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
	writeJSON(w, 200, map[string]any{"ok": true, "received": sess.Received, "size": sess.Size})
}

// handleUploadAbort DELETE /api/upload/chunk?id= —— 放弃上传并删除分片
func handleUploadAbort(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	upSessMu.Lock()
	sess := upSessMap[id]
	delete(upSessMap, id)
	upSessMu.Unlock()
	if sess != nil {
		_ = os.Remove(filepath.Join(sess.Dir, uploadTempPrefix+sess.ID+uploadTempSuffix))
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// gcUploadSessions 回收超时上传会话（由每小时清理任务调用）
func gcUploadSessions() {
	cutoff := time.Now().Add(-uploadTempTTL)
	upSessMu.Lock()
	var stale []*uploadSession
	for id, s := range upSessMap {
		if s.Created.Before(cutoff) {
			stale = append(stale, s)
			delete(upSessMap, id)
		}
	}
	upSessMu.Unlock()
	for _, s := range stale {
		_ = os.Remove(filepath.Join(s.Dir, uploadTempPrefix+s.ID+uploadTempSuffix))
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
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "trashed": true})
}

// handleZipDownload 多选打包：POST {paths:["a/b.txt","dir"]} → 流式 zip
func handleZipDownload(w http.ResponseWriter, r *http.Request, root string) {
	var body struct {
		Paths []string `json:"paths"`
	}
	if err := decodeStrict(r, &body); err != nil {
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
	if err := decodeStrict(r, &body); err != nil || strings.TrimSpace(body.Name) == "" {
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
	if err := decodeStrict(r, &body); err != nil || strings.TrimSpace(body.Name) == "" {
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
func handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		User string `json:"user"`
		Pass string `json:"pass"`
	}
	if err := decodeStrict(r, &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "请求参数错误: " + err.Error()})
		return
	}
	ip := clientIP(r)
	if ms := banRemaining(ip); ms > 0 {
		w.Header().Set("Retry-After", strconv.FormatInt(ms/1000+1, 10))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error": fmt.Sprintf("失败次数过多，该 IP 已被临时封禁，请 %d 分钟后再试", ms/60000+1),
		})
		return
	}
	if flagUser == "" {
		writeJSON(w, 400, map[string]any{"error": "服务未启用认证，无需登录"})
		return
	}
	if subtle.ConstantTimeCompare([]byte(body.User), []byte(flagUser)) != 1 || !checkPass(body.Pass) {
		recordAuthFail(ip)
		writeJSON(w, 401, map[string]any{"error": "用户名或密码错误"})
		return
	}
	tok, exp := newSession(flagUser, ip)
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: tok, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
		MaxAge: int(time.Until(time.UnixMilli(exp)).Seconds()),
		Secure: clientScheme(r) == "https",
	})
	writeJSON(w, 200, map[string]any{"ok": true})
}

// handleMove 重命名 / 同盘移动（from/to 均为相对根目录路径，to 含文件名）
func handleMove(w http.ResponseWriter, r *http.Request, root string) {
	var body struct {
		From string `json:"from"`
		To   string `json:"to"`
	}
	if err := decodeStrict(r, &body); err != nil {
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
	if fromAbs == toAbs {
		writeJSON(w, 400, map[string]any{"error": "源与目标是同一路径"})
		return
	}
	// 自嵌套校验：不能把文件夹移动到它自己的子目录里。
	// 前端已拦截，但 API 层必须兜底，否则只能靠 os.Rename 报 500
	if strings.HasPrefix(toAbs, fromAbs+string(filepath.Separator)) {
		writeJSON(w, 400, map[string]any{"error": "不能移动到自身或其子目录下"})
		return
	}
	if _, err := os.Stat(fromAbs); err != nil {
		writeJSON(w, 404, map[string]any{"error": "源文件不存在"})
		return
	}
	if _, err := os.Lstat(toAbs); err == nil {
		writeJSON(w, 400, map[string]any{"error": "目标位置已存在同名文件或文件夹"})
		return
	}
	// 目标目录必须已存在（不隐式创建，避免误操作堆出目录树）
	if err := os.MkdirAll(filepath.Dir(toAbs), 0o755); err != nil {
		writeJSON(w, 400, map[string]any{"error": "目标目录不存在"})
		return
	}
	if err := os.Rename(fromAbs, toAbs); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
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
		if s.AbsPath == fromAbs { // 被移动的文件/目录本身
			s.AbsPath = toAbs
			s.RelPath = newRel
			s.Name = filepath.Base(toAbs)
			changed = true
		} else if strings.HasPrefix(s.AbsPath, fromAbs+string(filepath.Separator)) {
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
	writeJSON(w, 200, map[string]any{"results": results, "truncated": len(results) >= limit})
}

// ---------------- WebDAV（Class 1 最小子集） ----------------
//
// 面向 Salt Player / foobar2000 / N_player 等音乐播放器与常规 WebDAV 客户端：
// OPTIONS / PROPFIND / GET / HEAD / PUT / MKCOL / DELETE / MOVE / PROPPATCH。
// 不实现 LOCK/UNLOCK（Class 2），Windows 资源管理器「映射网络驱动器」需要锁，不受支持。
// 鉴权：Basic（用户名/密码同管理端）或登录会话 Cookie；未启用认证时开放访问。
// 根路径即文件根目录：/dav/ = 根，/dav/音乐/a.mp3 = 根内相对路径。

const davPathPrefix = "/dav"

func handleDAV(w http.ResponseWriter, r *http.Request) {
	root, err := getRoot()
	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(409)
		_, _ = w.Write([]byte("根目录未初始化，请先在网页端完成设置"))
		return
	}
	rel := strings.TrimPrefix(r.URL.Path, davPathPrefix)
	rel = strings.TrimPrefix(rel, "/")
	if inTrashRel(rel) {
		w.WriteHeader(404)
		return
	}
	switch r.Method {
	case http.MethodOptions:
		w.Header().Set("DAV", "1")
		w.Header().Set("Allow", davAllowMethods)
		w.Header().Set("MS-Author-Via", "DAV")
		w.WriteHeader(204)
	case "PROPFIND":
		davPropfind(w, r, root, rel)
	case http.MethodGet, http.MethodHead:
		davGet(w, r, root, rel)
	case http.MethodPut:
		davPut(w, r, root, rel)
	case "MKCOL":
		davMkcol(w, r, root, rel)
	case http.MethodDelete:
		davDelete(w, r, root, rel)
	case "MOVE":
		davMove(w, r, root, rel)
	case "PROPPATCH":
		davProppatch(w, rel)
	default:
		w.Header().Set("Allow", davAllowMethods)
		w.WriteHeader(405)
	}
}

const davAllowMethods = "OPTIONS, GET, HEAD, PUT, PROPFIND, PROPPATCH, MKCOL, DELETE, MOVE"

// davResolve 把 /dav 相对路径解析为 root 内绝对路径（safeJoin + symlink 兜底）
func davResolve(root, rel string) (string, error) {
	p, err := safeJoin(root, rel)
	if err != nil {
		return "", err
	}
	if !realPathInside(root, p) {
		return "", errors.New("非法路径")
	}
	return p, nil
}

// davHref 构造 <D:href> / 链接地址：逐段 URL 转义，目录以 / 结尾
func davHref(rel string, isDir bool) string {
	if rel == "" {
		return davPathPrefix + "/"
	}
	segs := strings.Split(rel, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	h := davPathPrefix + "/" + strings.Join(segs, "/")
	if isDir {
		h += "/"
	}
	return h
}

func davPropfind(w http.ResponseWriter, r *http.Request, root, rel string) {
	p, err := davResolve(root, rel)
	if err != nil {
		w.WriteHeader(400)
		return
	}
	st, err := os.Stat(p)
	if err != nil {
		w.WriteHeader(404)
		return
	}
	depth := strings.ToLower(strings.TrimSpace(r.Header.Get("Depth")))
	if depth == "" {
		depth = "infinity"
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?>` + "\n")
	b.WriteString(`<D:multistatus xmlns:D="DAV:">`)
	davWriteResponse(&b, rel, st)
	if depth != "0" && st.IsDir() {
		items, err := os.ReadDir(p)
		if err == nil {
			for _, it := range items {
				if rel == "" && it.Name() == trashDirName {
					continue
				}
				if isUploadTemp(it.Name()) {
					continue
				}
				info, err := it.Info()
				if err != nil {
					continue
				}
				child := it.Name()
				if rel != "" {
					child = rel + "/" + it.Name()
				}
				davWriteResponse(&b, child, info)
			}
		}
	}
	b.WriteString(`</D:multistatus>`)
	w.Header().Set("Content-Type", `application/xml; charset="utf-8"`)
	w.WriteHeader(207)
	_, _ = w.Write([]byte(b.String()))
}

// davWriteResponse 单个资源的 propstat XML
func davWriteResponse(b *strings.Builder, rel string, st os.FileInfo) {
	isDir := st.IsDir()
	b.WriteString(`<D:response>`)
	b.WriteString(`<D:href>` + davHref(rel, isDir) + `</D:href>`)
	b.WriteString(`<D:propstat><D:prop>`)
	name := rel
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		name = rel[i+1:]
	}
	if name == "" {
		name = "/"
	}
	b.WriteString(`<D:displayname>` + htmlEsc(name) + `</D:displayname>`)
	if !isDir {
		b.WriteString(`<D:getcontentlength>` + strconv.FormatInt(st.Size(), 10) + `</D:getcontentlength>`)
		ct := "application/octet-stream"
		if t := mime.TypeByExtension(strings.ToLower(filepath.Ext(name))); t != "" {
			ct = t
		}
		b.WriteString(`<D:getcontenttype>` + htmlEsc(ct) + `</D:getcontenttype>`)
	}
	if isDir {
		b.WriteString(`<D:resourcetype><D:collection/></D:resourcetype>`)
	} else {
		b.WriteString(`<D:resourcetype/>`)
	}
	b.WriteString(`<D:getlastmodified>` + st.ModTime().UTC().Format(http.TimeFormat) + `</D:getlastmodified>`)
	b.WriteString(`<D:getetag>"` + fmt.Sprintf("%x-%x", st.Size(), st.ModTime().UnixNano()) + `"</D:getetag>`)
	b.WriteString(`</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>`)
	b.WriteString(`</D:response>`)
}

func davGet(w http.ResponseWriter, r *http.Request, root, rel string) {
	p, err := davResolve(root, rel)
	if err != nil {
		w.WriteHeader(400)
		return
	}
	st, err := os.Stat(p)
	if err != nil {
		w.WriteHeader(404)
		return
	}
	if st.IsDir() {
		// 浏览器直接打开 /dav/ 时给一个简单目录页（播放器客户端不会 GET 目录）
		items, _ := os.ReadDir(p)
		var b strings.Builder
		b.WriteString(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>`)
		b.WriteString(htmlEsc(rel))
		b.WriteString(`</title><style>body{font-family:sans-serif;margin:24px}a{display:block;padding:6px 0;font-size:15px}</style></head><body><h2>/`)
		b.WriteString(htmlEsc(rel))
		b.WriteString(`</h2>`)
		for _, it := range items {
			if rel == "" && it.Name() == trashDirName {
				continue
			}
			if isUploadTemp(it.Name()) {
				continue
			}
			child := it.Name()
			if rel != "" {
				child = rel + "/" + it.Name()
			}
			name := it.Name()
			if it.IsDir() {
				name += "/"
			}
			b.WriteString(`<a href="` + davHref(child, it.IsDir()) + `">` + htmlEsc(name) + `</a>`)
		}
		b.WriteString(`</body></html>`)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(200)
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write([]byte(b.String()))
		return
	}
	f, err := os.Open(p)
	if err != nil {
		w.WriteHeader(404)
		return
	}
	defer f.Close()
	// 内联返回（不设 attachment）：播放器按 Content-Type 流式读取，Range 拖动由 ServeContent 处理
	ct := "application/octet-stream"
	if t := mime.TypeByExtension(strings.ToLower(filepath.Ext(p))); t != "" {
		ct = t
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeContent(w, r, st.Name(), st.ModTime(), f)
}

func davPut(w http.ResponseWriter, r *http.Request, root, rel string) {
	if rel == "" || strings.HasSuffix(rel, "/") {
		w.WriteHeader(400)
		return
	}
	if inTrashRel(rel) {
		w.WriteHeader(403)
		return
	}
	p, err := safeJoin(root, rel)
	if err != nil {
		w.WriteHeader(400)
		return
	}
	// PUT 的父目录可能不存在，且目标文件通常是新建的：用 ensureCreatableInside
	// 校验已存在祖先（realPathInside 对不存在的路径放行，挡不住 symlink 逃逸）
	if !ensureCreatableInside(root, filepath.Dir(p)) {
		w.WriteHeader(403)
		return
	}
	// RFC 4918 9.7.1：目标是已存在的目录 → 405
	if st, err := os.Stat(p); err == nil && st.IsDir() {
		w.WriteHeader(405)
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		w.WriteHeader(500)
		return
	}
	created := true
	if _, err := os.Lstat(p); err == nil {
		created = false
	}
	// 临时文件 + 原子替换：上传中断不会用半成品覆盖原文件
	tmp, err := os.CreateTemp(filepath.Dir(p), ".davput-*")
	if err != nil {
		w.WriteHeader(500)
		return
	}
	tmpName := tmp.Name()
	_ = tmp.Chmod(0o644)
	var src io.Reader = r.Body
	if flagMaxMB > 0 {
		src = io.LimitReader(r.Body, flagMaxMB*1024*1024+1)
	}
	n, copyErr := io.Copy(tmp, src)
	closeErr := tmp.Close()
	if copyErr != nil || closeErr != nil {
		os.Remove(tmpName)
		w.WriteHeader(500)
		return
	}
	if flagMaxMB > 0 && n > flagMaxMB*1024*1024 {
		os.Remove(tmpName)
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	if err := os.Rename(tmpName, p); err != nil {
		os.Remove(tmpName)
		w.WriteHeader(500)
		return
	}
	if created {
		w.WriteHeader(201)
	} else {
		w.WriteHeader(204)
	}
}

func davMkcol(w http.ResponseWriter, r *http.Request, root, rel string) {
	if rel == "" {
		w.WriteHeader(400)
		return
	}
	if inTrashRel(rel) {
		w.WriteHeader(403)
		return
	}
	p, err := safeJoin(root, rel)
	if err != nil {
		w.WriteHeader(400)
		return
	}
	if !ensureCreatableInside(root, filepath.Dir(p)) {
		w.WriteHeader(403)
		return
	}
	if _, err := os.Stat(p); err == nil {
		w.WriteHeader(405) // 已存在
		return
	}
	if err := os.MkdirAll(p, 0o755); err != nil {
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(201)
}

func davDelete(w http.ResponseWriter, r *http.Request, root, rel string) {
	p, err := davResolve(root, rel)
	if err != nil {
		w.WriteHeader(400)
		return
	}
	if p == root {
		w.WriteHeader(403) // 不允许删除根目录
		return
	}
	if _, err := os.Lstat(p); err != nil {
		w.WriteHeader(404)
		return
	}
	// 与网页端一致：删除进回收站，防误删（需要彻底删除用回收站页面）
	if _, err := moveToTrash(root, p); err != nil {
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(204)
}

func davMove(w http.ResponseWriter, r *http.Request, root, rel string) {
	dest := r.Header.Get("Destination")
	if dest == "" {
		w.WriteHeader(400)
		return
	}
	du, err := url.Parse(dest)
	if err != nil || !strings.HasPrefix(du.Path, davPathPrefix) {
		w.WriteHeader(400) // 目标必须在 /dav 命名空间内
		return
	}
	drel := strings.TrimPrefix(du.Path, davPathPrefix)
	drel = strings.TrimPrefix(drel, "/")
	if inTrashRel(drel) {
		w.WriteHeader(403)
		return
	}
	fromAbs, err := davResolve(root, rel)
	if err != nil {
		w.WriteHeader(400)
		return
	}
	toAbs, err := safeJoin(root, drel)
	if err != nil {
		w.WriteHeader(400)
		return
	}
	if !realPathInside(root, toAbs) {
		w.WriteHeader(400)
		return
	}
	if fromAbs == root || toAbs == root {
		w.WriteHeader(403)
		return
	}
	// 自移动（源=目标）：若不拦截，下面「目标已存在→先入回收站」会把文件本身
	// 移进回收站，随后 rename 因源已不存在而 500，用户视角等于文件丢失
	if fromAbs == toAbs {
		w.WriteHeader(403)
		return
	}
	// 自嵌套：把目录移到它自己的子目录里，rename 只会报 EINVAL，
	// 必须在改动磁盘前拒绝（与网页端 /api/move 的校验对齐）
	if strings.HasPrefix(toAbs, fromAbs+string(filepath.Separator)) {
		w.WriteHeader(409)
		return
	}
	overwrite := !strings.EqualFold(r.Header.Get("Overwrite"), "F")
	existed := false
	if _, err := os.Lstat(toAbs); err == nil {
		existed = true
		if !overwrite {
			w.WriteHeader(412) // 目标已存在且 Overwrite: F
			return
		}
		// Overwrite: T → 目标先进回收站
		if _, err := moveToTrash(root, toAbs); err != nil {
			w.WriteHeader(500)
			return
		}
	}
	if err := os.MkdirAll(filepath.Dir(toAbs), 0o755); err != nil {
		w.WriteHeader(500)
		return
	}
	if err := os.Rename(fromAbs, toAbs); err != nil {
		w.WriteHeader(500)
		return
	}
	moveShareSync(root, fromAbs, toAbs)
	// RFC 4918 9.9.4：覆盖已有目标返回 204，新建返回 201
	if existed {
		w.WriteHeader(204)
	} else {
		w.WriteHeader(201)
	}
}

// davProppatch 最小实现：一律应答 200（播放器客户端不校验属性写回结果）
func davProppatch(w http.ResponseWriter, rel string) {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?>` + "\n")
	b.WriteString(`<D:multistatus xmlns:D="DAV:"><D:response>`)
	b.WriteString(`<D:href>` + davHref(rel, false) + `</D:href>`)
	b.WriteString(`<D:propstat><D:prop/><D:status>HTTP/1.1 200 OK</D:status></D:propstat>`)
	b.WriteString(`</D:response></D:multistatus>`)
	w.Header().Set("Content-Type", `application/xml; charset="utf-8"`)
	w.WriteHeader(207)
	_, _ = w.Write([]byte(b.String()))
}

// startTidy 定时清理：每小时清理一次过期超过 TIDY_HOURS（默认 72h）的分享记录；
// 同时清理回收站过期条目与分享密码防爆破记录
func startTidy() {
	go func() {
		for range time.Tick(time.Hour) {
			if !tidyEnabled() {
				continue
			}
			if removed, _ := runTidy(); removed > 0 {
				log.Printf("[清理] 移除 %d 条过期分享记录", removed)
			}
		}
	}()
	go func() {
		for range time.Tick(time.Hour) {
			// 回收站：超过 TRASH_DAYS（默认 7 天，0 = 永久保留）的条目自动彻底删除
			if root, err := getRoot(); err == nil {
				if n := trashSweep(root); n > 0 {
					log.Printf("[清理] 回收站自动清理 %d 项（超过保留期）", n)
				}
			}
			// 分享密码防爆破记录：过期条目回收，防止 map 长期缓慢增长
			sharePwGCSweep()
			// 分片上传会话：超 24h 的会话连同分片文件一并回收
			gcUploadSessions()
		}
	}()
}

// sharePwGCSweep 清理已过期的分享密码防爆破记录
func sharePwGCSweep() {
	now := time.Now().UnixMilli()
	sharePwMu.Lock()
	for k, f := range sharePwFails {
		// 封禁已到期，或计数窗口已结束且未升级为封禁 → 记录失效可删
		if (f.blockedUntil != 0 && f.blockedUntil <= now) ||
			(f.blockedUntil == 0 && now-f.firstAt > sharePwWindowMs) {
			delete(sharePwFails, k)
		}
	}
	sharePwMu.Unlock()
}

// tidyEnabled 自动清理开关：config.json 有配置用配置，默认开启
func tidyEnabled() bool {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	if cfg.TidyEnabled != nil {
		return *cfg.TidyEnabled
	}
	return true
}

// tidyGrace 返回配置的保留时长（小时）：config.json 优先，其次 TIDY_HOURS 环境变量，默认 72
func tidyGrace() int {
	cfgMu.Lock()
	if cfg.TidyHours > 0 {
		h := cfg.TidyHours
		cfgMu.Unlock()
		return h
	}
	cfgMu.Unlock()
	return envInt("TIDY_HOURS", 72)
}

// runTidy 立即执行一次清理，返回移除条数
func runTidy() (int, int) {
	grace := tidyGrace()
	cutoff := time.Now().Add(-time.Duration(grace) * time.Hour).UnixMilli()
	shareMu.Lock()
	removed := 0
	for tok, s := range shares {
		if s.ExpiresAt > 0 && s.ExpiresAt < cutoff {
			delete(shares, tok)
			removed++
		}
	}
	shareMu.Unlock()
	if removed > 0 {
		saveShares()
	}
	return removed, grace
}

// tidyPending 统计当前已过期、等待被清理的记录数
func tidyPending() int {
	grace := tidyGrace()
	cutoff := time.Now().Add(-time.Duration(grace) * time.Hour).UnixMilli()
	shareMu.Lock()
	defer shareMu.Unlock()
	n := 0
	for _, s := range shares {
		if s.ExpiresAt > 0 && s.ExpiresAt < cutoff {
			n++
		}
	}
	return n
}

func handleShareCreate(w http.ResponseWriter, r *http.Request, root string) {
	var body struct {
		Path          string `json:"path"`
		ExpireSeconds int64  `json:"expireSeconds"`
		MaxDownloads  int    `json:"maxDownloads"`
		Scheme        string `json:"scheme"`
		Host          string `json:"host"`
		Password      string `json:"password"` // 空 = 无密码
		Mode          string `json:"mode"`     // "direct"（默认）| "page"
		Alias         string `json:"alias"`    // 可选：自定义链接别名
		Hotlink       bool   `json:"hotlink"`  // 可选：防盗链
	}
	if err := decodeStrict(r, &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "请求参数错误: " + err.Error()})
		return
	}
	// scheme/host 必须白名单校验：scheme 只允许 auto/http/https；
	// host 不允许含空白、路径分隔符、查询/锚点、userinfo 等，
	// 否则可注入恶意链接（如 scheme=javascript:、host=evil.com 换行注入）
	switch body.Scheme {
	case "", "auto", "http", "https":
	default:
		writeJSON(w, 400, map[string]any{"error": "不支持的协议 scheme"})
		return
	}
	if strings.IndexFunc(body.Host, func(r rune) bool {
		return r <= ' ' || r == '/' || r == '\\' || r == '?' || r == '#' || r == '@'
	}) >= 0 {
		writeJSON(w, 400, map[string]any{"error": "host 不合法"})
		return
	}
	if body.Mode != "" && body.Mode != "direct" && body.Mode != "page" {
		writeJSON(w, 400, map[string]any{"error": "访问方式不合法"})
		return
	}
	// 归一化：存储层只认 ""（直链，兼容旧记录）与 "page"，
	// "direct" 是前端直链按钮的显式取值，落库前折回 ""
	if inTrashRel(body.Path) {
		writeJSON(w, 400, map[string]any{"error": "不能分享回收站内容"})
		return
	}
	// 拒绝分享根目录本身：全盘打包无大小预估、无进度，且极易把不应外发的
	// 内容（含各子目录全部文件）一次性暴露；需要分享请建子目录后分享它
	if strings.TrimSpace(filepath.ToSlash(body.Path)) == "" || body.Path == "/" {
		writeJSON(w, 400, map[string]any{"error": "不能分享根目录，请选择具体文件夹"})
		return
	}
	target, err := safeJoin(root, body.Path)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if !realPathInside(root, target) {
		writeJSON(w, 400, map[string]any{"error": "非法路径"})
		return
	}
	st, err := os.Stat(target)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "文件不存在"})
		return
	}
	// 文件夹也可以分享：访问时流式打包 zip 下载（不占服务器磁盘）
	size := st.Size()
	if st.IsDir() {
		size = 0
	}
	// 输入校验：负数会让「限次」静默变成不限次（alive 判定用 >0），
	// 负的过期时间也会被 >0 判断吞掉，二者都必须显式拒绝而不是静默忽略
	if body.MaxDownloads < 0 {
		writeJSON(w, 400, map[string]any{"error": "下载次数不能为负数"})
		return
	}
	if body.ExpireSeconds < 0 {
		writeJSON(w, 400, map[string]any{"error": "有效期不能为负数"})
		return
	}
	// 别名可选：填了就必须合法且未被占用，避免静默忽略让用户以为别名生效了
	alias := ""
	if strings.TrimSpace(body.Alias) != "" {
		alias = normalizeAlias(body.Alias)
		if alias == "" {
			writeJSON(w, 400, map[string]any{"error": "别名不合法：仅限中英文、数字、中划线、下划线，1~40 字符"})
			return
		}
		if aliasTaken(alias, "") {
			writeJSON(w, 400, map[string]any{"error": "别名已被占用: " + alias})
			return
		}
	}
	token := newToken()
	rec := &Share{
		Token:        token,
		Name:         filepath.Base(target),
		RelPath:      filepath.ToSlash(strings.TrimPrefix(strings.TrimPrefix(target, root), string(filepath.Separator))),
		AbsPath:      target,
		Size:         size,
		MaxDownloads: body.MaxDownloads,
		CreatedAt:    time.Now().UnixMilli(),
		Scheme:       body.Scheme,
		Host:         body.Host,
		Mode:         "",
		Alias:        alias,
		Hotlink:      body.Hotlink,
	}
	if body.Mode == "page" {
		rec.Mode = "page"
	}
	if rec.Scheme == "" {
		rec.Scheme = "auto"
	}
	if strings.TrimSpace(body.Password) != "" {
		pw := strings.TrimSpace(body.Password)
		setSharePassword(rec, pw)
	}
	if body.ExpireSeconds > 0 {
		rec.ExpiresAt = time.Now().UnixMilli() + body.ExpireSeconds*1000
	}
	shareMu.Lock()
	shares[token] = rec
	shareMu.Unlock()
	saveShares()

	host := rec.Host
	if host == "" {
		host = clientHost(r)
	}
	scheme := rec.Scheme
	if scheme == "auto" {
		scheme = clientScheme(r)
	}
	// 设置了别名就返回别名链接（token 链接同样有效）
	slug := rec.Token
	if rec.Alias != "" {
		slug = rec.Alias
	}
	writeJSON(w, 200, map[string]any{
		"ok":    true,
		"share": publicOne(rec),
		"url":   fmt.Sprintf("%s://%s/s/%s", scheme, host, slug),
	})
}

// handleShareUpdate 快速编辑分享：不删除重建，直接修改过期时间 / 密码 / 访问方式
func handleShareUpdate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token     string  `json:"token"`
		ExpiresAt int64   `json:"expiresAt"` // 毫秒时间戳，0 = 永久
		Password  string  `json:"password"`  // 空 = 清除密码保护
		Mode      string  `json:"mode"`      // "direct"（默认）| "page"
		Alias     *string `json:"alias"`     // 可选：null = 不修改；"" = 清除别名
		Hotlink   *bool   `json:"hotlink"`   // 可选：null = 不修改
	}
	if err := decodeStrict(r, &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "请求参数错误: " + err.Error()})
		return
	}
	if body.ExpiresAt < 0 {
		writeJSON(w, 400, map[string]any{"error": "过期时间不合法"})
		return
	}
	if body.Alias != nil && strings.TrimSpace(*body.Alias) != "" {
		alias := normalizeAlias(*body.Alias)
		if alias == "" {
			writeJSON(w, 400, map[string]any{"error": "别名不合法：仅限中英文、数字、中划线、下划线，1~40 字符"})
			return
		}
		if aliasTaken(alias, body.Token) {
			writeJSON(w, 400, map[string]any{"error": "别名已被占用: " + alias})
			return
		}
	}
	shareMu.Lock()
	rec, ok := shares[body.Token]
	if !ok {
		shareMu.Unlock()
		writeJSON(w, 404, map[string]any{"error": "分享不存在"})
		return
	}
	rec.ExpiresAt = body.ExpiresAt
	if body.Alias != nil {
		if strings.TrimSpace(*body.Alias) == "" {
			rec.Alias = ""
		} else {
			rec.Alias = normalizeAlias(*body.Alias)
		}
	}
	if body.Hotlink != nil {
		rec.Hotlink = *body.Hotlink
	}
	pw := strings.TrimSpace(body.Password)
	if pw != "" {
		setSharePassword(rec, pw)
	} else {
		clearSharePassword(rec) // 留空 = 清除密码保护
	}
	if body.Mode == "page" {
		rec.Mode = "page"
	} else {
		rec.Mode = ""
	}
	out := publicOne(rec)
	shareMu.Unlock()
	saveShares()
	writeJSON(w, 200, map[string]any{"ok": true, "share": out})
}

// handleSessionsList 当前活跃登录会话（含登录 IP 与时间），供「安全与会话」页展示
func handleSessionsList(w http.ResponseWriter, r *http.Request) {
	if flagUser == "" {
		writeJSON(w, 200, map[string]any{"enabled": false, "sessions": []any{}})
		return
	}
	cur := ""
	if c, err := r.Cookie(sessionCookie); err == nil {
		cur = c.Value
	}
	type sessItem struct {
		ID        string `json:"id"`
		IP        string `json:"ip"`
		CreatedAt int64  `json:"createdAt"`
		ExpiresAt int64  `json:"expiresAt"`
		Current   bool   `json:"current"`
	}
	now := time.Now().UnixMilli()
	sessMu.Lock()
	items := []sessItem{}
	for tok, s := range sessions {
		if s.ExpiresAt > 0 && s.ExpiresAt < now {
			continue
		}
		id := tok
		if len(id) > 12 { // 只暴露 token 前缀作为标识，完整 token 不出服务端
			id = id[:12]
		}
		items = append(items, sessItem{ID: id, IP: s.IP, CreatedAt: s.CreatedAt, ExpiresAt: s.ExpiresAt, Current: tok == cur})
	}
	sessMu.Unlock()
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt > items[j].CreatedAt })
	writeJSON(w, 200, map[string]any{"enabled": true, "sessions": items})
}

// handleSessionKick 踢出其他登录会话（当前会话不允许踢自己）
func handleSessionKick(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	if err := decodeStrict(r, &body); err != nil || strings.TrimSpace(body.ID) == "" {
		writeJSON(w, 400, map[string]any{"error": "请求参数错误"})
		return
	}
	cur := ""
	if c, err := r.Cookie(sessionCookie); err == nil {
		cur = c.Value
	}
	sessMu.Lock()
	found := ""
	for tok := range sessions {
		if strings.HasPrefix(tok, body.ID) {
			found = tok
			break
		}
	}
	if found == "" {
		sessMu.Unlock()
		writeJSON(w, 404, map[string]any{"error": "会话不存在或已过期"})
		return
	}
	if found == cur {
		sessMu.Unlock()
		writeJSON(w, 400, map[string]any{"error": "不能踢出当前登录的会话"})
		return
	}
	delete(sessions, found)
	sessMu.Unlock()
	saveSessions()
	writeJSON(w, 200, map[string]any{"ok": true})
}

// handlePasswordChange 修改管理员登录密码（需验证当前密码），哈希持久化到 config.json
func handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OldPass string `json:"oldPass"`
		NewPass string `json:"newPass"`
	}
	if err := decodeStrict(r, &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "请求参数错误: " + err.Error()})
		return
	}
	if flagUser == "" {
		writeJSON(w, 400, map[string]any{"error": "服务未启用登录认证，无需修改密码"})
		return
	}
	if !checkPass(body.OldPass) {
		writeJSON(w, 401, map[string]any{"error": "当前密码不正确"})
		return
	}
	newPw := strings.TrimSpace(body.NewPass)
	if len(newPw) < 6 {
		writeJSON(w, 400, map[string]any{"error": "新密码至少需要 6 位"})
		return
	}
	cfgMu.Lock()
	cfg.AuthPassHash = hashAuthPw(newPw)
	cfgMu.Unlock()
	saveConfig()
	log.Printf("[安全] 管理密码已通过网页修改（IP %s）", clientIP(r))
	// 密码变更后必须让其他会话失效：否则此前被盗用的 session 仍可长期使用，
	// 改密对用户而言等于没有恢复控制权。当前会话保留，避免自己被踢下线
	cur := ""
	if c, err := r.Cookie(sessionCookie); err == nil {
		cur = c.Value
	}
	sessMu.Lock()
	kicked := 0
	for tok := range sessions {
		if tok != cur {
			delete(sessions, tok)
			kicked++
		}
	}
	sessMu.Unlock()
	if kicked > 0 {
		saveSessions()
		log.Printf("[安全] 密码变更后已踢出 %d 个其他登录会话", kicked)
	}
	writeJSON(w, 200, map[string]any{"ok": true, "kickedSessions": kicked})
}

// appendShareLog 记录分享访问日志，每条最多保留 50 条
func appendShareLog(s *Share, ip, ua string, ok bool, note string) {
	if s.Log == nil {
		s.Log = []ShareLog{}
	}
	s.Log = append(s.Log, ShareLog{At: time.Now().UnixMilli(), IP: ip, UA: ua, OK: ok, Note: note})
	if len(s.Log) > 50 {
		s.Log = s.Log[len(s.Log)-50:]
	}
}

func htmlEsc(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}

// fmtSizeGo 字节数人性化（确认页展示用）
func fmtSizeGo(b int64) string {
	const unit = 1024
	if b < unit {
		return strconv.FormatInt(b, 10) + " B"
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// handleShareGet 分享访问入口：密码门禁 -> 确认页/直链 -> 计数与日志
func handleShareGet(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/s/")
	if i := strings.Index(token, "/"); i >= 0 {
		token = token[:i]
	}
	if token == "" {
		writeJSON(w, 404, map[string]any{"error": "缺少 token"})
		return
	}
	// 只接受 GET/HEAD：POST 等非下载动作不计数也不返回内容，
	// 否则任意构造 POST /s/xxx 就能把一次性链接的下载次数烧光
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "不支持的请求方法"})
		return
	}
	ip, ua := clientIP(r), r.UserAgent()
	if len(ua) > 120 {
		ua = ua[:120]
	}
	// 统计本次响应实际写出的字节数，收尾时累加到下载 ticket 的 Served。
	// 首次计数下载时 ticket 是在本请求过程中才签发的（请求里还没有 Cookie），
	// 所以 issuedTicket 也要一并兜住，否则第一次下载不会被记为「已传完」
	var issuedTicket string
	wc := &countingWriter{ResponseWriter: w}
	w = wc
	defer func() {
		t := dlTicketOf(r)
		if t == "" {
			t = issuedTicket
		}
		dlTicketAddServed(t, wc.n)
	}()

	// 只取一份快照用于判定与渲染，之后不再在锁外读 rec 的字段：
	// 否则会与并发的 countOnce（写 Downloads/LastDownloadAt）、
	// handleShareUpdate（写 ExpiresAt/Mode）、moveShareSync（写 AbsPath）竞争
	shareMu.Lock()
	live := shares[token]
	if live == nil {
		// 别名兜底：/s/<alias> 与 /s/<token> 等价；命中后换回真实 token，
		// 后续日志/计次/防爆破键全部基于 token，别名的存在与否不影响计数
		for tok, s := range shares {
			if s != nil && s.Alias != "" && s.Alias == token {
				live = shares[tok]
				token = tok
				break
			}
		}
	}
	var snap Share
	if live != nil {
		snap = *live
	}
	shareMu.Unlock()
	if live == nil {
		writeJSON(w, 404, map[string]any{"error": "分享链接无效"})
		return
	}
	rec := &snap // 只读视图；写操作一律经 live 在 shareMu 内进行
	logFail := func(note string) {
		shareMu.Lock()
		if l := shares[token]; l != nil {
			appendShareLog(l, ip, ua, false, note)
		}
		shareMu.Unlock()
		saveShares()
	}
	if rec.ExpiresAt > 0 && time.Now().UnixMilli() > rec.ExpiresAt {
		logFail("链接已过期")
		writeJSON(w, 403, map[string]any{"error": "链接已过期"})
		return
	}
	// 防盗链：开启后，带 Referer 且域名非本站的请求直接拒绝（直访/下载器不带 Referer 不受影响）
	if rec.Hotlink {
		if ref := r.Header.Get("Referer"); ref != "" {
			if u, perr := url.Parse(ref); perr == nil && u.Host != "" {
				if u.Host != r.Host && u.Host != clientHost(r) {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					w.Header().Set("Cache-Control", "no-store")
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte(`<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>禁止引用</title></head><body style="font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;color:#5A6478"><p>此链接已开启防盗链，请从原页面打开或直接访问。</p></body></html>`))
					return
				}
			}
		}
	}
	// 先取文件状态：下面的配额豁免判定需要文件大小
	st, err := os.Stat(rec.AbsPath)
	if err != nil {
		logFail("文件已被删除或移动")
		writeJSON(w, 404, map[string]any{"error": "文件已被删除或移动"})
		return
	}
	// ticket 判定必须放在配额检查之前：一次性链接首次下载即耗尽配额，
	// 若先查配额，中途断掉的合法续传（持 ticket + Range）会被门口的 403 拒掉，
	// 下发的 ticket 就永远用不上。持票续传不是新下载，豁免配额门槛。
	//
	// 但豁免必须限定为「上一次传输确实没传完」：否则一次正常下载拿到 ticket 后，
	// 反复带 Range: bytes=1- 每次都能取到接近完整的文件而永不计数（实测可复现）。
	// 用 ticket 上累计的已下发字节数判断是否已经完整传过一次。
	hasTicket := dlTicketValid(r, token)
	isResume := hasTicket && rangeStartPositive(r)
	if isResume && st.Size() > 0 && dlTicketServed(dlTicketOf(r)) >= st.Size() {
		isResume = false
	}
	if rec.MaxDownloads > 0 && rec.Downloads >= rec.MaxDownloads && !isResume {
		logFail("下载次数已用完")
		writeJSON(w, 403, map[string]any{"error": "下载次数已用完"})
		return
	}
	// 文件夹分享：访问时整体打包为 zip 流式下载（边压缩边传输，不落盘中转）
	isDirShare := st.IsDir()
	if isDirShare {
		// zip 是全量流，不存在「续传片段」语义：持 ticket 的 Range 请求
		// 每次拿到的都是完整 zip，若沿用 isResume 豁免，一次性文件夹分享
		// 会被无限次完整下载。文件夹一律按新下载计次（HEAD 仍豁免）
		isResume = false
	}
	// 媒体文件支持浏览器内预览（客户端渲染，服务端仅透传）：
	// - 直链模式：内联返回，对方在浏览器里直接看到/播放（仍按下载计数）
	// - 确认页模式：页面内嵌预览，预览请求（?inline=1）不消耗下载次数
	mediaKind := ""
	if !isDirShare {
		mediaKind = mediaKindOf(rec.Name)
	}
	// symlink 兜底：分享创建后若文件被替换成指向 root 外的链接，下载必须拒绝
	if root, err := getRoot(); err != nil || !realPathInside(root, rec.AbsPath) {
		logFail("文件已被删除或移动")
		writeJSON(w, 404, map[string]any{"error": "文件已被删除或移动"})
		return
	}
	// 密码门禁：无有效密码时渲染输入表单（带防爆破限制）
	givenPw := r.URL.Query().Get("pw")
	if rec.PasswordHash != "" {
		if msg, blocked := sharePwBlocked(token, ip); blocked {
			logFail("密码错误次数过多，暂时封禁")
			renderSharePage(w, rec, true, false, givenPw, msg, http.StatusTooManyRequests, isDirShare)
			return
		}
		ok, legacy := verifyPwHash(nsShare, givenPw, rec.PasswordHash)
		if legacy && ok {
			// 旧分享记录的哈希还是单次 sha256：校验通过后就地升级并落盘
			shareMu.Lock()
			if up := hashSharePw(givenPw); up != "" {
				if l := shares[token]; l != nil {
					l.PasswordHash = up
				}
			}
			shareMu.Unlock()
			saveShares()
		}
		if !ok {
			if givenPw != "" {
				blockedMsg := sharePwRecordFail(token, ip)
				logFail("密码错误")
				status := http.StatusOK
				if blockedMsg != "" {
					status = http.StatusTooManyRequests
				}
				renderSharePage(w, rec, true, true, givenPw, blockedMsg, status, isDirShare)
				return
			}
			renderSharePage(w, rec, true, false, givenPw, "", http.StatusOK, isDirShare)
			return
		}
		sharePwClear(token, ip)
	}
	// 缓存重验证（条件请求）确实不是一次真实的新下载，可以免计次；
	// 但必须确认服务端「真的会回 304」才豁免 —— 旧实现只看请求头里有没有
	// If-Modified-Since / If-None-Match 就免计次，任何人加一个 1970 年的时间戳
	// 就能带着完整文件响应无限下载（实测可复现）。这里按真实 modtime 判定。
	// 文件夹分享（zip 全量流）不适用：条件请求同样能拿完整 zip，必须计次
	if !isDirShare && condRequestNotModified(r, st.ModTime()) {
		isResume = true
	}
	// HEAD 不是真实下载：下载器/IM/邮件客户端的链接预检都会先发 HEAD，
	// 若计次会「看一眼就把一次性链接打死」，因此与续传同样处理
	isHead := r.Method == http.MethodHead
	// countOnce 在 shareMu 内原子地完成「检查配额 + 扣减」，
	// 避免 MaxDownloads=1 时并发请求同时通过前置检查造成超发；返回 false 表示配额已用完
	countOnce := func() bool {
		shareMu.Lock()
		l := shares[token]
		if l == nil {
			shareMu.Unlock()
			return false
		}
		if l.MaxDownloads > 0 && l.Downloads >= l.MaxDownloads {
			shareMu.Unlock()
			return false
		}
		l.Downloads++
		l.LastDownloadAt = time.Now().UnixMilli()
		appendShareLog(l, ip, ua, true, "")
		shareMu.Unlock()
		saveShares()
		// 只有真实计过次的下载才拿到续传授权，伪造 Range 的头拿不到 ticket
		issuedTicket = setDlTicketCookie(w, token)
		return true
	}
	noQuota := func() {
		logFail("下载次数已用完")
		writeJSON(w, 403, map[string]any{"error": "下载次数已用完"})
	}
	// 直链模式（默认，与历史行为一致）：链接即下载。
	// 计数在发送文件【之前】同步完成：一次性链接首次请求即消耗配额，
	// 客户端中断/并发连接/预取都无法绕过；经授权的续传片段与 HEAD 除外
	if rec.Mode != "page" {
		if counted := !isResume && !isHead; counted && !countOnce() {
			noQuota()
			return
		}
		if isDirShare {
			serveShareZip(w, rec)
		} else if mediaKind != "" {
			// 图片/视频/音频：内联返回，对方打开链接直接在浏览器里看到而非弹下载；
			// 保存/另存为仍可用，下载器拿到的也是完整文件
			serveInline(w, r, rec.AbsPath, rec.Name)
		} else {
			serveDownload(w, r, rec.AbsPath, rec.Name)
		}
		return
	}
	// 确认页模式：展示文件信息，?dl=1 才真正下载（此时才计数）；
	// ?inline=1 为页面内嵌的预览请求：仅限媒体文件，密码门禁已在上面通过，
	// 不消耗下载次数（一次性链接「看一眼预览」不该把唯一一次下载烧掉）
	if r.URL.Query().Get("dl") != "1" {
		if mediaKind != "" && r.URL.Query().Get("inline") == "1" {
			// 仅首次完整拉取（无 Range）记一条「预览」访问日志，拖动进度条产生的
			// Range 片段不记，避免日志被同一播放会话刷屏
			if r.Header.Get("Range") == "" {
				shareMu.Lock()
				if l := shares[token]; l != nil {
					appendShareLog(l, ip, ua, true, "预览")
				}
				shareMu.Unlock()
				saveShares()
			}
			serveInline(w, r, rec.AbsPath, rec.Name)
			return
		}
		renderSharePage(w, rec, false, false, givenPw, "", http.StatusOK, isDirShare)
		return
	}
	counted := !isResume && !isHead
	if counted && !countOnce() {
		noQuota()
		return
	}
	if isDirShare {
		serveShareZip(w, rec)
	} else {
		serveDownload(w, r, rec.AbsPath, rec.Name)
	}
}

// serveShareZip 文件夹分享的流式 zip 下载（与密码门禁/计数逻辑解耦，仅负责输出）。
// root 传入根目录：打包时排除根级回收站（已删除文件不得借分享外泄）
func serveShareZip(w http.ResponseWriter, rec *Share) {
	root, _ := getRoot()
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", contentDisposition("attachment", rec.Name)+".zip")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
	zw := zip.NewWriter(w)
	defer zw.Close()
	_ = zipAdd(zw, root, rec.AbsPath, rec.Name)
}

// renderSharePage 确认页 / 密码输入页（自包含 HTML，不依赖管理端静态资源）
// askPw=true 渲染密码表单；否则渲染文件信息 + 下载按钮（携带已验证的 pw）
// ---------------- 分享密码防爆破 ----------------
// 同一 IP 对同一 token：10 分钟内密码错误满 5 次封禁 15 分钟
var (
	sharePwMu    sync.Mutex
	sharePwFails = map[string]*sharePwFail{} // key: token|ip
)

type sharePwFail struct {
	count        int
	firstAt      int64
	blockedUntil int64
}

const (
	sharePwWindowMs = 10 * 60 * 1000
	sharePwMaxFails = 5
	sharePwBlockMs  = 15 * 60 * 1000
)

func sharePwKey(token, ip string) string { return token + "|" + ip }

// sharePwBlocked 返回当前是否处于封禁状态及剩余提示
func sharePwBlocked(token, ip string) (string, bool) {
	sharePwMu.Lock()
	defer sharePwMu.Unlock()
	f := sharePwFails[sharePwKey(token, ip)]
	if f == nil || f.blockedUntil == 0 {
		return "", false
	}
	remain := f.blockedUntil - time.Now().UnixMilli()
	if remain <= 0 {
		delete(sharePwFails, sharePwKey(token, ip))
		return "", false
	}
	return fmt.Sprintf("密码错误次数过多，请 %d 分钟后再试", int(remain/60000)+1), true
}

// sharePwRecordFail 记录一次失败；若刚好触发封禁返回提示文案
func sharePwRecordFail(token, ip string) string {
	sharePwMu.Lock()
	defer sharePwMu.Unlock()
	key := sharePwKey(token, ip)
	f := sharePwFails[key]
	now := time.Now().UnixMilli()
	if f == nil || now-f.firstAt > sharePwWindowMs {
		f = &sharePwFail{count: 0, firstAt: now}
		sharePwFails[key] = f
	}
	f.count++
	if f.count >= sharePwMaxFails {
		f.blockedUntil = now + sharePwBlockMs
		return "密码错误次数过多，已临时封禁 15 分钟"
	}
	return ""
}

func sharePwClear(token, ip string) {
	sharePwMu.Lock()
	delete(sharePwFails, sharePwKey(token, ip))
	sharePwMu.Unlock()
}

// renderSharePage 的 status 参数：正常页传 200，密码错误次数过多被封禁时传 429，
// 让客户端能从状态码感知限流（此前先写 body 再 WriteHeader 导致恒为 200）
func renderSharePage(w http.ResponseWriter, s *Share, askPw, pwWrong bool, givenPw, notice string, status int, isDir bool) {
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"><title>文件下载</title>`)
	b.WriteString(`<style>body{margin:0;background:#F4F6FA;font-family:-apple-system,BlinkMacSystemFont,"PingFang SC","Segoe UI",sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;min-height:100dvh;color:#000;box-sizing:border-box;padding:calc(16px + env(safe-area-inset-top)) calc(12px + env(safe-area-inset-right)) calc(16px + env(safe-area-inset-bottom)) calc(12px + env(safe-area-inset-left))}
.card{background:#fff;border-radius:18px;padding:34px 30px;width:min(420px,92vw);text-align:center;box-shadow:0 10px 40px rgba(0,0,0,.06)}
.ic{width:56px;height:56px;margin:0 auto 14px;border-radius:14px;background:rgba(0,122,255,.1);color:#2563EB;display:flex;align-items:center;justify-content:center}
.ic svg{width:28px;height:28px}
h1{font-size:19px;margin:0 0 4px;word-break:break-all}
.meta{font-size:13px;color:rgba(60,60,67,.6);margin:2px 0}
.tag{display:inline-block;padding:2px 8px;border-radius:6px;font-size:11.5px;background:rgba(120,120,128,.12);margin:6px 3px 0;color:#3C3C43}
.btn{display:block;width:100%;height:46px;border:0;border-radius:12px;background:#2563EB;color:#fff;font-size:15px;font-weight:500;cursor:pointer;margin-top:18px;text-decoration:none;line-height:46px}
.btn:active{opacity:.85}
input{width:100%;height:44px;border:1px solid rgba(60,60,67,.13);border-radius:10px;padding:0 12px;font-size:16px;box-sizing:border-box;margin-top:16px;outline:none}
input:focus{border-color:#2563EB;box-shadow:0 0 0 3px rgba(0,122,255,.12)}
.err{color:#FF3B30;font-size:13px;margin-top:8px}
.pv{margin:18px 0 0}
.pv img{max-width:100%;max-height:38vh;border-radius:10px}
.pv video{width:100%;max-height:38vh;border-radius:10px;background:#000}
.pv audio{width:100%;margin-top:10px}
.pv-hint{font-size:11.5px;color:rgba(60,60,67,.45);margin-top:6px}</style></head><body><div class="card">`)
	b.WriteString(`<div class="ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M12 16V4"/><path d="m7 9 5-5 5 5"/><path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/></svg></div>`)
	b.WriteString(`<h1>` + htmlEsc(s.Name) + (map[bool]string{true: ` <span style="font-size:13px;color:rgba(60,60,67,.55)">（文件夹，将打包为 ZIP）</span>`, false: ""}[isDir]) + `</h1>`)
	if isDir {
		b.WriteString(`<div class="meta">文件夹</div>`)
	} else {
		b.WriteString(`<div class="meta">` + htmlEsc(fmtSizeGo(s.Size)) + `</div>`)
	}
	if s.ExpiresAt > 0 {
		left := time.Until(time.UnixMilli(s.ExpiresAt))
		b.WriteString(`<span class="tag">` + htmlEsc(fmtLeftGo(left)) + `</span>`)
	} else {
		b.WriteString(`<span class="tag">永久有效</span>`)
	}
	if s.MaxDownloads > 0 {
		// 并发下 Downloads 可能短暂越过 MaxDownloads，显示层兜底为 0
		left := s.MaxDownloads - s.Downloads
		if left < 0 {
			left = 0
		}
		b.WriteString(`<span class="tag">剩余 ` + strconv.Itoa(left) + ` 次下载</span>`)
	}
	if askPw {
		b.WriteString(`<form method="get" action="">`)
		b.WriteString(`<input type="text" name="pw" placeholder="请输入访问密码" autofocus>`)
		if pwWrong {
			b.WriteString(`<div class="err">密码错误，请重试</div>`)
		}
		if notice != "" {
			b.WriteString(`<div class="err">` + htmlEsc(notice) + `</div>`)
		}
		b.WriteString(`<button class="btn" type="submit">验证并继续</button></form>`)
	} else {
		// 媒体文件（图片/视频/音频）：下载按钮上方内嵌预览，浏览器端渲染。
		// 预览请求 ?inline=1 不消耗下载次数，另存原文件走下方下载按钮
		if mk := mediaKindOf(s.Name); mk != "" && !isDir {
			src := "?inline=1"
			if givenPw != "" {
				src += "&pw=" + url.QueryEscape(givenPw)
			}
			switch mk {
			case "img":
				b.WriteString(`<div class="pv"><img src="` + htmlEsc(src) + `" alt="预览"></div>`)
			case "vid":
				b.WriteString(`<div class="pv"><video src="` + htmlEsc(src) + `" controls playsinline preload="metadata"></video><div class="pv-hint">预览不消耗下载次数</div></div>`)
			case "aud":
				b.WriteString(`<div class="pv"><audio src="` + htmlEsc(src) + `" controls preload="metadata"></audio><div class="pv-hint">预览不消耗下载次数</div></div>`)
			}
		}
		dl := "?dl=1"
		if givenPw != "" {
			dl += "&pw=" + url.QueryEscape(givenPw)
		}
		b.WriteString(`<a class="btn" href="` + htmlEsc(dl) + (map[bool]string{true: `">打包下载 ZIP</a>`, false: `">下载文件</a>`}[isDir]))
		if notice != "" {
			b.WriteString(`<div class="err">` + htmlEsc(notice) + `</div>`)
		}
	}
	b.WriteString(`</div></body></html>`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// 状态码必须在 Write 之前设置：一旦写过 body，net/http 会隐式发出 200，
	// 之后的 WriteHeader 被静默丢弃（并在日志刷 superfluous WriteHeader 警告）
	w.WriteHeader(status)
	_, _ = w.Write([]byte(b.String()))
}

func fmtLeftGo(d time.Duration) string {
	if d <= 0 {
		return "已过期"
	}
	if d < time.Hour {
		return fmt.Sprintf("%d 分钟后过期", int(d.Minutes())+1)
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%d 小时后过期", int(d.Hours())+1)
	}
	return fmt.Sprintf("%d 天后过期", int(d.Hours()/24)+1)
}

// ---------------- 启动 ----------------
func main() {
	flag.IntVar(&flagPort, "port", envInt("PORT", 8080), "监听端口")
	flag.StringVar(&flagHost, "host", envStr("HOST", "0.0.0.0"), "监听地址")
	flag.StringVar(&flagDir, "dir", os.Getenv("ROOT_DIR"), "文件根目录（预设后无需网页配置）")
	flag.StringVar(&flagDataDir, "data-dir", envStr("DATA_DIR", defaultDataDir()), "配置与分享记录存放目录")
	flag.StringVar(&flagUser, "user", os.Getenv("AUTH_USER"), "管理端用户名（Basic 认证）")
	flag.StringVar(&flagPass, "pass", os.Getenv("AUTH_PASS"), "管理端密码")
	flag.BoolVar(&flagProxy, "trust-proxy", envBool("TRUST_PROXY", false), "信任反向代理头 X-Forwarded-*")
	flag.Int64Var(&flagMaxMB, "max-upload-mb", int64(envInt("MAX_UPLOAD_MB", 0)), "单文件上传上限(MB)，0 不限制")
	flag.BoolVar(&flagLog, "log", envBool("LOG", true), "输出访问日志")
	showVer := flag.Bool("version", false, "打印版本信息后退出")
	flag.Parse()

	if *showVer {
		fmt.Printf("fileserver %s\n  commit:    %s\n  built:     %s\n  repo:      https://github.com/%s\n",
			curVersion(), commit, buildTime, updateRepo)
		return
	}

	loadConfig()
	loadShares()
	loadSessions()
	// ROOT_DIR/-dir 仅作为首次初始化的默认值：
	// config.json 中已有根目录时不覆盖，否则服务重启（含每次更新）会把用户改过的目录打回环境变量里的值
	if flagDir != "" && cfg.RootDir == "" {
		abs, _ := filepath.Abs(flagDir)
		cfg.RootDir = abs
		saveConfig()
	}

	addr := fmt.Sprintf("%s:%d", flagHost, flagPort)
	fmt.Println("============================================")
	// CI 注入的 version 形如 "v1.0.0"，本地构建为 "1.0.0"，统一成单个 v 前缀
	fmt.Printf("  文件服务 %s 已启动\n", curVersion())
	fmt.Printf("  版本详情:   commit %s · 构建于 %s\n", commit, buildTime)
	fmt.Printf("  监听地址:   %s\n", addr)
	fmt.Printf("  文件目录:   %s\n", orDefault(cfg.RootDir, "(未设置，打开页面配置)"))
	fmt.Printf("  数据目录:   %s\n", flagDataDir)
	if flagUser != "" {
		fmt.Printf("  访问认证:   已开启（用户: %s，会话 %d 天）\n", flagUser, int(sessionTTL().Hours()/24))
	} else {
		fmt.Println("  访问认证:   未开启（公网部署请加 -user/-pass）")
	}
	if flagProxy {
		fmt.Println("  反向代理:   是（识别 X-Forwarded-Proto / Host）")
	}
	if addrs, err := localIPs(); err == nil {
		for _, ip := range addrs {
			fmt.Printf("  访问地址:   http://%s:%d\n", ip, flagPort)
		}
	}
	fmt.Println("============================================")

	startBanGC() // 认证失败记录的定期清理
	startTidy()  // 过期分享记录的定期清理

	srv := &http.Server{
		Addr:              addr,
		Handler:           http.HandlerFunc(handler),
		ReadHeaderTimeout: 30 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// 默认数据目录：可执行文件同级目录下的 data/
// 部署为服务时建议显式指定 -data-dir（如 /var/lib/fileserver），便于持久化
func defaultDataDir() string {
	return filepath.Join(".", "data")
}
func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
func localIPs() ([]string, error) {
	list, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, a := range list {
		ipNet, ok := a.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() {
			continue
		}
		if ip4 := ipNet.IP.To4(); ip4 != nil {
			out = append(out, ip4.String())
		}
	}
	return out, nil
}
