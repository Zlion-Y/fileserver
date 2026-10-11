package main

import (
	"archive/zip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
)

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
// 注意：调用方必须已持有 shareMu（锁内版本），锁外的入口检查仅作快速失败
func aliasTakenLocked(alias, exceptToken string) bool {
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

func aliasTaken(alias, exceptToken string) bool {
	shareMu.Lock()
	defer shareMu.Unlock()
	return aliasTakenLocked(alias, exceptToken)
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

type dlTicketRec struct {
	Token string
	Exp   int64
	// Served 本 ticket 至今已实际下发的字节数。
	// 用来区分「上一次传输确实没传完」与「已经完整传过一次」：
	// 没有它的话，一次正常下载拿到 ticket 之后，反复带 Range: bytes=1-
	// 每次都能取到接近完整的文件而永不计数（实测可复现），maxDownloads 形同虚设。
	Served int64
}

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

// rangeCoversToEnd 判断 Range 请求是否覆盖到文件末尾（即响应包含完整尾部内容）。
// 无 Range 头视为覆盖；多段 Range 任一段覆盖末尾即视为覆盖
func rangeCoversToEnd(r *http.Request, size int64) bool {
	rg := r.Header.Get("Range")
	if rg == "" {
		return true
	}
	if size <= 0 {
		return true
	}
	rg = strings.TrimPrefix(rg, "bytes=")
	for _, part := range strings.Split(rg, ",") {
		p := strings.SplitN(strings.TrimSpace(part), "-", 2)
		if len(p) == 0 || strings.TrimSpace(p[0]) == "" {
			continue
		}
		start, err := strconv.ParseInt(strings.TrimSpace(p[0]), 10, 64)
		if err != nil {
			continue
		}
		end := size - 1
		if len(p) == 2 && strings.TrimSpace(p[1]) != "" {
			if e, err2 := strconv.ParseInt(strings.TrimSpace(p[1]), 10, 64); err2 == nil {
				end = e
			}
		}
		if start <= size-1 && end >= size-1 {
			return true
		}
	}
	return false
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
// cookiePath 按「用户当前访问的 /s/<别名或token>」精确限定：别名访问的链接
// 若把 Cookie Path 绑到真实 token，续传请求（同别名 URL）会带不上 Cookie，
// 限次链接中途断开就无法续传。返回签发的 ticket（空串表示失败）
func setDlTicketCookie(w http.ResponseWriter, token, cookiePath string) string {
	ticket := newDlTicket(token)
	if ticket == "" {
		return ""
	}
	http.SetCookie(w, &http.Cookie{
		Name:     dlTicketCookie,
		Value:    ticket,
		Path:     cookiePath, // 精确作用域：不带入其他接口，也不与其他分享冲突
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
			// 预览记录：已不存在分享的条目回收
			previewGC()
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

// maxExpireSeconds 分享有效期上限（10 年）：无上限的 ExpireSeconds 乘 1000
// 会溢出成负数，「>0 判定」失效，链接被当成永久且永不回收
const maxExpireSeconds = int64(10 * 365 * 24 * 3600)

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
	if err := decodeStrict(w, r, &body); err != nil {
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
	if body.ExpireSeconds > maxExpireSeconds {
		writeJSON(w, 400, map[string]any{"error": "有效期过长（最长 10 年）"})
		return
	}
	if body.ExpireSeconds > 0 {
		rec.ExpiresAt = time.Now().UnixMilli() + body.ExpireSeconds*1000
	}
	shareMu.Lock()
	// 锁内复查别名：入口检查与插入之间有窗口，两个并发创建同名别名会双双通过
	if alias != "" && aliasTakenLocked(alias, "") {
		shareMu.Unlock()
		writeJSON(w, 400, map[string]any{"error": "别名已被占用: " + alias})
		return
	}
	shares[token] = rec
	// publicOne 读 Downloads 等字段，必须锁内完成：
	// 锁外用 live 指针读会与 countOnce/handleShareUpdate 的锁内写竞争
	out := publicOne(rec)
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
		"share": out,
		"url":   fmt.Sprintf("%s://%s/s/%s", scheme, host, slug),
	})
}

// handleShareUpdate 快速编辑分享：不删除重建，直接修改过期时间 / 密码 / 访问方式。
// 全部字段用指针语义（nil = 不修改）：旧的值类型字段在「只改个别项」的
// 快速编辑里会把有效期/密码/访问方式静默清空，永久链接秒变 1 小时或反之
func handleShareUpdate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token     string  `json:"token"`
		ExpiresAt *int64  `json:"expiresAt"` // 毫秒时间戳，0 = 永久；null = 不修改
		Password  *string `json:"password"`  // null = 不修改；"" = 清除密码保护
		Mode      *string `json:"mode"`      // "direct"（默认）| "page"；null = 不修改
		Alias     *string `json:"alias"`     // 可选：null = 不修改；"" = 清除别名
		Hotlink   *bool   `json:"hotlink"`   // 可选：null = 不修改
	}
	if err := decodeStrict(w, r, &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "请求参数错误: " + err.Error()})
		return
	}
	if body.ExpiresAt != nil && *body.ExpiresAt < 0 {
		writeJSON(w, 400, map[string]any{"error": "过期时间不合法"})
		return
	}
	if body.Mode != nil && *body.Mode != "" && *body.Mode != "direct" && *body.Mode != "page" {
		writeJSON(w, 400, map[string]any{"error": "访问方式不合法"})
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
	// 锁内复查：入口检查与持锁修改之间别名可能已被其他请求占用
	if body.Alias != nil && strings.TrimSpace(*body.Alias) != "" && aliasTakenLocked(normalizeAlias(*body.Alias), body.Token) {
		shareMu.Unlock()
		writeJSON(w, 400, map[string]any{"error": "别名已被占用: " + normalizeAlias(*body.Alias)})
		return
	}
	if body.ExpiresAt != nil {
		rec.ExpiresAt = *body.ExpiresAt
	}
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
	if body.Password != nil {
		pw := strings.TrimSpace(*body.Password)
		if pw != "" {
			setSharePassword(rec, pw)
		} else {
			clearSharePassword(rec) // 显式空串 = 清除密码保护
		}
	}
	if body.Mode != nil {
		if *body.Mode == "page" {
			rec.Mode = "page"
		} else {
			rec.Mode = ""
		}
	}
	out := publicOne(rec)
	shareMu.Unlock()
	saveShares()
	writeJSON(w, 200, map[string]any{"ok": true, "share": out})
}

// handleSessionsList 当前活跃登录会话（含登录 IP 与时间），供「安全与会话」页展示
func appendShareLog(s *Share, ip, ua string, ok bool, note string) {
	if s.Log == nil {
		s.Log = []ShareLog{}
	}
	s.Log = append(s.Log, ShareLog{At: time.Now().UnixMilli(), IP: ip, UA: ua, OK: ok, Note: note})
	if len(s.Log) > 50 {
		s.Log = s.Log[len(s.Log)-50:]
	}
}

// ---------------- IP 归属地查询（分享访问日志 / 登录会话展示用） ----------------
//
// 数据源固定为 UAPIs（uapis.cn）的 ipinfo 接口（source=commercial，2 积分/次），
// 精度到区县级 + 运营商。配置了 UAPIs Key（data/config.json 的 uapiKey 或 UAPI_KEY
// 环境变量）走计费额度（QPS 7、额度更大），未配置走免注册访客积分（QPS 4、1500 积分/月）。
// 查询结果进程内缓存：命中后不再出网；归属地本身极少变动。

// ipGeo 归属地信息；空字段不序列化，前端按已有字段拼接展示
type ipGeo struct {
	Country  string `json:"country,omitempty"`
	Prov     string `json:"prov,omitempty"`
	City     string `json:"city,omitempty"`
	District string `json:"district,omitempty"`
	Street   string `json:"street,omitempty"`
	ISP      string `json:"isp,omitempty"`
	Source   string `json:"source,omitempty"` // 数据源标识：空 = 查询失败
}

type ipGeoEntry struct {
	geo ipGeo
	at  time.Time
}

func throttleGeo(interval time.Duration) {
	geoRateMu.Lock()
	now := time.Now()
	start := geoNextStart
	if start.Before(now) {
		start = now
	}
	geoNextStart = start.Add(interval)
	geoRateMu.Unlock()
	if d := time.Until(start); d > 0 {
		time.Sleep(d)
	}
}

// lookupIPGeo 带缓存查询单个 IP 的归属地（并发安全）
func lookupIPGeo(rawIP string) ipGeo {
	rawIP = strings.TrimSpace(rawIP)
	if rawIP == "" {
		return ipGeo{}
	}
	ip := net.ParseIP(rawIP)
	if ip == nil {
		return ipGeo{}
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return ipGeo{ISP: "局域网", Source: "local"}
	}
	now := time.Now()
	geoMu.Lock()
	if e, ok := geoCache[rawIP]; ok {
		ttl := geoOKTTL
		if e.geo.Source == "" {
			ttl = geoBadTTL
		}
		if now.Sub(e.at) < ttl {
			geoMu.Unlock()
			return e.geo
		}
	}
	geoMu.Unlock()

	geo := fetchGeoUapis(rawIP)
	geoMu.Lock()
	geoCache[rawIP] = ipGeoEntry{geo: geo, at: time.Now()}
	if len(geoCache) > geoMaxIPs {
		// 先按各自 TTL 清过期（失败 10 分钟、成功 7 天）。
		// 之前统一按 10 分钟清，缓存一旦装满，7 天内的新鲜成功结果也会被当成
		// 过期项删掉，归属地缓存退化成 10 分钟，白白烧上游积分
		for k, v := range geoCache {
			ttl := geoOKTTL
			if v.geo.Source == "" {
				ttl = geoBadTTL
			}
			if now.Sub(v.at) >= ttl {
				delete(geoCache, k)
			}
		}
	}
	if len(geoCache) > geoMaxIPs {
		// 全是新条目仍超限（短时间涌入大量新 IP）：按写入时间淘汰最旧的一半，
		// 摊薄后续每次插入都触发全表扫描的成本
		ents := make([]ipGeoEnt, 0, len(geoCache))
		for k, v := range geoCache {
			ents = append(ents, ipGeoEnt{k, v.at})
		}
		sort.Slice(ents, func(i, j int) bool { return ents[i].at.Before(ents[j].at) })
		for _, e := range ents {
			if len(geoCache) <= geoMaxIPs/2 {
				break
			}
			delete(geoCache, e.k)
		}
	}
	geoMu.Unlock()
	return geo
}

// ipGeoEnt 缓存淘汰用的键-时间对
type ipGeoEnt struct {
	k  string
	at time.Time
}

// uapiKey 归属地查询用的 UAPIs Key：环境变量 UAPI_KEY 优先，其次 data/config.json 的
// uapiKey 字段（管理后台保存即写到这里）；都为空则走访客积分模式（免注册，额度低）
func uapiKey() string {
	if v := os.Getenv("UAPI_KEY"); v != "" {
		return strings.TrimSpace(v)
	}
	cfgMu.Lock()
	defer cfgMu.Unlock()
	return strings.TrimSpace(cfg.UapiKey)
}

// maskKey key 打码回显：uapi-ab12_…wX9z，完整值不出服务器
func maskKey(k string) string {
	k = strings.TrimSpace(k)
	if k == "" {
		return ""
	}
	r := []rune(k)
	if len(r) <= 11 {
		return "…"
	}
	return string(r[:7]) + "…" + string(r[len(r)-4:])
}

// fetchJSON URL 出 GET，把响应体解析为 JSON 对象（非 2xx / 超时 / 解析失败返回 nil）。
// hdrs 为附加请求头（可为 nil）
func fetchJSON(url string, hdrs map[string]string) map[string]any {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	resp, err := geoClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var v map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&v); err != nil {
		return nil
	}
	return v
}

// fetchGeoUapis UAPIs.cn ipinfo：source=commercial 精度到区县。
// region 为空格分隔字符串：境内是 "中国 省份 城市 区县"（如 "中国 湖北省 荆门市 钟祥市"），
// 境外是英文（如 "United States Virginia Ashburn"），分词位数不可靠，整串放国家；
// llc 是运营商简称（"移动"），比 isp 全称更适合行内展示
func fetchGeoUapis(ip string) ipGeo {
	key := uapiKey()
	interval := geoIntervalVisitor
	if key != "" {
		interval = geoIntervalKeyed
	}
	throttleGeo(interval) // 全局排队起跑：并发再高也不会撞上 QPS 上限
	var hdrs map[string]string
	if key != "" {
		// 有 Key 走计费额度（实测 Bearer 头会把限流切换为 billing-key-rate），
		// 无 Key 不带头，走免注册访客积分
		hdrs = map[string]string{"Authorization": "Bearer " + key}
	}
	v := fetchJSON("https://uapis.cn/api/v1/network/ipinfo?ip="+url.QueryEscape(ip)+"&source=commercial", hdrs)
	if v == nil {
		return ipGeo{}
	}
	region, _ := v["region"].(string)
	// 个别冷门 IP 会返回 "*" 之类的占位垃圾，视为查询失败不展示
	if strings.Trim(region, "*-·. ") == "" {
		return ipGeo{}
	}
	g := ipGeo{ISP: geoStr(v, "llc", "isp"), Source: "UAPIs"}
	parts := strings.Fields(region)
	if len(parts) > 0 && parts[0] == "中国" {
		g.Country = parts[0]
		if len(parts) > 1 {
			g.Prov = parts[1]
		}
		if len(parts) > 2 {
			g.City = parts[2]
		}
		if len(parts) > 3 {
			g.District = parts[3]
		}
		if d := geoStr(v, "district"); d != "" && g.District == "" {
			g.District = d
		}
	} else {
		g.Country = region
	}
	return g
}

// geoStr 从 JSON 对象里取第一个存在的字符串字段
func geoStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// handleIPGeo GET /api/ipgeo?ips=a,b,c → 批量查询归属地（管理端日志/会话展示用）。
// 并发查询以缩短首屏等待；单批最多 30 个。
func handleIPGeo(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	raw := q.Get("ips")
	ips := strings.Split(raw, ",")
	requested := make([]string, 0, len(ips))
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" || net.ParseIP(ip) == nil {
			continue
		}
		requested = append(requested, ip)
		if len(requested) >= 30 {
			break
		}
	}
	out := make(map[string]ipGeo, len(requested))
	var wg sync.WaitGroup
	var mu sync.Mutex
	// 上游普遍限流（如 UAPIs QPS 4）：并发封顶，超出部分排队
	sem := make(chan struct{}, 4)
	for _, ip := range requested {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			g := lookupIPGeo(ip)
			mu.Lock()
			out[ip] = g
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	writeJSON(w, 200, map[string]any{"geos": out})
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
	// URL 里的原始别名/token（Cookie Path 要与它一致，续传请求才带得上 ticket）
	urlSlug := token
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
		// 失败日志延迟落盘：旧的每条失败都全量重写 shares.json，
		// 未认证请求可以以此放大磁盘 IO 并刷日志（见 startSharesFlush）
		markSharesDirty()
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
		if givenPw == "" {
			// 空密码直接按「未提供」渲染表单，不跑 PBKDF2：
			// 旧的无条件校验让匿名请求每次都烧满 50k 轮（弱设备 CPU DoS），
			// 且空密码本来就不可能通过非空口令的哈希校验
			renderSharePage(w, rec, true, false, "", "", http.StatusOK, isDirShare)
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
	// HEAD 请求文件夹分享：只回响应头，不做完整遍历+压缩
	// （旧实现 HEAD 也全量打包，零配额消耗 CPU/IO 且不留访问日志无法审计）
	if isDirShare && isHead {
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", contentDisposition("attachment", rec.Name)+".zip")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(200)
		return
	}
	// 「到文件末尾」的传输（无 Range 或 Range 覆盖到末尾）持票并发互斥：
	// 防止一次合法计次后 N 个并发 Range: bytes=1- 同时通过准入、
	// 每条都拿到接近完整的文件（ticket 的 Served 在响应结束才累加）
	ticketNow := dlTicketOf(r)
	if !isDirShare && !isHead && hasTicket && rangeCoversToEnd(r, st.Size()) {
		if !dlInFlightAdd(ticketNow) {
			logFail("同一链接的并发下载已超限")
			writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "该链接正在下载中，请勿并发重复下载"})
			return
		}
		defer dlInFlightDone(ticketNow)
	}
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
		// 只有真实计过次的下载才拿到续传授权，伪造 Range 的头拿不到 ticket；
		// Cookie Path 用当前 URL 里的别名或 token，保证同 URL 的续传请求能带上
		issuedTicket = setDlTicketCookie(w, token, "/s/"+urlSlug)
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
				// 完整内容预览每 IP 只放行一次：inline 不计数是给「看一眼」用的，
				// 不限次等于绕过 maxDownloads 无限取回完整文件
				if !previewAllow(token, ip) {
					writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "完整预览已获取过，请通过下载按钮获取文件"})
					return
				}
				shareMu.Lock()
				if l := shares[token]; l != nil {
					appendShareLog(l, ip, ua, true, "预览")
				}
				shareMu.Unlock()
				markSharesDirty()
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
type sharePwFail struct {
	count        int
	firstAt      int64
	blockedUntil int64
}

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

// previewDone 每个 token|ip 只允许一次「完整内容」的 inline 预览拉取。
// ?inline=1 不计数是设计使然（一次性链接看一眼预览不该烧掉唯一一次下载），
// 但完全不限的话，图片/音视频分享可以无限次取回完整字节，maxDownloads 形同虚设。
// 按 IP 记账（clientIP 已做转发头信任处理，伪造 XFF 打不进来）
func previewAllow(token, ip string) bool {
	key := token + "|" + ip
	previewMu.Lock()
	defer previewMu.Unlock()
	if len(previewDone) > previewMaxIP {
		previewDone = map[string]bool{} // 粗粒度兜底：极端情况下整体重置，不阻断服务
	}
	if previewDone[key] {
		return false
	}
	previewDone[key] = true
	return true
}

// previewGC 回收已不存在分享的预览记录（每小时清理任务调用）
func previewGC() {
	shareMu.Lock()
	defer shareMu.Unlock()
	previewMu.Lock()
	defer previewMu.Unlock()
	for k := range previewDone {
		i := strings.IndexByte(k, '|')
		if i <= 0 {
			delete(previewDone, k)
			continue
		}
		if _, ok := shares[k[:i]]; !ok {
			delete(previewDone, k)
		}
	}
}

// dlInFlight 每个 ticket 同时只允许一条「到文件末尾」的传输在途：
// 一次合法计次后并发 N 个 Range: bytes=1- 的请求在准入时都读到 Served < size，
// 全部放行会把一次下载放大成 N 次完整内容下发
func dlInFlightAdd(t string) bool {
	if t == "" {
		return true
	}
	dlInFlightMu.Lock()
	defer dlInFlightMu.Unlock()
	if dlInFlight[t] >= 1 {
		return false
	}
	dlInFlight[t]++
	return true
}

func dlInFlightDone(t string) {
	if t == "" {
		return
	}
	dlInFlightMu.Lock()
	if dlInFlight[t] > 0 {
		dlInFlight[t]--
	}
	if dlInFlight[t] == 0 {
		delete(dlInFlight, t)
	}
	dlInFlightMu.Unlock()
}

// sharesDirty 失败访问日志的延迟落盘标记：过期链接/密码错误等未认证的失败
// 请求每一次都全量重写 shares.json 是写放大（DoS + SSD 磨损），
// 改为内存累计 + 定期批量落盘
var sharesDirty int32

func markSharesDirty() { atomic.StoreInt32(&sharesDirty, 1) }

func startSharesFlush() {
	go func() {
		for range time.Tick(30 * time.Second) {
			if atomic.CompareAndSwapInt32(&sharesDirty, 1, 0) {
				saveShares()
			}
		}
	}()
}

// flushSharesOnExit 优雅关闭前把未落盘的日志刷出去
func flushSharesOnExit() {
	if atomic.CompareAndSwapInt32(&sharesDirty, 1, 0) {
		saveShares()
	}
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
