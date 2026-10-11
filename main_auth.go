package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

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

type authAttempt struct {
	count        int
	windowStart  int64
	blockedUntil int64
}

func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = h
	}
	// X-Forwarded-For 可被任意客户端伪造。仅当直连来源本身是环回或内网地址时
	// （即确实处在反向代理之后）才采信，否则端口直接暴露在公网时
	// 伪造 XFF 就能绕过防爆破并污染访问日志。
	if flagProxy && isTrustedProxyPeer(host) {
		// 优先取可信反代覆盖设置的 X-Real-IP（deploy/nginx.conf 有配）
		if h := r.Header.Get("X-Real-IP"); h != "" {
			if ip := net.ParseIP(strings.TrimSpace(h)); ip != nil {
				return ip.String()
			}
		}
		// XFF 是追加式链：首段是客户端可任意伪造的（每次请求换个假 IP
		// 就能绕开按 IP 记账的防爆破），真实来源是可信代理自己追加的末段
		if h := r.Header.Get("X-Forwarded-For"); h != "" {
			parts := strings.Split(h, ",")
			if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
				return ip.String()
			}
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
	if err := json.Unmarshal(b, &m); err != nil || m == nil {
		log.Printf("[持久化] sessions.json 解析失败（%v），忽略", err)
		return
	}
	// "token": null 的条目在遍历时解引用会直接 panic（服务拒绝启动），
	// 与 loadShares 同样在加载期剔除
	for k, s := range m {
		if s == nil {
			delete(m, k)
		}
	}
	sessions = m
	// 清掉已过期的历史会话
	now := time.Now().UnixMilli()
	sessMu.Lock()
	for k, s := range sessions {
		if s == nil {
			delete(sessions, k)
			continue
		}
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
	defer sessMu.Unlock()
	b, err := json.MarshalIndent(sessions, "", "  ")
	if err != nil {
		log.Printf("[持久化] sessions 序列化失败: %v", err)
		return
	}
	if err := atomicWriteFile(dataPath("sessions.json"), b, 0o600); err != nil {
		log.Printf("[持久化] sessions.json 写盘失败: %v", err)
	}
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
	if !ok || s == nil {
		if ok {
			delete(sessions, token)
		}
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
		// 与 /api 同一防爆破命名空间：旧的提前 return 让 /dav 完全绕过
		// 封禁与失败计数，可以无限爆破密码（且每次失败都烧一轮 PBKDF2）
		ip := clientIP(r)
		if ms := banRemaining(ip); ms > 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(ms/1000+1, 10))
			w.Header().Set("WWW-Authenticate", `Basic realm="fileserver", charset="UTF-8"`)
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"error": fmt.Sprintf("失败次数过多，该 IP 已被临时封禁，请 %d 分钟后再试", ms/60000+1),
			})
			return false
		}
		if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" && validSession(c.Value) {
			return true
		}
		u, pw, hasBasic := r.BasicAuth()
		if hasBasic &&
			subtle.ConstantTimeCompare([]byte(u), []byte(flagUser)) == 1 &&
			checkPass(pw) {
			return true
		}
		if hasBasic {
			recordAuthFail(ip)
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="fileserver", charset="UTF-8"`)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "WebDAV 需要登录（用户名/密码同管理端）"})
		return false
	}
	// 分享链接、健康检查免密；登录流程自身免密
	if strings.HasPrefix(p, "/s/") || p == "/healthz" ||
		p == "/login" || p == "/api/login" || p == "/api/logout" {
		return true
	}
	// 管理界面与静态资源：未登录一律 302 到登录页。
	// 旧实现页面壳公开——虽然数据全走 API，但后台的菜单结构、按钮布局、
	// 全部 API 端点都写在 index.html 与 app.js 里，等于向未登录访客
	// 公开管理界面的完整轮廓，也方便攻击者按图索骥。现与登录页统一：
	// 未登录只能看到 /login
	if !strings.HasPrefix(p, "/api/") {
		ip := clientIP(r)
		if ms := banRemaining(ip); ms > 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(ms/1000+1, 10))
			http.Redirect(w, r, "/login", http.StatusFound)
			return false
		}
		if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" && validSession(c.Value) {
			return true
		}
		u, pw, hasBasic := r.BasicAuth()
		if hasBasic &&
			subtle.ConstantTimeCompare([]byte(u), []byte(flagUser)) == 1 &&
			checkPass(pw) {
			return true
		}
		http.Redirect(w, r, "/login", http.StatusFound)
		return false
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

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		User string `json:"user"`
		Pass string `json:"pass"`
	}
	if err := decodeStrict(w, r, &body); err != nil {
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
		if s == nil {
			continue
		}
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
	if err := decodeStrict(w, r, &body); err != nil || strings.TrimSpace(body.ID) == "" {
		writeJSON(w, 400, map[string]any{"error": "请求参数错误"})
		return
	}
	// 会话 ID 是 token 前 12 位：必须完整传入并精确匹配。
	// 无长度约束的前缀匹配会踢中不确定目标（id="1" 命中第一个前缀相符者），
	// 若先命中当前会话还会反把自己踢下线的请求挡回 400
	if len(body.ID) != 12 {
		writeJSON(w, 400, map[string]any{"error": "会话 ID 不合法（需完整 12 位）"})
		return
	}
	cur := ""
	if c, err := r.Cookie(sessionCookie); err == nil {
		cur = c.Value
	}
	sessMu.Lock()
	found := ""
	ambiguous := false
	for tok := range sessions {
		if len(tok) >= 12 && tok[:12] == body.ID {
			if found != "" {
				ambiguous = true
				break
			}
			found = tok
		}
	}
	if ambiguous {
		sessMu.Unlock()
		writeJSON(w, 409, map[string]any{"error": "会话 ID 冲突，请刷新后重试"})
		return
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
	if err := decodeStrict(w, r, &body); err != nil {
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
