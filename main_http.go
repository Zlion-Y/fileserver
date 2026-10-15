package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

func handler(w http.ResponseWriter, r *http.Request) {
	// 安全响应头必须在鉴权之前设置：401/429/413 这类错误响应同样
	// 不能缺 nosniff/CSP/HSTS（旧实现先 checkAuth 后设头，错误响应全裸奔）
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	// CSP：前端仅引用同源资源 + 内联样式（登录页 <style> 块与少量 style 属性）+
	// favicon data: URL；归属地查询在服务端完成，浏览器端无外部请求。
	// script-src 不再包含 'unsafe-inline'：两处内联脚本（主题预执行、登录提交）
	// 已外置为 theme.js / login.js，全仓也没有内联事件属性（onclick= 计数为 0）。
	// 留着 'unsafe-inline' 就等于把 CSP 的 XSS 兜底作用整体作废
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; "+
			"script-src 'self'; "+
			"style-src 'self' 'unsafe-inline'; "+
			"img-src 'self' data:; "+
			"connect-src 'self'; "+
			"font-src 'self'; "+
			"media-src 'self'; "+
			"object-src 'none'; "+
			"base-uri 'self'; "+
			"form-action 'self'; "+
			"frame-ancestors 'none'")
	// HSTS 仅在确认客户端走 HTTPS 时下发（反代终止 TLS 的场景）；
	// 纯 HTTP 内网部署时下发也会被浏览器忽略，但不加更严谨。
	// 不带 includeSubDomains：同主域其他子站未必启用 HTTPS，避免误伤。
	if clientScheme(r) == "https" {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	}
	// 访问日志必须在 checkAuth 之前注册：否则 401/429/302 这些拒绝响应
	// 全部不留痕——而爆破尝试、封禁触发恰好是防爆破与归属地功能最需要审计的事件。
	// 且必须记 clientIP(r) 而不是 RemoteAddr：开了 trust-proxy 后
	// 每一行记的都是代理自己的 IP，日志彻底失去定位价值
	if flagLog {
		defer func() {
			log.Printf("%s %s %s", r.Method, r.URL.Path, clientIP(r))
		}()
	}
	if !checkAuth(w, r) {
		return
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
		// 清除用的属性要和签发时一致（Path=/、HttpOnly、SameSite、Secure），
		// 否则部分浏览器按属性匹配删除，清不掉旧 cookie
		http.SetCookie(w, &http.Cookie{
			Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: true, SameSite: http.SameSiteLaxMode,
			Secure: clientScheme(r) == "https",
		})
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
		if err := decodeStrict(w, r, &body); err != nil {
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
	case p == "/api/uapikey" && r.Method == http.MethodGet:
		// 回显只给打码值，完整 key 不出服务器；环境变量 UAPI_KEY 已设置时提示前端
		envSet := os.Getenv("UAPI_KEY") != ""
		key := uapiKey()
		writeJSON(w, 200, map[string]any{"fromEnv": envSet, "masked": maskKey(key)})
	case p == "/api/uapikey" && r.Method == http.MethodPost:
		var body struct {
			Key string `json:"key"`
		}
		if err := decodeStrict(w, r, &body); err != nil {
			writeJSON(w, 400, map[string]any{"error": "请求参数错误: " + err.Error()})
			return
		}
		key := strings.TrimSpace(body.Key)
		if len(key) > 256 {
			writeJSON(w, 400, map[string]any{"error": "Key 过长（最多 256 字符）"})
			return
		}
		cfgMu.Lock()
		cfg.UapiKey = key
		cfgMu.Unlock()
		saveConfig()
		writeJSON(w, 200, map[string]any{"ok": true, "masked": maskKey(key)})
	case p == "/api/selfupdate" && r.Method == http.MethodPost:
		// 非发布版本（dev/容器构建）一律拒绝在线更新：容器里替换二进制
		// 跑的是镜像外文件，重建即回滚，版本不可复现（与 Dockerfile 注释对齐）
		if !isReleaseVersion() {
			writeJSON(w, 400, map[string]any{"error": "当前为非发布版本（dev/容器构建），一键更新不可用，请通过镜像或重新构建升级"})
			return
		}
		// multipart = 手动上传更新包（服务器连不上 GitHub 时的本地替代路径）
		if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
			handleSelfUpdateUpload(w, r)
			return
		}
		var body struct {
			To string `json:"to"` // 可选：指定目标版本（如 v1.0.4），空 = 最新
		}
		if err := decodeStrict(w, r, &body); err != nil {
			writeJSON(w, 400, map[string]any{"error": "请求参数错误: " + err.Error()})
			return
		}
		epoch, okUpd := updAcquire()
		if !okUpd {
			s, _, _, _ := getUpd()
			writeJSON(w, http.StatusConflict, map[string]any{"error": "已有更新任务在进行中（" + s + "）"})
			return
		}
		go runSelfUpdate(epoch, strings.TrimSpace(body.To))
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
			// 显式带 used：前端若用 total-free 反推已用，会把文件系统给 root
			// 预留的块也算成已用（ext4 默认 5%），磁盘水位显示偏高且各文件系统不一致
			if total, free, used, err := diskUsage(rootDir); err == nil {
				out["disk"] = map[string]int64{"total": total, "free": free, "used": used}
			}
		}
		writeJSON(w, 200, out)

	// 设置 / 修改根目录
	case p == "/api/config" && r.Method == http.MethodPost:
		var body struct {
			RootDir string `json:"rootDir"`
		}
		if err := decodeStrict(w, r, &body); err != nil {
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
		case p == "/api/ipgeo":
			handleIPGeo(w, r)
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

func decodeStrict(w http.ResponseWriter, r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		log.Printf("[参数] 请求体解析失败（%s %s）: %v", r.Method, r.URL.Path, err)
		return errBadBody
	}
	// 只允许单个 JSON 值：{"a":1} 垃圾数据 / 拼接的第二个对象同样拒绝
	if dec.More() {
		log.Printf("[参数] 请求体含多余数据（%s %s）", r.Method, r.URL.Path)
		return errBadBody
	}
	return nil
}

// errBadBody 请求体解析失败时对客户端返回的统一文案
var errBadBody = errors.New("请求体格式错误")
