package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// 端到端用例：起真实 handler（httptest），走真实的登录/分享/目录/子路径解析路径。
// 上一版把登录页脚本外置后忘了把 /login.js 放进免密白名单，任何人打开登录页
// 都拿不到脚本、无法提交 —— 单元测试查不出这种「页面之间的依赖」，只能端到端测。

const (
	testUser = "tester"
	testPass = "pw12345"
)

// resetGlobals 复位包级全局：这些 map/flag 在一个进程里跨用例共享，
// 上一个用例留下的封禁记录、会话、分享会让下一个用例莫名失败
func resetGlobals(t *testing.T) (root, data string) {
	t.Helper()
	root, data = t.TempDir(), t.TempDir()
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	cfgMu.Lock()
	cfg = config{RootDir: abs}
	cfgMu.Unlock()
	flagDataDir = data
	flagUser, flagPass = testUser, testPass
	flagProxy, flagMaxMB, flagLog = false, 0, false
	trustedProxyNets = nil
	for _, k := range []string{"SESSION_DAYS", "TIDY_HOURS", "TRUSTED_PROXIES", "COOKIE_SECURE", "LOG", "TRUST_PROXY"} {
		os.Unsetenv(k)
	}
	shareMu.Lock()
	shares = map[string]*Share{}
	shareMu.Unlock()
	sessMu.Lock()
	sessions = map[string]*sessInfo{}
	sessMu.Unlock()
	authFailMu.Lock()
	authFails = map[string]*authAttempt{}
	authFailMu.Unlock()
	sharePwMu.Lock()
	sharePwFails = map[string]*sharePwFail{}
	sharePwMu.Unlock()
	dlTicketMu.Lock()
	dlTickets = map[string]dlTicketRec{}
	dlTicketMu.Unlock()
	previewMu.Lock()
	previewBytes = map[string]int64{}
	previewMu.Unlock()
	dlInFlightMu.Lock()
	dlInFlight = map[string]int{}
	dlInFlightMu.Unlock()
	return abs, data
}

func newServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	root, _ := resetGlobals(t)
	srv := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(srv.Close)
	return srv, root
}

// call 用 srv.Client() 真发一次请求（带 Basic 认证），返回状态码与响应体
func call(t *testing.T, srv *httptest.Server, method, path, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Body = io.NopCloser(strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(testUser+":"+testPass)))
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

// callRaw 不跟随重定向，用于断言 302 的目标
func callRaw(t *testing.T, srv *httptest.Server, method, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

type shareResp struct {
	Share struct {
		Token     string `json:"token"`
		Alias     string `json:"alias"`
		Site      bool   `json:"site"`
		IsDir     bool   `json:"isDir"`
		Downloads int    `json:"downloads"`
	} `json:"share"`
	URL string `json:"url"`
}

// createShare 通过管理端 API 建分享（顺便验证接口契约本身）
func createShare(t *testing.T, srv *httptest.Server, body string) shareResp {
	t.Helper()
	code, txt := call(t, srv, "POST", "/api/share", body)
	if code != 200 {
		t.Fatalf("建分享应 200，实际 %d：%s", code, txt)
	}
	var r shareResp
	if err := json.Unmarshal([]byte(txt), &r); err != nil {
		t.Fatalf("分享响应不是 JSON：%v / %s", err, txt)
	}
	if r.Share.Token == "" {
		t.Fatalf("响应里没有 token：%s", txt)
	}
	return r
}

func downloadsOf(t *testing.T, srv *httptest.Server, token string) int {
	t.Helper()
	code, txt := call(t, srv, "GET", "/api/shares", "")
	if code != 200 {
		t.Fatalf("列分享应 200，实际 %d", code)
	}
	var v struct {
		Shares []struct {
			Token     string `json:"token"`
			Downloads int    `json:"downloads"`
		} `json:"shares"`
	}
	if err := json.Unmarshal([]byte(txt), &v); err != nil {
		t.Fatal(err)
	}
	for _, s := range v.Shares {
		if s.Token == token {
			return s.Downloads
		}
	}
	t.Fatalf("分享列表里没有 %s", token)
	return -1
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// ---------------- 1. 登录可用性（v1.8.0 的自锁回归） ----------------

func TestLoginPageUsableWithoutAuth(t *testing.T) {
	srv, _ := newServer(t)

	// 登录页本身免密
	res, err := srv.Client().Get(srv.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("/login 免密应 200，实际 %d", res.StatusCode)
	}
	// 登录页引用的脚本必须同样免密可取，否则表单装不上提交逻辑
	// （v1.8.0 把内联脚本外置成 /login.js 时忘了放白名单，全站自锁）
	if !strings.Contains(string(page), `src="login.js"`) {
		t.Fatal("登录页没有引用 login.js，前端与鉴权白名单可能已脱节")
	}
	r2, err := srv.Client().Get(srv.URL + "/login.js")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, r2.Body)
	ct := r2.Header.Get("Content-Type")
	r2.Body.Close()
	if r2.StatusCode != 200 {
		t.Fatalf("未登录取 /login.js 必须 200，实际 %d", r2.StatusCode)
	}
	if !strings.Contains(ct, "javascript") {
		t.Fatalf("/login.js 的 Content-Type 应为 JS，实际 %q", ct)
	}
	// 管理端资源仍然要登录：不能为了修登录页把整站放开。
	// 用不跟随重定向的客户端 —— 默认的 srv.Client() 会把 302 跟到 /login 再报 200
	r3 := callRaw(t, srv, "GET", "/app.js")
	io.Copy(io.Discard, r3.Body)
	r3.Body.Close()
	if r3.StatusCode != http.StatusFound {
		t.Fatalf("未登录取 /app.js 应 302 到登录页，实际 %d", r3.StatusCode)
	}
}

func TestLoginFlowWithCookie(t *testing.T) {
	srv, _ := newServer(t)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	c := srv.Client()
	c.Jar = jar

	// 错口令
	_, body := callNoAuth(t, srv, `/api/login`, `{"user":"tester","pass":"wrong"}`)
	if !strings.Contains(body, "用户名或密码错误") {
		t.Fatalf("错口令应给出统一错误文案，实际：%s", body)
	}
	// 对口令
	code, body := callNoAuth(t, srv, `/api/login`, `{"user":"tester","pass":"`+testPass+`"}`)
	if code != 200 {
		t.Fatalf("正确口令登录应 200，实际 %d / %s", code, body)
	}
	// 带着会话 Cookie 访问管理接口与首页
	req, _ := http.NewRequest("GET", srv.URL+"/api/state", nil)
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("登录后 /api/state 应 200，实际 %d", res.StatusCode)
	}
	req2, _ := http.NewRequest("GET", srv.URL+"/", nil)
	res2, err := c.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := io.ReadAll(res2.Body)
	res2.Body.Close()
	if res2.StatusCode != 200 {
		t.Fatalf("登录后首页应 200，实际 %d", res2.StatusCode)
	}
	// 管理端页面必须能拿到它的脚本与样式（否则页面是空壳）
	for _, a := range []string{"/app.js", "/theme.js", "/style.css", "/qr.js"} {
		rq, _ := http.NewRequest("GET", srv.URL+a, nil)
		rs, err := c.Do(rq)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, rs.Body)
		rs.Body.Close()
		if rs.StatusCode != 200 {
			t.Fatalf("登录后 %s 应 200，实际 %d（管理页会缺资源）", a, rs.StatusCode)
		}
	}
	_ = b2
}

func TestStaticPageBruteForceIsCounted(t *testing.T) {
	srv, _ := newServer(t)
	// 静态页分支此前不记失败次数，是对 / 的无限口令预言机
	var last string
	for i := 0; i < 12; i++ {
		req, _ := http.NewRequest("GET", srv.URL+"/", nil)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(testUser+":guess"+string(rune('a'+i%26)))))
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		last = res.Status
	}
	// 计数生效后，同一 IP 在 /api 上应已被封（429）
	code, body := callNoAuth(t, srv, "/api/login", `{"user":"tester","pass":"`+testPass+`"}`)
	if code != http.StatusTooManyRequests {
		t.Fatalf("静态页爆破应触发按 IP 的封禁（登录返回 429），实际 %d / %s / 最后静态响应 %s", code, body, last)
	}
}

// ---------------- 2. 文件分享 ----------------

func TestFileShareDirectCounts(t *testing.T) {
	srv, root := newServer(t)
	writeFile(t, filepath.Join(root, "a.txt"), "hello-a")
	sh := createShare(t, srv, `{"path":"a.txt","expireSeconds":0,"maxDownloads":1,"scheme":"auto","host":"","mode":"direct","alias":"","hotlink":false,"password":""}`)
	tok := sh.Share.Token

	code, body := callRawGet(t, srv, "/s/"+tok)
	if code != 200 || body != "hello-a" {
		t.Fatalf("直链下载应拿到内容，实际 %d / %q", code, body)
	}
	if n := downloadsOf(t, srv, tok); n != 1 {
		t.Fatalf("应计 1 次，实际 %d", n)
	}
	// 配额用尽后再取应被拒
	code2, _ := callRawGet(t, srv, "/s/"+tok)
	if code2 != http.StatusForbidden {
		t.Fatalf("限 1 次的链接第二次应 403，实际 %d", code2)
	}
}

// callNoAuth 不带任何凭据发 POST（登录接口本身就是免密的）
func callNoAuth(t *testing.T, srv *httptest.Server, path, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest("POST", srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func callRawGet(t *testing.T, srv *httptest.Server, path string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", srv.URL+path, nil)
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func TestPasswordShareLeaksNoStateBeforeAuth(t *testing.T) {
	srv, root := newServer(t)
	writeFile(t, filepath.Join(root, "p.txt"), "secret-content")
	sh := createShare(t, srv, `{"path":"p.txt","expireSeconds":0,"maxDownloads":1,"scheme":"auto","host":"","mode":"page","alias":"","hotlink":false,"password":"pw123456"}`)
	tok := sh.Share.Token
	// 先用正确口令下一次，把配额打光
	if code, _ := callRawGet(t, srv, "/s/"+tok+"?pw=pw123456&dl=1"); code != 200 {
		t.Fatalf("带口令下载应 200，实际 %d", code)
	}
	// 不知道口令的人再来：只能看到密码页，不得泄露配额/文件状态
	code, body := callRawGet(t, srv, "/s/"+tok)
	if code != 200 {
		t.Fatalf("受保护链接在口令未知时应回密码页(200)，实际 %d", code)
	}
	if strings.Contains(body, "下载次数已用完") {
		t.Fatal("泄露了配额状态：不知道口令也能看到「下载次数已用完」")
	}
	if !strings.Contains(body, `name="pw"`) {
		t.Fatal("没有渲染密码输入框")
	}
	// 文件被删除时同理：必须先过口令才说「不存在」
	if err := os.Remove(filepath.Join(root, "p.txt")); err != nil {
		t.Fatal(err)
	}
	code2, body2 := callRawGet(t, srv, "/s/"+tok)
	if code2 != 200 || strings.Contains(body2, "文件已被删除") {
		t.Fatalf("未认证时不得泄露文件存在性，实际 %d / %q", code2, body2)
	}
}

func TestPreviewRangeBudgetBlocksFullRefetch(t *testing.T) {
	srv, root := newServer(t)
	writeFile(t, filepath.Join(root, "m.mp4"), strings.Repeat("x", 4096))
	sh := createShare(t, srv, `{"path":"m.mp4","expireSeconds":0,"maxDownloads":1,"scheme":"auto","host":"","mode":"page","alias":"","hotlink":false,"password":""}`)
	tok := sh.Share.Token
	// 预览不烧配额
	if code, _ := callRawGet(t, srv, "/s/"+tok+"?inline=1"); code != 200 {
		t.Fatalf("首次预览应 200，实际 %d", code)
	}
	// 带 Range 也不能绕过这道闸（v1.8.0 之前加个 Range: bytes=1- 就无限回捞）
	previewMu.Lock()
	previewBytes[tok+"|127.0.0.1"] = 4096 + previewSlack + 1 // 把额度打到用尽
	previewMu.Unlock()
	code, _ := callRawGet(t, srv, "/s/"+tok+"?inline=1")
	if code != http.StatusTooManyRequests {
		t.Fatalf("预览额度用尽后应 429，实际 %d", code)
	}
	if n := downloadsOf(t, srv, tok); n != 0 {
		t.Fatalf("预览不该计次，实际 %d", n)
	}
}

// ---------------- 3. 文件夹分享：列表 / 单文件 / 静态站点 ----------------

func TestDirShareListingAndSingleFile(t *testing.T) {
	srv, root := newServer(t)
	writeFile(t, filepath.Join(root, "share", "a.txt"), "AAA")
	writeFile(t, filepath.Join(root, "share", "sub", "b.txt"), "BBBBB")
	writeFile(t, filepath.Join(root, "share", ".trash", "gone.txt"), "GONE") // 回收站内容不外泄
	writeFile(t, filepath.Join(root, "share", ".fup-deadbeef.part"), "PART") // 半成品不外泄

	sh := createShare(t, srv, `{"path":"share","expireSeconds":0,"maxDownloads":3,"scheme":"auto","host":"","mode":"direct","alias":"","hotlink":false,"password":""}`)
	tok := sh.Share.Token
	if !sh.Share.IsDir {
		t.Fatal("分享响应里 isDir 应为 true，前端靠它决定是否显示「静态网页发布」")
	}

	// 目录链接缺尾斜杠 → 302 补上（页面里的相对路径才能解析）
	res := callRaw(t, srv, "GET", "/s/"+tok)
	defer res.Body.Close()
	if res.StatusCode != http.StatusFound || !strings.HasSuffix(res.Header.Get("Location"), tok+"/") {
		t.Fatalf("目录分享应 302 到带尾斜杠的地址，实际 %d -> %q", res.StatusCode, res.Header.Get("Location"))
	}

	// 列表页
	code, body := callRawGet(t, srv, "/s/"+tok+"/")
	if code != 200 || !strings.Contains(body, "text/html") && !strings.Contains(body, "<table") {
		t.Fatalf("目录列表页应 200 且含表格，实际 %d", code)
	}
	for _, want := range []string{"a.txt", "sub/", "打包下载"} {
		if !strings.Contains(body, want) {
			t.Fatalf("列表页缺少 %q", want)
		}
	}
	for _, forbidden := range []string{".trash", "gone.txt", ".fup-deadbeef", "PART"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("列表页不应出现 %q", forbidden)
		}
	}
	if n := downloadsOf(t, srv, tok); n != 0 {
		t.Fatalf("只看列表不该计次，实际 %d", n)
	}

	// 单个文件按需下载：计一次
	code2, body2 := callRawGet(t, srv, "/s/"+tok+"/a.txt")
	if code2 != 200 || body2 != "AAA" {
		t.Fatalf("单文件下载应拿到内容，实际 %d / %q", code2, body2)
	}
	// 子目录可继续浏览
	code3, body3 := callRawGet(t, srv, "/s/"+tok+"/sub/")
	if code3 != 200 || !strings.Contains(body3, "b.txt") {
		t.Fatalf("子目录列表应可浏览，实际 %d / %q", code3, body3)
	}
	// 子目录里的文件
	if code4, b4 := callRawGet(t, srv, "/s/"+tok+"/sub/b.txt"); code4 != 200 || b4 != "BBBBB" {
		t.Fatalf("子目录文件下载失败：%d / %q", code4, b4)
	}
	if n := downloadsOf(t, srv, tok); n != 2 {
		t.Fatalf("取了两个文件应计 2 次，实际 %d", n)
	}
	// 整包 zip 仍可用（再计一次），且超限后目录依然可浏览
	if code5, _ := callRawGet(t, srv, "/s/"+tok+"/?dl=1"); code5 != 200 {
		t.Fatalf("打包下载应 200，实际 %d", code5)
	}
	if n := downloadsOf(t, srv, tok); n != 3 {
		t.Fatalf("打包后再计一次应为 3，实际 %d", n)
	}
	// 配额耗尽：列表仍可看，文件取用被拒
	if code6, _ := callRawGet(t, srv, "/s/"+tok+"/"); code6 != 200 {
		t.Fatalf("配额用尽后目录列表仍应可浏览，实际 %d", code6)
	}
	if code7, _ := callRawGet(t, srv, "/s/"+tok+"/a.txt"); code7 != http.StatusForbidden {
		t.Fatalf("配额用尽后取文件应 403，实际 %d", code7)
	}
}

func TestDirShareSiteMode(t *testing.T) {
	srv, root := newServer(t)
	writeFile(t, filepath.Join(root, "site", "index.html"),
		`<!DOCTYPE html><html><head><link rel="stylesheet" href="style.css"></head><body><h1 id="t">静态站</h1><script>document.getElementById("t").textContent="ok";</script></body></html>`)
	writeFile(t, filepath.Join(root, "site", "style.css"), "h1{color:red}")
	writeFile(t, filepath.Join(root, "site", "img", "logo.svg"), "<svg/>")

	sh := createShare(t, srv, `{"path":"site","expireSeconds":0,"maxDownloads":1,"scheme":"auto","host":"","mode":"direct","alias":"","hotlink":false,"password":"","site":true}`)
	tok := sh.Share.Token
	if !sh.Share.Site {
		t.Fatal("site 字段没有回显，创建接口或响应结构脱节")
	}
	code, body := callRawGet(t, srv, "/s/"+tok+"/")
	if code != 200 || !strings.Contains(body, "静态站") {
		t.Fatalf("站点模式应直接渲染 index.html，实际 %d / %q", code, body)
	}
	// 子资源按相对路径可取（页面里 href="style.css" → /s/<tok>/style.css）
	if c2, b2 := callRawGet(t, srv, "/s/"+tok+"/style.css"); c2 != 200 || b2 != "h1{color:red}" {
		t.Fatalf("站点子资源取不到：%d / %q", c2, b2)
	}
	if c3, _ := callRawGet(t, srv, "/s/"+tok+"/img/logo.svg"); c3 != 200 {
		t.Fatalf("站点深层子资源取不到：%d", c3)
	}
	// 浏览与资源加载一律不计次：maxDownloads=1 也还能继续看
	if n := downloadsOf(t, srv, tok); n != 0 {
		t.Fatalf("站点浏览不该计次，实际 %d", n)
	}
	// 页面响应里 CSP 放开了内联脚本（否则「丢个页面」直接白屏），但仍禁止被嵌套。
	// 要看响应头，body 里查不出来
	cspReq, _ := http.NewRequest("GET", srv.URL+"/s/"+tok+"/", nil)
	cspRes, err := srv.Client().Do(cspReq)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, cspRes.Body)
	pageCSP := cspRes.Header.Get("Content-Security-Policy")
	cspRes.Body.Close()
	if !strings.Contains(pageCSP, "script-src 'self' 'unsafe-inline'") {
		t.Fatalf("站点页面的 CSP 没有放开内联脚本，页内 <script> 会被拦：%q", pageCSP)
	}
	if !strings.Contains(pageCSP, "frame-ancestors 'none'") {
		t.Fatalf("站点页面仍应禁止被嵌套：%q", pageCSP)
	}
	// 显式下载仍然计次并受 maxDownloads 约束
	if c4, _ := callRawGet(t, srv, "/s/"+tok+"/style.css?dl=1"); c4 != 200 {
		t.Fatalf("站点内显式下载应 200，实际 %d", c4)
	}
	if c5, _ := callRawGet(t, srv, "/s/"+tok+"/style.css?dl=1"); c5 != http.StatusForbidden {
		t.Fatalf("限 1 次用完后显式下载应 403，实际 %d", c5)
	}
}

func TestSiteFlagRejectedForFile(t *testing.T) {
	srv, root := newServer(t)
	writeFile(t, filepath.Join(root, "f.txt"), "x")
	code, body := call(t, srv, "POST", "/api/share", `{"path":"f.txt","expireSeconds":0,"maxDownloads":0,"scheme":"auto","host":"","mode":"direct","alias":"","hotlink":false,"password":"","site":true}`)
	if code != 400 || !strings.Contains(body, "文件夹") {
		t.Fatalf("文件分享开站点应被拒绝并说明原因，实际 %d / %s", code, body)
	}
}

func TestShareSubpathEscapeBlocked(t *testing.T) {
	srv, root := newServer(t)
	writeFile(t, filepath.Join(root, "pub", "ok.txt"), "OK")
	writeFile(t, filepath.Join(root, "private.txt"), "PRIV")
	sh := createShare(t, srv, `{"path":"pub","expireSeconds":0,"maxDownloads":0,"scheme":"auto","host":"","mode":"direct","alias":"","hotlink":false,"password":""}`)
	tok := sh.Share.Token

	for _, bad := range []string{
		"/s/" + tok + "/../private.txt",
		"/s/" + tok + "/%2e%2e/private.txt",
		"/s/" + tok + "/..%2fprivate.txt",
		"/s/" + tok + "/a/../../private.txt",
	} {
		code, body := callRawGet(t, srv, bad)
		if strings.Contains(body, "PRIV") {
			t.Fatalf("子路径越界拿到了分享外的内容：%s -> %q", bad, body)
		}
		if code == 200 {
			t.Fatalf("越界路径应被拒绝，却返回 200：%s", bad)
		}
	}
	if code, body := callRawGet(t, srv, "/s/"+tok+"/ok.txt"); code != 200 || body != "OK" {
		t.Fatalf("正常子路径应可下载：%d / %q", code, body)
	}
}

func TestShareSubpathSymlinkEscapeBlocked(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 上创建符号链接需要特权")
	}
	srv, root := newServer(t)
	shared := filepath.Join(root, "pub")
	outside := filepath.Join(t.TempDir(), "secret")
	writeFile(t, filepath.Join(shared, "keep.txt"), "KEEP")
	writeFile(t, outside, "OUTSIDE")
	if err := os.MkdirAll(filepath.Join(shared), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(shared, "link")); err != nil {
		t.Skipf("无法创建符号链接：%v", err)
	}
	sh := createShare(t, srv, `{"path":"pub","expireSeconds":0,"maxDownloads":0,"scheme":"auto","host":"","mode":"direct","alias":"","hotlink":false,"password":"","site":true}`)
	tok := sh.Share.Token
	code, body := callRawGet(t, srv, "/s/"+tok+"/link")
	if strings.Contains(body, "OUTSIDE") {
		t.Fatal("借分享目录内的符号链接读到了分享外的文件")
	}
	if code == 200 {
		t.Fatalf("符号链接越界应被拒绝，实际 200 / %q", body)
	}
	// 正常文件不受影响
	if c2, b2 := callRawGet(t, srv, "/s/"+tok+"/keep.txt"); c2 != 200 || b2 != "KEEP" {
		t.Fatalf("正常子路径受影响：%d / %q", c2, b2)
	}
}

// ---------------- 4. 上一轮安全修复的回归护栏 ----------------

func TestTrustedProxyPeerOnlyLoopbackByDefault(t *testing.T) {
	if !isTrustedProxyPeer("127.0.0.1") {
		t.Fatal("环回应可信（同机反代）")
	}
	// 曾经的判据是「内网地址就算可信代理」，配上出厂 TRUST_PROXY=1，
	// docker 网桥来源能让客户端自己声明 X-Real-IP
	for _, ip := range []string{"172.17.0.1", "192.168.1.10", "10.0.0.5"} {
		if isTrustedProxyPeer(ip) {
			t.Fatalf("未显式配置的 %s 不应被当成可信代理", ip)
		}
	}
	trustedProxyNets = parseTrustedProxies("172.17.0.1/32, 10.0.0.0/8")
	defer func() { trustedProxyNets = nil }()
	if !isTrustedProxyPeer("172.17.0.1") || !isTrustedProxyPeer("10.1.2.3") {
		t.Fatal("TRUSTED_PROXIES 列出的网段应可信")
	}
	if isTrustedProxyPeer("8.8.8.8") {
		t.Fatal("公网地址不应被放行")
	}
}

func TestSessionTTLClamped(t *testing.T) {
	// 越界值回落默认（7 天）并告警：0 会让会话「刚签发即过期」，
	// 极大值会让 Duration 溢出回绕成不可预测值
	os.Setenv("SESSION_DAYS", "0")
	defer os.Unsetenv("SESSION_DAYS")
	if d := sessionTTL(); d != 7*24*time.Hour {
		t.Fatalf("SESSION_DAYS=0 应回落默认 7 天，实际 %v", d)
	}
	os.Setenv("SESSION_DAYS", "999999999999")
	if d := sessionTTL(); d != 7*24*time.Hour {
		t.Fatalf("SESSION_DAYS 极大值应回落默认 7 天，实际 %v", d)
	}
	os.Setenv("SESSION_DAYS", "30")
	if d := sessionTTL(); d != 30*24*time.Hour {
		t.Fatalf("区间内的值应原样生效，实际 %v", d)
	}
}

func TestEnvBoolAcceptsWords(t *testing.T) {
	os.Setenv("LOG", "on")
	defer os.Unsetenv("LOG")
	if !envBool("LOG", false) {
		t.Fatal("LOG=on 应识别为真（旧实现把不认识的写法一律当 false）")
	}
	os.Setenv("LOG", "banana")
	if !envBool("LOG", true) {
		t.Fatal("无法识别的值应回落默认值而不是静默关闭")
	}
}

func TestPwHashRejectsEmptySaltOrKey(t *testing.T) {
	// 解析器若不拒绝空段，ConstantTimeCompare 对两个空切片返回「相等」= 任意口令通过
	for _, rec := range []string{"pbkdf2$1000$$", "pbkdf2$1000$00$", "pbkdf2$0$00$00", "pbkdf2$x$00$00"} {
		if ok, _ := verifyPwHash(nsAuth, "anything", rec); ok {
			t.Fatalf("畸形哈希记录 %q 竟通过了校验", rec)
		}
	}
	if ok, _ := verifyPwHash(nsAuth, "anything", "pbkdf2$999999999$00$00"); ok {
		t.Fatal("超上限的迭代次数应拒绝校验（否则 CPU 消耗由写文件的人决定）")
	}
}

func TestPreviewByteBudget(t *testing.T) {
	keyTok, keyIP := "tk", "ip"
	if !previewAllow(keyTok, keyIP, 100) {
		t.Fatal("初始应有额度")
	}
	previewCharge(keyTok, keyIP, 100)
	if !previewAllow(keyTok, keyIP, 100) {
		t.Fatal("恰好等于文件大小后应拒绝")
	}
	previewCharge(keyTok, keyIP, previewSlack)
	if previewAllow(keyTok, keyIP, 100) {
		t.Fatal("超出文件长度 + slack 后应拒绝")
	}
}

func TestRenameExclusiveDoesNotOverwrite(t *testing.T) {
	dir := t.TempDir()
	src1 := filepath.Join(dir, "s1")
	src2 := filepath.Join(dir, "s2")
	writeFile(t, src1, "one")
	writeFile(t, src2, "two")
	// 先放一个同名真实文件：第二次改名绝不能把它顶掉（Linux 上 os.Rename 会静默覆盖）
	writeFile(t, filepath.Join(dir, "target"), "EXISTING")

	alt := func(i int) string {
		if i == 0 {
			return "target"
		}
		return "target(1)"
	}
	got1, err := renameExclusive(dir, alt, src1)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got1) != "target(1)" {
		t.Fatalf("target 已被占用，应顺延到 target(1)，实际 %s", got1)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "target")); string(b) != "EXISTING" {
		t.Fatalf("原有文件被覆盖了：%q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "target(1)")); string(b) != "one" {
		t.Fatalf("新文件内容不对：%q", b)
	}
	// 目录占用同名时同样顺延（Windows 上给出的是 ACCESS_DENIED 而非 EEXIST）
	writeFile(t, src2, "two")
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	got2, err := renameExclusive(dir, func(i int) string {
		if i == 0 {
			return "d"
		}
		return "d(1)"
	}, src2)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got2) != "d(1)" {
		t.Fatalf("同名目录应顺延，实际 %s", got2)
	}
	// 名字空出来时就用原名
	got3, err := renameExclusive(dir, func(i int) string { return "free" }, src1+".none")
	if err == nil {
		t.Fatalf("源不存在时应报错，不该改名成功：%s", got3)
	}
}

func TestTidyGraceClamped(t *testing.T) {
	os.Setenv("TIDY_HOURS", "99999999999999")
	defer os.Unsetenv("TIDY_HOURS")
	cfgMu.Lock()
	cfg.TidyHours = 0
	cfgMu.Unlock()
	if g := tidyGrace(); g <= 0 || g > 8760 {
		// 溢出成负数会让 cutoff 落到未来，一次清理就删光所有带到期时间的分享
		t.Fatalf("TIDY_HOURS 极大值应被钳制，实际 %d", g)
	}
}

// ---------------- 5. WebDAV 语义 ----------------

func TestDavPropfindDepth(t *testing.T) {
	srv, root := newServer(t)
	writeFile(t, filepath.Join(root, "d1", "a.txt"), "A")
	writeFile(t, filepath.Join(root, "d1", "d2", "b.txt"), "B")

	count := func(depth string) int {
		req, _ := http.NewRequest("PROPFIND", srv.URL+"/dav/d1/", nil)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(testUser+":"+testPass)))
		if depth != "" {
			req.Header.Set("Depth", depth)
		}
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		if depth == "2" {
			return res.StatusCode
		}
		return strings.Count(string(b), "<D:response>")
	}
	if n := count("0"); n != 1 {
		t.Fatalf("Depth:0 应只有 1 条，实际 %d", n)
	}
	if n := count("1"); n != 3 {
		t.Fatalf("Depth:1 应为 目录+a.txt+d2 = 3 条，实际 %d", n)
	}
	// 缺省按 RFC 视为 infinity；旧实现把 infinity 静默当 1 层，
	// 同步类客户端会把没列出来的当成服务端没有的
	if n := count(""); n != 4 {
		t.Fatalf("缺省 Depth 应递归到 4 条，实际 %d", n)
	}
	if n := count("infinity"); n != 4 {
		t.Fatalf("Depth:infinity 应递归到 4 条，实际 %d", n)
	}
	if c := count("2"); c != http.StatusBadRequest {
		t.Fatalf("非法 Depth 应 400，实际 %d", c)
	}
}

func TestDavDestinationValidation(t *testing.T) {
	srv, root := newServer(t)
	writeFile(t, filepath.Join(root, "mv.txt"), "M")
	// /davx.txt 越过命名空间边界：不能被当成 /dav/x.txt
	req, _ := http.NewRequest("MOVE", srv.URL+"/dav/mv.txt", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(testUser+":"+testPass)))
	req.Header.Set("Destination", srv.URL+"/davx.txt")
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode == http.StatusCreated || res.StatusCode == http.StatusNoContent {
		t.Fatal("Destination 越出 /dav 命名空间却被接受了")
	}
	if _, err := os.Stat(filepath.Join(root, "mv.txt")); err != nil {
		t.Fatal("被拒绝的移动不该已经把源文件挪走")
	}
	// 外部主机
	req2, _ := http.NewRequest("MOVE", srv.URL+"/dav/mv.txt", nil)
	req2.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(testUser+":"+testPass)))
	req2.Header.Set("Destination", "http://evil.example/dav/x.txt")
	res2, err := srv.Client().Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	res2.Body.Close()
	if res2.StatusCode == http.StatusCreated || res2.StatusCode == http.StatusNoContent {
		t.Fatal("Destination 指向外部主机却被当成局部路径")
	}
}
