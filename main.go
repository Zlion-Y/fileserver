package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
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
	version   = "1.7.0"
	commit    = "unknown" // 构建时由 -ldflags 注入
	buildTime = "unknown"
	// changelogB64 当前版本更新日志（base64）。CI 构建时把上一 tag 到本 tag 的
	// 提交清单编码后注入：base64 纯 ASCII，规避 -X 对换行/引号/中文的解析问题；
	// 运行期在 versionJSON 内解码。注入后「检查更新」页离线也能展示更新内容
	changelogB64 = ""
)

// builtinChangelog 解码构建时注入的更新日志；空串表示未注入（本地构建/容器）
const (
	updateRepo     = "Zlion-Y/fileserver"
	updateCacheTTL = 10 * 60 * 1000 // 检查结果缓存 10 分钟
	updateTimeout  = 6 * time.Second

	// uploadSlackBytes 上传请求整体 body 相对「单文件上限」的余量：
	// 留给 multipart 边界、其它表单字段与多文件场景的开销
	uploadSlackBytes = 8 << 20 // 8MB
)

var (
	updCache     ghRelease
	updCheckedAt int64
	updMu        sync.Mutex

	notesCache = map[string]string{} // tag -> Release 说明
	notesMu    sync.Mutex
)

// verNums 把 "v1.2.3" 解析成 [1,2,3]（无法解析的段按 0 处理）
var (
	updStatusMu sync.Mutex
	updStatus   = "idle"
	updMsg      = ""
	updBusy     int32
	updCancel   int32 // 置 1 请求取消（仅 downloading 阶段有效）
	updDone     int64 // 已下载字节数
	updTotal    int64 // 总字节数（Content-Length；未知为 -1）
)

const (
	pbkdf2Prefix = "pbkdf2$"
	authIter     = 100000 // 管理端密码：登录频率极低，可以用较高迭代
	shareIter    = 50000  // 分享密码：每次下载都要校验，路由器等弱设备上适度下调
	// 各命名空间前缀，避免管理密码与分享密码的存储串可互换
	nsAuth  = "fs-auth:"
	nsShare = "fs-pw:"
)

// pbkdf2Key 标准 PBKDF2(HMAC-SHA256) 实现
var (
	masterKeyOnce sync.Once
	masterKeyVal  []byte
	masterKeyErr  error
)

// pwMasterKey 返回分享密码加密主密钥：优先 FS_MASTER_KEY 环境变量，
// 否则在 data 目录维护一个 0600 的随机密钥文件
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
		// 与 clientIP 同一信任模型：仅当直连来源本身是可信代理时才采信
		// 转发头，否则任何人都能用 X-Forwarded-Host 把钓鱼域名拼进分享链接
		host := r.RemoteAddr
		if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			host = h
		}
		if isTrustedProxyPeer(host) {
			if h := r.Header.Get("X-Forwarded-Host"); h != "" {
				h = strings.TrimSpace(strings.Split(h, ",")[0])
				// host 会原样拼进 URL，含分隔符/空白即可注入，一律拒收
				if h != "" && !strings.ContainsAny(h, " \t/\\?#@") {
					return h
				}
			}
		}
	}
	return r.Host
}

// ---------------- 认证 ----------------

// ---------- 防爆破：失败超限封禁 IP ----------
var (
	authFails  = map[string]*authAttempt{}
	authFailMu sync.Mutex
)

const (
	failWindowMs  = 5 * 60 * 1000  // 统计窗口：5 分钟
	failMaxTries  = 10             // 窗口内最多失败次数
	banDurationMs = 15 * 60 * 1000 // 封禁时长：15 分钟
)

// clientIP 取真实来源 IP（反代模式下优先 X-Real-IP，其次 XFF 末段）
var (
	sessMu   sync.Mutex
	sessions = map[string]*sessInfo{}
)

const (
	dlTicketCookie = "fs_dl"       // Cookie 名（Path 按 /s/<token> 精确限定，互不干扰）
	dlTicketTTL    = 6 * time.Hour // ticket 有效期：够长时间断点续传，又不至于永久有效
)

var (
	dlTicketMu sync.Mutex
	dlTickets  = map[string]dlTicketRec{}
)

// newDlTicket 签发随机 ticket 并绑定分享 token
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
const (
	uploadTempPrefix = ".fup-"
	uploadTempSuffix = ".part"
	uploadChunkMax   = 64 << 20 // 单片上限 64MB，防恶意大 body
	uploadTempTTL    = 24 * time.Hour
)

var (
	upSessMu  sync.Mutex
	upSessMap = map[string]*uploadSession{}
)

const (
	geoOKTTL  = 7 * 24 * time.Hour // 成功结果：归属地极少变动，缓存一周
	geoBadTTL = 10 * time.Minute   // 失败结果：短缓存，避免每次打开日志都重试上游
	geoMaxIPs = 4 * 1024           // 缓存条目上限，超出时顺手清掉过期项
)

var (
	geoMu     sync.Mutex
	geoCache  = map[string]ipGeoEntry{}
	geoClient = &http.Client{Timeout: 5 * time.Second}
	// 上游限流：带 Key QPS 7、访客 QPS 4。批量查询虽并发封顶 4，但上游延迟
	// 仅 ~300ms 时实际可达 ~13 req/s，会触发 429 且结果被当成失败缓存 10 分钟。
	// 全局节流：相邻两次上游请求的「发起时刻」至少间隔如下，均留有余量
	geoRateMu    sync.Mutex
	geoNextStart time.Time
)

const (
	geoIntervalKeyed   = 180 * time.Millisecond // 有 Key：≤5.5 req/s（限 7）
	geoIntervalVisitor = 300 * time.Millisecond // 访客：≤3.3 req/s（限 4）
)

// throttleGeo 全局节流：为本次上游调用排定不早于 geoNextStart 的发起时刻并等待
var (
	sharePwMu    sync.Mutex
	sharePwFails = map[string]*sharePwFail{} // key: token|ip
)

const (
	sharePwWindowMs = 10 * 60 * 1000
	sharePwMaxFails = 5
	sharePwBlockMs  = 15 * 60 * 1000
)

var (
	previewMu    sync.Mutex
	previewDone  = map[string]bool{}
	previewFull  = errors.New("完整预览已获取过，请通过下载按钮获取文件")
	previewMaxIP = 8192 // 防 map 无限增长的上限
)

var (
	dlInFlightMu sync.Mutex
	dlInFlight   = map[string]int{}
)

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

	// 鉴权组合的启动即校验：只设用户名不设密码 = 空密码即可登录（等于没设认证）；
	// 只设密码不设用户名 = checkAuth 对空用户名直接放行，全 API 裸奔。
	// 与其带着虚假的「认证已开启」横幅上线，不如拒绝启动并说清楚。
	// 注意放在 loadConfig 之后：网页改过密（config.json 有哈希）时允许 -pass 留空
	loadConfig()
	loadShares()
	loadSessions()
	if flagUser != "" && flagPass == "" && authRecord() == "" {
		fmt.Println("错误：设置了 -user/AUTH_USER 但没有设置 -pass/AUTH_PASS，空密码即可登录。")
		fmt.Println("      请补齐密码，或同时去掉两者以明确关闭认证。")
		os.Exit(1)
	}
	if flagUser == "" && flagPass != "" {
		fmt.Println("错误：只设置了 -pass/AUTH_PASS 而未设置 -user/AUTH_USER，认证不会生效。")
		fmt.Println("      请同时设置两者。")
		os.Exit(1)
	}
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

	startBanGC()       // 认证失败记录的定期清理
	startTidy()        // 过期分享记录的定期清理
	startSharesFlush() // 失败访问日志的批量落盘

	srv := &http.Server{
		Addr:              addr,
		Handler:           http.HandlerFunc(handler),
		ReadHeaderTimeout: 30 * time.Second,
		// 只加 IdleTimeout 收闲连接；不设 WriteTimeout——
		// 大文件下载是长流式响应，设了会把慢速下载掐断
		IdleTimeout: 120 * time.Second,
	}
	// 优雅关闭：在途下载/tidy 被硬切会丢状态；先停接新请求，
	// 给在途请求最多 10 秒收尾，并刷掉未落盘的分享日志
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		log.Println("[退出] 收到退出信号，正在等待在途请求结束…")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
	flushSharesOnExit()
}

// 默认数据目录：可执行文件同级目录下的 data/。
// 旧的 filepath.Join(".", "data") 跟随 CWD——从别的目录启动就表现为
// 「密码被重置/分享全丢」并在意外位置新建数据目录
func defaultDataDir() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "data")
	}
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
