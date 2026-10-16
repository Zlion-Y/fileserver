package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type config struct {
	RootDir      string `json:"rootDir"`
	AuthPassHash string `json:"authPassHash,omitempty"` // 网页「安全与会话」修改后的管理密码哈希（优先于 -pass/AUTH_PASS）
	TidyEnabled  *bool  `json:"tidyEnabled,omitempty"`  // nil = 默认开启自动清理
	TidyHours    int    `json:"tidyHours,omitempty"`    // >0 时优先于 TIDY_HOURS 环境变量
	// UapiKey UAPIs.cn 的 API Key（IP 归属地查询用）。data/ 在 .gitignore 中，
	// 写在这里不会进版本库；环境变量 UAPI_KEY 优先。留空 = 访客积分模式（免注册）
	UapiKey string `json:"uapiKey,omitempty"`
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
	PasswordEnc    string `json:"passwordEnc,omitempty"`
	LegacyPassword string `json:"password,omitempty"`     // 兼容旧版本遗留明文，加载时迁移后清空，不再落盘
	Password       string `json:"-"`                      // 仅内存字段：管理端回显用，绝不持久化
	PasswordHash   string `json:"passwordHash,omitempty"` // PBKDF2 口令哈希，空 = 无密码
	Mode           string `json:"mode,omitempty"`         // "" = 直链下载（兼容旧记录），"page" = 确认页
	Alias          string `json:"alias,omitempty"`        // 自定义链接别名：/s/<alias>，对外发布更好看
	Hotlink        bool   `json:"hotlink,omitempty"`      // 防盗链：带 Referer 且来源域名非本站时拒绝
	// Site 文件夹分享的「静态网页发布」开关（借鉴 dufs 把一个目录当站点服务）：
	// 打开后 /s/<别名>/ 直接渲染目录里的 index.html，页面里的相对路径可从
	// /s/<别名>/<文件> 取到，浏览与子资源加载不消耗下载次数（内容是所有者主动对外
	// 发布的网页，限次语义留给 ?dl=1 的显式下载）；目录里没有 index.html 时
	// 回落到列表页。关闭时（默认）也能浏览列表，但每个文件的取都计一次，
	// maxDownloads 不会被「逐个翻看」架空
	Site bool       `json:"site,omitempty"`
	Log  []ShareLog `json:"log,omitempty"`
}

type sharePublic struct {
	Share
	Alive bool `json:"alive"`
	HasPw bool `json:"hasPw"`
	// IsDir 让管理端能判断这条分享是不是文件夹（Size 对目录存的是 0，
	// 而 0 字节的文件同样是 0，不能拿来当目录判据）
	IsDir    bool   `json:"isDir"`
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

// envIntRange 带区间钳制的整数配置。裸 envInt 让越界值直通到底层运算：
// SESSION_DAYS=0 会让会话「刚签发即过期」，TIDY_HOURS 极大值在
// time.Duration(h)*time.Hour 上溢出为负、把清理截止推到未来而一次删光有效分享。
// 这类值没有任何理由是笔误之外的正确配置，钳制 + 告警比照单全收安全
func envIntRange(k string, def, lo, hi int) int {
	n := envInt(k, def)
	if n < lo || n > hi {
		log.Printf("[配置] %s=%d 超出允许区间 [%d,%d]，已按默认值 %d 处理", k, n, lo, hi, def)
		return def
	}
	return n
}

// envBool 只认明确写法；无法识别的取值回落默认值并告警。
// 旧实现把一切非 "1"/"true" 的值当 false，于是 LOG=on、TRUST_PROXY=yes
// 会在用户以为开启的情况下静默关掉审计日志/转发头识别
func envBool(k string, def bool) bool {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	switch strings.ToLower(v) {
	case "1", "t", "true", "y", "yes", "on", "enabled":
		return true
	case "0", "f", "false", "n", "no", "off", "disabled":
		return false
	}
	log.Printf("[配置] %s=%q 不是可识别的布尔值，已按默认值 %v 处理", k, v, def)
	return def
}

// ---------------- 持久化 ----------------
func dataPath(name string) string {
	if err := os.MkdirAll(flagDataDir, 0o700); err != nil {
		log.Printf("[持久化] 数据目录 %s 创建失败: %v", flagDataDir, err)
	}
	return filepath.Join(flagDataDir, name)
}

// atomicWriteFile 临时文件 + fsync + rename 的原子落盘：
// 没有 Sync 的话断电后 rename 出来的可能是 0 长度文件；写失败必须暴露给调用方，
// 静默丢弃会让管理员收到「已保存」的假成功（磁盘满/只读时配置实际回退了）
//
// 临时名用 CreateTemp 随机后缀 + O_EXCL，不用固定 path+".tmp"：固定名在多进程
// 共用数据目录时（自更新重启窗口新旧进程重叠）会互相截断，而本地用户预先放置的
// 同名文件或指向别处的符号链接，会让 O_TRUNC 穿透写到链接目标上，
// 且已存在的 tmp 会让 perm 参数被内核忽略、"0600 的秘密文件"实际沿用旧权限
func atomicWriteFile(path string, b []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	// 无论后续走到哪个 return，都要把中间文件收掉，否则磁盘上留一堆 .tmp-N
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// backupCorrupt 把损坏的数据文件改名留证（.corrupt-<时间戳>），
// 避免下一次 saveShares 把可手工抢救的原始数据静默覆盖掉
func backupCorrupt(path string) {
	bak := fmt.Sprintf("%s.corrupt-%s", path, time.Now().Format("20060102-150405"))
	if err := os.Rename(path, bak); err == nil {
		log.Printf("[持久化] %s 解析失败，已改名保留为 %s，请手工检查后恢复", path, bak)
	}
}

func loadConfig() {
	b, err := os.ReadFile(dataPath("config.json"))
	if err != nil {
		return
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		// 损坏即静默清空 = 管理员被锁在外面（rootDir/密码哈希丢失），必须留证
		log.Printf("[持久化] config.json 解析失败（%v），沿用默认配置", err)
		backupCorrupt(dataPath("config.json"))
	}
}
func saveConfig() {
	// 全程持 cfgMu：marshal 和写盘都在锁内完成。此前 Marshal 无锁读 cfg，
	// 与 POST /api/config 等写操作并发构成数据竞争（go test -race 可复现）；
	// 若写盘放在锁外，两个并发保存者还会互相覆盖（旧快照后写，丢更新）。
	cfgMu.Lock()
	defer cfgMu.Unlock()
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		log.Printf("[持久化] config 序列化失败: %v", err)
		return
	}
	if err := atomicWriteFile(dataPath("config.json"), b, 0o600); err != nil {
		log.Printf("[持久化] config.json 写盘失败，本次修改可能未保存: %v", err)
	}
}
func loadShares() {
	b, err := os.ReadFile(dataPath("shares.json"))
	if err != nil {
		return
	}
	var m map[string]*Share
	if err := json.Unmarshal(b, &m); err != nil || m == nil {
		// 解析失败继续往下走 = 内存空表，下一次任意保存会把全部分享
		// （含密码与访问日志）清零。必须留证并终止加载
		log.Printf("[持久化] shares.json 解析失败（%v），加载 0 条分享", err)
		backupCorrupt(dataPath("shares.json"))
		return
	}
	// 手工编辑/损坏的 shares.json 可能出现 "token": null，
	// 任何后续遍历（publicOne/runTidy/moveShareSync）解引用都会 panic，这里直接剔除
	for k, s := range m {
		if s == nil {
			delete(m, k)
		}
	}
	shares = m
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
	// 全程持锁：如果在 Marshal 之后才释放锁又重新取快照，并发修改会被后写者覆盖丢失。
	// 注意所有调用点都必须先 Unlock 才能调用本函数（Go 互斥锁不可重入）
	shareMu.Lock()
	b, err := json.MarshalIndent(shares, "", "  ")
	if err != nil {
		shareMu.Unlock()
		log.Printf("[持久化] shares 序列化失败: %v", err)
		return
	}
	// 0600：shares.json 含加密后的分享密码与访问日志，不应默认全局可读
	if err := atomicWriteFile(dataPath("shares.json"), b, 0o600); err != nil {
		log.Printf("[持久化] shares.json 写盘失败，分享数据可能未保存: %v", err)
	}
	shareMu.Unlock()
}

// ---------------- 工具 ----------------
func writeJSON(w http.ResponseWriter, code int, v any) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write(b)
}

// fsErr 文件系统错误统一脱敏：os.Rename/Open 等的原始错误串包含服务器
// 绝对路径（root 下 .trash 等），直接回传客户端属于信息泄露。
// 细节进服务端日志，对客户端给固定文案
func fsErr(scope string, err error) string {
	log.Printf("[fs] %s: %v", scope, err)
	return "服务器文件操作失败，详情请查看服务端日志"
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
