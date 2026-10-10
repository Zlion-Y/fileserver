package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ---------------- safeJoin / pathWithin ----------------

func TestSafeJoin(t *testing.T) {
	root := t.TempDir()
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		rel     string
		wantErr bool
	}{
		{"普通子路径", "a/b.txt", false},
		{"空路径回到根", "", false},
		{"点路径", "./a.txt", false},
		{"绝对路径按相对处理", "/a.txt", false},
		{"一级穿越", "../escape.txt", true},
		{"二段穿越", "a/../../escape.txt", true},
		{"纯点穿越", "..", true},
		// 反斜杠在 Windows 上是分隔符（判越界），在 Linux 上是合法文件名的一部分
		{"反斜杠路径", `a\..\..\x`, runtime.GOOS == "windows"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := safeJoin(root, c.rel)
			if c.wantErr {
				if err == nil {
					t.Fatalf("safeJoin(%q) 期望报错，实际返回 %q", c.rel, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("safeJoin(%q) 意外报错: %v", c.rel, err)
			}
			if !pathWithin(abs, got) {
				t.Fatalf("safeJoin(%q) = %q 越出根 %q", c.rel, got, abs)
			}
		})
	}
}

func TestPathWithin(t *testing.T) {
	sep := string(filepath.Separator)
	// 根目录用平台真实分隔符：Windows 是 "C:\"，Unix 是 "/"
	driveRoot := "C:" + sep
	rootRoot := driveRoot
	if runtime.GOOS != "windows" {
		rootRoot = "/"
	}
	cases := []struct {
		root, child string
		want        bool
	}{
		{driveRoot, "C:" + sep + "Windows", true},            // 盘符根：旧实现此处恒 false
		{rootRoot, rootRoot + "srv", true},                   // 平台根目录
		{"/srv/files", "/srv/files" + sep + "a.txt", true},   // 正常子路径
		{"/srv/files", "/srv/files", true},                   // 自身
		{"/srv/files", "/srv/files2" + sep + "a.txt", false}, // 前缀同名字目录不算在内
		{"/srv/files", "/srv/other", false},
	}
	for _, c := range cases {
		if got := pathWithin(c.root, c.child); got != c.want {
			t.Errorf("pathWithin(%q, %q) = %v, 期望 %v", c.root, c.child, got, c.want)
		}
	}
}

// ---------------- realPathInside / ensureCreatableInside ----------------

func TestRealPathInsideSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("需要特权才能创建符号链接，Windows 上跳过")
	}
	root := t.TempDir()
	secretDir := t.TempDir()
	if err := os.Symlink(secretDir, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	// 不存在的路径：realPathInside 放行（新建场景，由 ensureCreatableInside 兜底）
	if !realPathInside(root, filepath.Join(root, "link", "new.txt")) {
		t.Fatal("不存在的新路径应放行")
	}
	// 已存在且真实位于 root 外（经由 root 内 symlink）：必须拒绝
	if err := os.WriteFile(filepath.Join(secretDir, "x.txt"), []byte("s"), 0o644); err != nil {
		t.Fatal(err)
	}
	if realPathInside(root, filepath.Join(root, "link", "x.txt")) {
		t.Fatal("root 内 symlink 指向外部目录，realPathInside 应拒绝已存在的越界路径")
	}
	// root 自身：放行
	if !realPathInside(root, root) {
		t.Fatal("root 自身应放行")
	}
	// 不存在的普通新路径：放行
	if !realPathInside(root, filepath.Join(root, "newdir", "x.txt")) {
		t.Fatal("不存在的新路径应放行")
	}
}

func TestEnsureCreatableInsideSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("需要特权才能创建符号链接，Windows 上跳过")
	}
	root := t.TempDir()
	secretDir := t.TempDir()
	if err := os.Symlink(secretDir, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	// target 本身不存在，但祖先是越界 symlink：必须拒绝
	if ensureCreatableInside(root, filepath.Join(root, "link", "newdir")) {
		t.Fatal("越界 symlink 祖先未拦截，新建内容会写到 root 外")
	}
	if !ensureCreatableInside(root, filepath.Join(root, "ok", "newdir")) {
		t.Fatal("正常新路径应放行")
	}
}

// ---------------- 回收站 ----------------

func TestInTrashRel(t *testing.T) {
	cases := []struct {
		rel  string
		want bool
	}{
		{".trash", true},
		{".trash/x.txt", true},
		{"./.trash/x.txt", true},
		{"a/../.trash/x.txt", true},
		{"//.trash/x.txt", true},
		{".trash/", true},
		{"trash", false},
		{".trashx", false},
		{"a/.trash/x", false}, // 子目录下的同名目录不是回收站
		{"normal.txt", false},
	}
	caseInsensitive := runtime.GOOS == "windows" || runtime.GOOS == "darwin"
	if caseInsensitive {
		cases = append(cases,
			struct {
				rel  string
				want bool
			}{".TRASH", true},
			struct {
				rel  string
				want bool
			}{".Trash/x.txt", true},
		)
	} else {
		cases = append(cases,
			struct {
				rel  string
				want bool
			}{".TRASH", false},
			struct {
				rel  string
				want bool
			}{".Trash/x.txt", false},
		)
	}
	for _, c := range cases {
		if got := inTrashRel(c.rel); got != c.want {
			t.Errorf("inTrashRel(%q) = %v, 期望 %v", c.rel, got, c.want)
		}
	}
}

func TestTrashOrigFromName(t *testing.T) {
	stamp := time.Now().Format("20060102-150405")
	cases := []struct {
		entry, want string
	}{
		{stamp + "_ab12_report.pdf", "report.pdf"},                   // 新格式
		{stamp + "_ab12_1_report.pdf", "report.pdf"},                 // 新格式冲突重试（跳过序号）
		{stamp + "_report.pdf", "report.pdf"},                        // v1.1.0 旧格式
		{stamp + "_1_report.pdf", "report.pdf"},                      // v1.1.1 旧格式（序号）
		{stamp + "_ab12_my_file.txt", "my_file.txt"},                 // 原名含下划线
		{stamp + "_ab12_1_my_file.txt", "my_file.txt"},               // 冲突重试 + 原名含下划线
		{"weird_name.txt", "weird_name.txt"},                         // 无法识别：原样返回
		{"20260102_150405_report.pdf", "20260102_150405_report.pdf"}, // 时间戳格式不对：原样返回
	}
	for _, c := range cases {
		if got := trashOrigFromName(c.entry); got != c.want {
			t.Errorf("trashOrigFromName(%q) = %q, 期望 %q", c.entry, got, c.want)
		}
	}
}

func TestValidTrashEntry(t *testing.T) {
	for _, bad := range []string{"", ".", "..", "a/b", `a\b`, "../x"} {
		if validTrashEntry(bad) {
			t.Errorf("validTrashEntry(%q) 应为 false", bad)
		}
	}
	for _, good := range []string{"x.txt", "20260102-150405_ab12_report.pdf"} {
		if !validTrashEntry(good) {
			t.Errorf("validTrashEntry(%q) 应为 true", good)
		}
	}
}

func TestReservedName(t *testing.T) {
	if !reservedName(".trash") {
		t.Error("reservedName(.trash) 应为 true")
	}
	caseInsensitive := runtime.GOOS == "windows" || runtime.GOOS == "darwin"
	if got := reservedName(".TRASH"); got != caseInsensitive {
		t.Errorf("reservedName(.TRASH) = %v, 期望 %v（平台 %s）", got, caseInsensitive, runtime.GOOS)
	}
	if reservedName("trash") || reservedName(".trash2") {
		t.Error("普通名字不应命中保留名")
	}
}

// ---------------- 版本号 ----------------

func TestVerNumsAndGreater(t *testing.T) {
	if v := verNums("v1.2.3"); v != [3]int{1, 2, 3} {
		t.Errorf("verNums(v1.2.3) = %v", v)
	}
	if v := verNums(" 1.10.0 "); v != [3]int{1, 10, 0} {
		t.Errorf("verNums(1.10.0) = %v", v)
	}
	if v := verNums("dev"); v != [3]int{0, 0, 0} {
		t.Errorf("verNums(dev) = %v", v)
	}
	cases := []struct {
		a, b string
		want bool
	}{
		{"v1.2.3", "v1.2.2", true},
		{"v1.2.3", "v1.2.3", false},
		{"v1.10.0", "v1.9.9", true},
		{"v2.0.0", "v1.99.99", true},
		{"v1.2.3", "v1.2.10", false},
		{"dev", "v0.0.1", false},
	}
	for _, c := range cases {
		if got := verGreater(c.a, c.b); got != c.want {
			t.Errorf("verGreater(%q, %q) = %v, 期望 %v", c.a, c.b, got, c.want)
		}
	}
}

// ---------------- 文件名 ----------------

func TestSanitizeName(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"a/b.txt", "b.txt"},
		{"../x.txt", "x.txt"}, // ../ 前缀经 FromSlash+Base 剥离，各平台一致
		{"normal.txt", "normal.txt"},
		{"con.txt", "_con.txt"},
		{"CON", "_CON"},
		{"lpt3.log", "_lpt3.log"},
		{"a<b>:c", "a_b__c"},
	}
	for _, c := range cases {
		if got := sanitizeName(c.in); got != c.want {
			t.Errorf("sanitizeName(%q) = %q, 期望 %q", c.in, got, c.want)
		}
	}
	for _, bad := range []string{"", ".", "..", "  "} {
		got := sanitizeName(bad)
		if got == "" || got == "." || got == ".." || strings.ContainsAny(got, `/\`) {
			t.Errorf("sanitizeName(%q) = %q, 应回退为安全名", bad, got)
		}
	}
}

// ---------------- Range 判次 ----------------

func TestRangeCoversToEnd(t *testing.T) {
	mkReq := func(rg string) *http.Request {
		r := httptest.NewRequest("GET", "/s/x", nil)
		if rg != "" {
			r.Header.Set("Range", rg)
		}
		return r
	}
	cases := []struct {
		name string
		rg   string
		size int64
		want bool
	}{
		{"无 Range 头", "", 200, true},
		{"开区间到末尾", "bytes=100-", 200, true},
		{"闭区间到末尾", "bytes=0-199", 200, true},
		{"只取中段不含末尾", "bytes=0-99", 200, false},
		{"多段任一含末尾", "bytes=0-99,150-", 200, true},
		{"end 超界视为到末尾", "bytes=100-999999", 200, true},
		{"start 越界", "bytes=500-", 200, false},
		{"非法段被跳过", "bytes=abc,180-", 200, true},
		{"空文件任何请求都算", "bytes=0-99", 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := rangeCoversToEnd(mkReq(c.rg), c.size); got != c.want {
				t.Errorf("rangeCoversToEnd(%q, %d) = %v, 期望 %v", c.rg, c.size, got, c.want)
			}
		})
	}
}

// ---------------- decodeStrict ----------------

func TestDecodeStrict(t *testing.T) {
	type body struct {
		Path string `json:"path"`
	}
	ok := httptest.NewRequest("POST", "/api/share", strings.NewReader(`{"path":"a.txt"}`))
	var v body
	if err := decodeStrict(httptest.NewRecorder(), ok, &v); err != nil {
		t.Fatalf("合法 JSON 被拒绝: %v", err)
	}
	if v.Path != "a.txt" {
		t.Fatalf("字段解析错误: %+v", v)
	}

	// 尾部垃圾（两个对象拼接）必须拒绝
	garbage := httptest.NewRequest("POST", "/api/share", strings.NewReader(`{"path":"a.txt"}{"x":1}`))
	if err := decodeStrict(httptest.NewRecorder(), garbage, &v); err == nil {
		t.Fatal("尾部垃圾未被拒绝")
	}

	// 未知字段必须拒绝（拼错字段名不再被静默忽略）
	unknown := httptest.NewRequest("POST", "/api/share", strings.NewReader(`{"path":"a.txt","expireHours":1}`))
	if err := decodeStrict(httptest.NewRecorder(), unknown, &v); err == nil {
		t.Fatal("未知字段未被拒绝")
	}

	// 空 body 必须拒绝
	empty := httptest.NewRequest("POST", "/api/share", strings.NewReader(``))
	if err := decodeStrict(httptest.NewRecorder(), empty, &v); err == nil {
		t.Fatal("空 body 未被拒绝")
	}
}
