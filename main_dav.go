package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

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
	// 内联返回（不设 attachment）：播放器按 Content-Type 流式读取，Range 拖动由 ServeContent 处理。
	// 例外：text/html 与 SVG 同源内联渲染会执行其中脚本（CSP 的 unsafe-inline 拦不住），
	// 是已登录上下文的存储型 XSS 面，一律强制按附件下载
	ext := strings.ToLower(filepath.Ext(p))
	if ext == ".html" || ext == ".htm" || ext == ".svg" {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", contentDisposition("attachment", st.Name()))
		w.Header().Set("X-Content-Type-Options", "nosniff")
	} else {
		ct := "application/octet-stream"
		if t := mime.TypeByExtension(ext); t != "" {
			ct = t
		}
		w.Header().Set("Content-Type", ct)
	}
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
	// RFC 4918：父集合不存在 → 409（隐式 MkdirAll 会把打错的路径静默造成目录树）
	if st, err := os.Stat(filepath.Dir(p)); err != nil || !st.IsDir() {
		w.WriteHeader(http.StatusConflict)
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
	// RFC 4918 9.3：父集合必须已存在（409），只创建单级集合
	if st, err := os.Stat(filepath.Dir(p)); err != nil || !st.IsDir() {
		w.WriteHeader(http.StatusConflict)
		return
	}
	if err := os.Mkdir(p, 0o755); err != nil {
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
	// 目标的父目录可能尚不存在（realPathInside 对不存在的路径放行，挡不住
	// symlink 逃逸）：与网页端 /api/move 一致，用 ensureCreatableInside
	// 校验已存在祖先，防止 rename 经 root 内的符号链接目录落到 root 外
	if !ensureCreatableInside(root, filepath.Dir(toAbs)) {
		w.WriteHeader(403)
		return
	}
	if fromAbs == root || toAbs == root {
		w.WriteHeader(403)
		return
	}
	// 自移动（源=目标）：若不拦截，下面「目标已存在→先入回收站」会把文件本身
	// 移进回收站，随后 rename 因源已不存在而 500，用户视角等于文件丢失。
	// Windows 大小写不敏感 FS 上仅改大小写的 MOVE 字符串比较不相等，
	// 必须用 os.SameFile 判定，否则目标会被自己覆盖进回收站
	if fi, err := os.Lstat(fromAbs); err == nil {
		if ti, err2 := os.Lstat(toAbs); err2 == nil && os.SameFile(fi, ti) {
			w.WriteHeader(403)
			return
		}
	}
	// 自嵌套：把目录移到它自己的子目录里，rename 只会报 EINVAL，
	// 必须在改动磁盘前拒绝（与网页端 /api/move 的校验对齐）
	if absPrefix(fromAbs, toAbs) {
		w.WriteHeader(409)
		return
	}
	overwrite := !strings.EqualFold(r.Header.Get("Overwrite"), "F")
	existed := false
	trashedEntry := ""
	if _, err := os.Lstat(toAbs); err == nil {
		existed = true
		if !overwrite {
			w.WriteHeader(412) // 目标已存在且 Overwrite: F
			return
		}
		// Overwrite: T → 目标先进回收站（记录条目名，rename 失败时回滚）
		if e, err := moveToTrash(root, toAbs); err != nil {
			w.WriteHeader(500)
			return
		} else {
			trashedEntry = e
		}
	}
	// RFC 4918：父集合不存在 → 409
	if st, err := os.Stat(filepath.Dir(toAbs)); err != nil || !st.IsDir() {
		if trashedEntry != "" {
			if _, rerr := trashRestore(root, trashedEntry); rerr != nil {
				log.Printf("[dav] MOVE 失败且回滚失败，目标滞留回收站（%s）: %v", trashedEntry, rerr)
			}
		}
		w.WriteHeader(http.StatusConflict)
		return
	}
	if err := os.Rename(fromAbs, toAbs); err != nil {
		// rename 失败必须把已进回收站的目标恢复原位，
		// 否则用户视角是「文件消失」+ 500 的不一致态
		if trashedEntry != "" {
			if _, rerr := trashRestore(root, trashedEntry); rerr != nil {
				log.Printf("[dav] MOVE 失败且回滚失败，目标滞留回收站（%s）: %v", trashedEntry, rerr)
			}
		}
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
