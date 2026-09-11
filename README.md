# fileserver —— 单文件自建文件服务（Go）

一个**单个可执行文件**的文件服务：**目录设置 / 上传 / 删除 / 带 token 的限时限次分享链接**。
Go 实现（零第三方库），前端经 `//go:embed` 编译进二进制，拷贝到服务器即可运行，**无任何运行时依赖**。

## 功能

| 功能 | 说明 |
| --- | --- |
| 首次设置目录 | 打开页面后选择本地磁盘目录（带服务端目录树选择器）；也可用 `ROOT_DIR` 环境变量预设，跳过设置 |
| 修改目录 | 右上角「修改目录」随时切换根目录 |
| 上传 | 点击按钮或拖拽到页面，支持多文件、大文件（multipart 流式直写目标目录，不落系统临时盘）、进度条 |
| 删除 | 文件 / 文件夹（含内部文件）均可删除 |
| 大小显示 | 文件名后方直接显示体积（B/KB/MB/GB） |
| 分享链接 | 每个文件一个「分享链接」按钮，一键复制带 token 的直链 |
| 链接控制 | 有效期（1 小时 ~ 30 天 / 永久 / 自定义时刻）、下载次数（1/5/20/不限/自定义） |
| 协议切换 | 自动识别当前域名与协议 / 强制 HTTP（路由器、局域网无 HTTPS）/ 强制 HTTPS，可手动覆盖域名端口 |
| 续传 | 下载支持 HTTP Range，可断点续传 |
| 登录页 + Session | 浏览器访问走登录页签发 Cookie 会话（HttpOnly，默认 7 天，`SESSION_DAYS` 可调）；Basic 认证仍兼容 curl / 脚本 |
| 磁盘空间 | 页脚实时显示根目录所在磁盘的已用 / 剩余空间 |
| 重命名 / 移动 | 每个条目可重命名，输入含子目录的完整相对路径即等于移动 |
| 搜索 / 排序 / 筛选 | 全盘递归文件名搜索（防卡死限量）；按名称 / 大小 / 时间排序；按文件 / 文件夹筛选 |
| 分享密码 | 分享链接可设访问密码（PBKDF2 哈希校验），密码以 AES-GCM 加密存储，管理端可查看/复制 |
| 分享文件夹 | 文件夹也可分享：访问时流式打包 ZIP 下载（边压缩边传输，不占服务器磁盘）；多选文件可「打包下载 ZIP」 |
| 二维码 | 生成分享链接后同屏展示二维码（纯前端生成，零依赖），手机扫码即下 |
| 回收站 | 删除先进回收站（同盘原子 rename），可恢复/彻底删除；超过 `TRASH_DAYS`（默认 7 天，0 = 永久保留）自动清理 |
| 媒体预览 | 图片/视频/音频在浏览器内直接预览与播放（客户端渲染，服务端只透传文件流，视频音频支持拖动） |
| 文件夹上传 | 「上传文件夹」递归上传整个目录结构（含子目录，自动创建） |
| 大目录优化 | 列表分页拉取 + 前端虚拟滚动：万级文件目录也只渲染可见行；排序/筛选服务端化 |
| 深色模式 | 跟随系统或手动切换，选择持久化 |
| WebDAV | `/dav/` 挂载文件根目录（Class 1：PROPFIND/GET/PUT/MKCOL/DELETE/MOVE），Salt Player 等播放器可直接连；Basic 认证同管理端 |
| 直链 / 确认页 | 直链模式打开即下载；确认页模式先展示文件信息，点下载才计数 |
| 分享访问日志 | 每条分享记录最近 50 次访问（IP / UA / 成败 / 失败原因），管理端可查 |
| 定时清理 | 后台每小时清理过期分享记录；保留时长与开关可在「定时清理」页直接配置并持久化（初始值取 `TIDY_HOURS`，默认 72） |
| 访问控制 | 管理端需登录（或 Basic 认证）；分享链接 `/s/token` 免密 |
| 防爆破 | 同一 IP 5 分钟内认证失败满 10 次自动封禁 15 分钟 |
| 检查更新 | 服务端代理查询 GitHub 最新 Release，提示新版本，并同时展示**当前版本**与**新版本**的更新内容 |
| 一键自更新 | 发现新版本后点「一键更新」：服务器自动下载对应架构二进制 → 校验 → 原子替换 → 自动重启，全程无需登录服务器，并展示版本更新日志
| 更新内容 | Release 说明若只有 GitHub 自动生成的 Full Changelog 链接，会自动用两版本之间的提交记录补全成可读清单 |
| 分享管理 | 分享列表支持筛选（全部/有效/已过期/带密码/直链）、勾选批量撤销、条目内快速编辑（有效期/密码/访问方式），无需删除重建 |
| 安全与会话 | 查看活跃登录会话（IP / 登录时间）、踢出其他会话、网页修改管理员密码（新密码哈希持久化，立即生效） |

## 快速开始

```bash
./fileserver                          # 默认 0.0.0.0:8080
./fileserver --port 16666 --dir /data/files --user admin --pass 你的密码
./fileserver --version                # 版本详情（版本号 / commit / 构建时间）
```

参数：`--port --host --dir --data-dir --user --pass --trust-proxy --max-upload-mb --log`
（同名环境变量 `PORT / ROOT_DIR / DATA_DIR / AUTH_USER / AUTH_PASS / TRUST_PROXY / MAX_UPLOAD_MB / LOG` 同样生效，命令行优先）

## 获取二进制

### 方式一：GitHub Release（推荐）

仓库内置 workflow：每次 push 跑 `go vet` + 编译 + 冒烟测试；打 tag 自动交叉编译 8 个平台并发布 Release。

```bash
git tag v1.0.3 && git push origin v1.0.3
```

产物：`linux_amd64 / linux_arm64 / linux_armv7 / linux_armv5 / linux_386 /
linux_mipsle / windows_amd64.exe / darwin_arm64`。

### 方式二：本机编译

```bash
bash build.sh                              # 编译全部平台 -> dist-go/
bash build.sh linux/amd64 linux/arm/5      # 只编译指定平台
VERSION=v1.0.3 bash build.sh
```

## 部署到 Linux 服务器（一键脚本，推荐）

脚本自动识别 CPU 架构（amd64 / arm64 / armv7 / armv5 / mipsle / 386）、从 Release 下载二进制、放行防火墙、注册 systemd 开机自启。

```bash
curl -fsSL https://raw.githubusercontent.com/Zlion-Y/fileserver/main/install-remote.sh -o install-remote.sh
sudo bash install-remote.sh --dry-run                        # 先看会做什么，不改系统
sudo FS_USER=admin FS_PASS=你的密码 bash install-remote.sh   # 正式安装
```

| 需求 | 命令 |
| --- | --- |
| 换文件目录 / 端口 | `sudo DIR=/mnt/disk/share PORT=9000 bash install-remote.sh` |
| 指定版本 | `sudo VERSION=v1.0.3 bash install-remote.sh` |
| 升级到最新版 | 重跑安装即可（自动继承已有配置与密码） |
| 卸载（保留文件与分享记录） | `sudo bash install-remote.sh --uninstall` |

装好后：配置在 `/etc/fileserver.env`（改完 `systemctl restart fileserver`），日志 `journalctl -u fileserver -f`。

### 手动部署（三行）

```bash
sudo curl -fsSL -o /usr/local/bin/fileserver \
  https://github.com/Zlion-Y/fileserver/releases/download/v1.0.3/fileserver_linux_amd64
sudo chmod +x /usr/local/bin/fileserver
sudo /usr/local/bin/fileserver --port 16666 --dir /data/files \
     --data-dir /var/lib/fileserver --user admin --pass 你的密码
```

`--data-dir` 必须落在持久目录，分享记录存在里面的 `shares.json`。

## Docker

```bash
cp .env.example .env      # 修改 ROOT_DIR / AUTH_PASS 等
docker compose up -d      # 多阶段构建，数据落在 ./files 与 ./data
```

`docker-compose.yml` 默认只监听 `127.0.0.1:16666`，由 Nginx/Caddy 反代后对外。

## 手动 systemd + Nginx

```bash
sudo cp fileserver_linux_amd64 /usr/local/bin/fileserver && sudo chmod +x /usr/local/bin/fileserver
sudo cp deploy/fileserver.service /etc/systemd/system/        # 记得改 Environment 里的路径与密码
sudo cp deploy/nginx.conf /etc/nginx/conf.d/fileserver.conf   # 记得改域名与证书路径
sudo systemctl daemon-reload && sudo systemctl enable --now fileserver
sudo nginx -t && sudo systemctl reload nginx
```

## 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `PORT` | `8080`（部署脚本默认 `16666`） | 监听端口 |
| `HOST` | `0.0.0.0` | 监听地址 |
| `ROOT_DIR` | 无 | 预设文件根目录，设置后无需网页首次配置 |
| `DATA_DIR` | `./data` | 存放 `config.json` / `shares.json` / `sessions.json`，**必须持久化** |
| `TRUST_PROXY` | `0` | 置 `1` 后按 `X-Forwarded-Proto/Host` 生成分享链接（反代必开） |
| `AUTH_USER` / `AUTH_PASS` | 无 | 管理端认证；设置后浏览器走登录页 + Cookie 会话，Basic 认证供 curl / 脚本兼容 |
| `SESSION_DAYS` | `7` | 登录会话有效期（天） |
| `TIDY_HOURS` | `72` | 分享记录过期后保留时长（小时），仅在 config.json 尚未保存过清理配置时作为初始值 |
| `TRASH_DAYS` | `7` | 回收站保留天数，超过自动彻底删除；`0` = 永久保留 |
| `SEARCH_LIMIT` | `200` | 全盘搜索最多返回条数（上限 1000） |
| `MAX_UPLOAD_MB` | `0` | 单个文件上限（MB），0 为不限制；chunked（无 Content-Length）上传同样受限 |
| `LOG` | `1` | 访问日志开关 |

## HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/state` | 初始化状态、快捷目录 |
| GET | `/api/version` | 版本详情 + 检查更新（含服务器架构 goos/goarch/goarm、对应 Release 包名与直链） |
| POST | `/api/selfupdate` | 一键自更新（JSON body）：下载最新 Release 对应架构二进制并原子替换后自动重启 |
| POST | `/api/selfupdate` | 手动上传更新包（multipart `file` 字段）：服务器连不上 GitHub 时，本地下载好二进制从网页传上去，校验魔数后替换重启，上限 256MB |
| GET | `/api/selfupdate` | 查询自更新任务状态（idle/downloading/replacing/restarting/done/error） |
| POST | `/api/config` | 设置 / 修改根目录 |
| GET | `/api/browse?path=` | 服务端目录树（选目录用） |
| GET | `/api/list?path=` | 文件列表（含大小、修改时间） |
| POST | `/api/mkdir?path=` | 新建文件夹 |
| POST | `/api/upload?path=` | multipart 上传，字段名 `files` |
| DELETE | `/api/item?path=` | 删除文件或目录 |
| GET | `/api/download?path=` | 直接下载（管理端） |
| POST | `/api/share` | 创建分享：`path / expireSeconds / maxDownloads / scheme / host` |
| GET | `/api/shares` | 分享列表 |
| DELETE | `/api/share?token=` | 撤销分享 |
| POST | `/api/zip` | 多选打包：`{"paths":["a.txt","dir"]}` → 流式 ZIP 下载 |
| GET | `/api/trash` | 回收站列表 |
| POST | `/api/trash/restore` | 恢复：`{"name":"回收站内条目名"}` |
| POST | `/api/trash/purge` | 彻底删除单个条目 |
| POST | `/api/trash/clear` | 清空回收站 |
| GET | `/api/list` | 文件列表（可选 `offset/limit/sort/filter/size` 分页与服务端排序筛选；带 `limit` 时返回 `total/hasMore`） |
| GET | `/s/:token` | 分享下载（校验有效期与次数；文件夹分享为流式 ZIP） |
| 任意 | `/dav/*` | WebDAV（OPTIONS/PROPFIND/GET/HEAD/PUT/MKCOL/DELETE/MOVE/PROPPATCH） |
| GET | `/healthz` | 健康检查 |

所有 POST 接口均为**严格 JSON 解码**：字段名拼错、未知字段一律 400 并回显原因（如把
`expireSeconds` 写成 `expireHours` 不会静默变成永久链接）。

## WebDAV（Salt Player / 播放器直连）

服务地址即 `http://<主机>:<端口>/dav/`，路径对应文件根目录，认证同管理端（用户名/密码）。
支持 Class 1 动词（PROPFIND / GET / HEAD / PUT / MKCOL / DELETE / MOVE / PROPPATCH），
文件以内联 Content-Type 返回并支持 Range，音乐播放器可直接流式播放与拖动。
未实现 LOCK/UNLOCK（Class 2），Windows 资源管理器「映射网络驱动器」不受支持；
Salt Player / foobar2000 / 常规移动端文件管理器均可正常使用。删除同样进回收站。

## 注意事项

- **分享记录存于 `DATA_DIR/shares.json`**，容器重建时若该目录未持久化，已有链接会全部失效。
- 反代场景务必设置 `TRUST_PROXY=1`，否则生成的链接会变成 `http://127.0.0.1:16666/...`。
- Nginx 需放开 `client_max_body_size 0` 并关闭 `proxy_buffering`（`deploy/nginx.conf` 已配置）。
- 公网部署请务必设置 `AUTH_USER` / `AUTH_PASS`，否则任何人都能管理文件。
- 上传采用 multipart 流式写盘：逐 part 直接写入目标目录，不经系统临时盘中转，不受内存/32MB 阈值限制；同名文件自动追加 `(1)`、`(2)` 后缀（排他创建，并发上传不会互相覆盖）；上传目标子目录不存在时自动创建。
- 删除进入回收站（`<根目录>/.trash/`），保留期内可在「回收站」页恢复；彻底删除后不可恢复。
- 大目录：列表按页拉取（每页 500 项）+ 前端虚拟滚动，仅渲染可见行；排序/类型/大小筛选由服务端在分页前完成。
- 超过 `MAX_UPLOAD_MB` 的文件会立即中断并删除半成品，返回 413。
- Docker 构建可传 `--build-arg VERSION=v1.2.3` 注入版本号；未注入时版本为 `dev`（非发布版本），网页会禁用一键更新（容器内应重新构建镜像，而非替换二进制）。
- 反向代理场景开启 `TRUST_PROXY=1` 后，仅当直连来源为环回/内网地址时才采信 `X-Forwarded-For`，端口直接暴露公网时伪造 XFF 无效。
- 路径参数均做了根目录越权校验，无法通过 `../` 访问目录以外的文件。
