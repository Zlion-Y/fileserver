#!/usr/bin/env bash
# =============================================================
#  文件服务 —— Linux 服务器一键部署
#  自动识别 CPU 架构 → 从 GitHub Release 下载对应二进制 → 注册 systemd 开机自启
#
#  用法（在服务器上执行）：
#    sudo bash install-remote.sh                                 # 交互询问口令（推荐）
#    sudo FS_USER=admin FS_PASS_FILE=/run/secrets/fs bash install-remote.sh
#    sudo -E FS_USER=admin FS_PASS=123456 bash install-remote.sh # 注意见下
#    sudo DIR=/mnt/disk/share PORT=9000 bash install-remote.sh   # 自定义目录与端口
#    sudo VERSION=v1.7.0 bash install-remote.sh                  # 指定版本
#    sudo bash install-remote.sh --dry-run                        # 只看会做什么，不改系统
#    sudo bash install-remote.sh --uninstall                      # 卸载（删除配置与口令文件）
#
#  ⚠ 口令不要走命令行：`sudo FS_PASS=xxx bash install-remote.sh` 里
#    FS_PASS=xxx 是 sudo 的 argv，任何本地用户 `ps` 一眼就能看到。
#    三种安全写法：留空触发交互输入（不回显）、FS_PASS_FILE 指向 0600 的文件、
#    或事先 export 再用 `sudo -E` 继承环境
#
#  可用环境变量：
#    DIR           文件根目录      默认 /data/files
#    DATA_DIR      配置/分享记录    默认 /var/lib/fileserver（务必持久化）
#    PORT          监听端口        默认 16666
#    FS_USER       管理端用户名     默认不启用认证（公网务必设置）
#    FS_PASS       管理端密码（慎用，见上面警告）；留空则交互询问
#    FS_PASS_FILE  从这个文件读口令，避免口令出现在命令行
#    FS_PROXY      1=识别反代头     默认 0；Nginx/Caddy 与服务同机时才设 1
#    FS_TRUSTED_CIDRS  可信代理网段（CIDR 逗号分隔），写入 TRUSTED_PROXIES
#    VERSION       Release 版本     默认取最新版
#    REPO          GitHub 仓库      默认 Zlion-Y/fileserver
# =============================================================
set -euo pipefail

REPO="${REPO:-Zlion-Y/fileserver}"
# 先记录用户是否显式指定（否则后面无法区分"显式传了 16666"和"用了默认值"）
PORT_GIVEN="${PORT:-}"
DIR_GIVEN="${DIR:-}"
PORT="${PORT:-16666}"
DIR="${DIR:-/data/files}"
DATA_DIR="${DATA_DIR:-/var/lib/fileserver}"
FS_USER="${FS_USER:-${AUTH_USER:-}}"
FS_PASS="${FS_PASS:-${AUTH_PASS:-}}"
# 直连暴露端口是常态，而反代头的采信面一旦打开就等于把「来源 IP」交给客户端，
# 所以默认关闭：同机反代（环回来源）才需要 FS_PROXY=1
FS_PROXY="${FS_PROXY:-0}"
FS_TRUSTED_CIDRS="${FS_TRUSTED_CIDRS:-}"
VERSION="${VERSION:-}"
DRY=0
UNINSTALL=0
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help) sed -n '2,31p' "$0"; exit 0 ;;
    *) echo "未知参数: $a"; exit 1 ;;
  esac
done

[ "$(id -u)" = "0" ] || { echo "请用 root 执行：sudo bash $0"; exit 1; }
[ "$(uname -s)" = "Linux" ] || { echo "仅支持 Linux 服务器（本机是 $(uname -s)）"; exit 1; }

BIN=/usr/local/bin/fileserver
SERVICE=/etc/systemd/system/fileserver.service
ENVFILE="${ENVFILE:-/etc/fileserver.env}"

# 去掉值两侧可能存在的引号：老版本把 AUTH_USER="admin" 连引号一起写进了
# env 文件，而读取用的 cut -d= -f2- 会把引号原样带回来，于是第二次运行
# 产出 AUTH_USER=""admin""，登录直接坏掉 —— 升级路径必须能吃下旧格式
read_env_val() {
  local key="$1" raw
  raw="$(grep -E "^${key}=" "$ENVFILE" 2>/dev/null | tail -1 | cut -d= -f2- || true)"
  raw="${raw%\"}"; raw="${raw#\"}"
  raw="${raw%\'}"; raw="${raw#\'}"
  printf '%s' "$raw"
}

# 重跑/升级时继承已有配置，避免忘记带参数导致认证被清空、目录被改回默认值。
# 这段必须排在卸载分支之前：卸载也要按真实目录汇报，否则打印的是内置默认值，
# 用户按错的地点去找自己的文件
if [ -f "$ENVFILE" ]; then
  [ -z "$FS_USER" ] && FS_USER="$(read_env_val AUTH_USER)"
  [ -z "$FS_PASS" ] && FS_PASS="$(read_env_val AUTH_PASS)"
  prev_dir="$(read_env_val ROOT_DIR)"
  prev_port="$(read_env_val PORT)"
  [ -z "$DIR_GIVEN" ] && [ -n "$prev_dir" ] && DIR="$prev_dir"
  [ -z "$PORT_GIVEN" ] && [ -n "$prev_port" ] && PORT="$prev_port"
fi

# 口令绝不出现在 argv：没给 FS_PASS 时先试 FS_PASS_FILE，再交互询问（不回显）
if [ -n "${FS_PASS_FILE:-}" ] && [ -z "$FS_PASS" ] && [ -f "$FS_PASS_FILE" ]; then
  FS_PASS="$(head -1 "$FS_PASS_FILE")"
  if [ -z "$FS_PASS" ]; then echo "FS_PASS_FILE=$FS_PASS_FILE 是空的"; exit 1; fi
elif [ "$DRY" = 0 ] && [ -n "${FS_USER:-}" ] && [ -z "$FS_PASS" ] && [ -t 0 ]; then
  read -rs -p "为管理端用户 $FS_USER 输入访问密码（不回显）: " FS_PASS; echo
  [ -n "$FS_PASS" ] || { echo "密码不能为空（只设用户名 = 空密码即可登录）"; exit 1; }
fi

# ---------- 卸载 ----------
if [ "$UNINSTALL" = 1 ]; then
  echo "== 卸载 =="
  systemctl stop fileserver 2>/dev/null || true
  systemctl disable fileserver 2>/dev/null || true
  rm -f "$SERVICE" "$BIN"
  # env 文件是 0600，但里面写着管理口令：卸载就该一并清掉，
  # 留在 /etc 下等着被同机别的账号翻出来不算「保留数据」
  if [ -f "$ENVFILE" ]; then rm -f "$ENVFILE"; echo "已删除配置文件：$ENVFILE（含管理口令）"; fi
  systemctl daemon-reload 2>/dev/null || true
  echo "程序已卸载。数据仍保留在：$DATA_DIR（分享记录）与 $DIR（文件）"
  exit 0
fi

# ---------- 识别架构 ----------
detect_target() {
  local m; m="$(uname -m)"
  case "$m" in
    x86_64|amd64)      echo linux_amd64 ;;
    aarch64|arm64)     echo linux_arm64 ;;
    armv7*|armhf)      echo linux_armv7 ;;
    # Release 没有 armv6 产物；GOARM=5 产物向后兼容 ARMv6 硬件，误装 armv7 会直接 SIGILL
    armv6*)            echo linux_armv5 ;;
    mipsel|mipsle)     echo linux_mipsle ;;
    i386|i686)         echo linux_386 ;;
    armv5*|arm*)       # 老 ARM 盒子：按 cpuinfo 再判一次
      if grep -qi 'ARMv7\|ARMv8' /proc/cpuinfo 2>/dev/null; then echo linux_armv7; else echo linux_armv5; fi ;;
    *) echo "" ;;
  esac
}
TARGET="$(detect_target)"
[ -n "$TARGET" ] || { echo "无法识别 CPU 架构（uname -m = $(uname -m)），请手动从 Release 下载对应二进制"; exit 1; }

# ---------- 解析版本号 ----------
if [ -z "$VERSION" ]; then
  VERSION="$(curl -fsSL --connect-timeout 10 --max-time 30 --retry 2 \
             "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
             | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name":[[:space:]]*"([^"]+)".*/\1/' || true)"
fi
[ -n "$VERSION" ] || { echo "取不到最新版本号（服务器无法访问 GitHub？）。可先手动指定：sudo VERSION=v1.7.0 bash $0"; exit 1; }

ASSET="fileserver_${TARGET}"
URL="https://github.com/$REPO/releases/download/$VERSION/$ASSET"

echo "============================================"
echo "  文件服务 一键部署"
echo "  仓库:     $REPO"
echo "  版本:     $VERSION"
echo "  架构:     $(uname -m) -> $TARGET"
echo "  下载地址: $URL"
echo "  端口:     $PORT"
echo "  文件目录: $DIR"
echo "  数据目录: $DATA_DIR"
[ -n "$FS_USER" ] && echo "  访问认证: 已开启（$FS_USER）" || echo "  访问认证: 未开启（公网部署强烈建议设置）"
echo "============================================"

# ---------- 防火墙 ----------
FIREWALL_MSG=""
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "Status: active"; then
  if [ "$DRY" = 1 ]; then
    FIREWALL_MSG="5. 放行端口：ufw allow $PORT/tcp"
  elif ufw allow "$PORT"/tcp >/dev/null 2>&1; then
    FIREWALL_MSG="防火墙:     已放行 $PORT/tcp (ufw)"
  else
    FIREWALL_MSG="防火墙:     ufw 放行失败，请手动执行 ufw allow $PORT/tcp"
  fi
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  if [ "$DRY" = 1 ]; then
    FIREWALL_MSG="5. 放行端口：firewall-cmd --add-port=$PORT/tcp --permanent"
  elif firewall-cmd --add-port="$PORT"/tcp --permanent >/dev/null 2>&1 && firewall-cmd --reload >/dev/null 2>&1; then
    FIREWALL_MSG="防火墙:     已放行 $PORT/tcp (firewalld)"
  else
    FIREWALL_MSG="防火墙:     firewalld 放行失败，请手动执行 firewall-cmd --add-port=$PORT/tcp --permanent"
  fi
fi

if [ "$DRY" = 1 ]; then
  echo
  echo "[dry-run] 将执行："
  echo "  1. 下载 $ASSET -> $BIN 并 chmod +x"
  echo "  2. 创建目录 $DIR 与 $DATA_DIR"
  echo "  3. 写入 $ENVFILE（配置）"
  echo "  4. 写入 $SERVICE 并 systemctl enable --now fileserver"
  [ -n "$FIREWALL_MSG" ] && echo "  $FIREWALL_MSG"
  echo "实际未做任何改动。去掉 --dry-run 即执行。"
  exit 0
fi

# ---------- 下载 ----------
command -v curl >/dev/null || { echo "需要 curl，请先安装：apt install -y curl / yum install -y curl"; exit 1; }
TMP="$(mktemp)"
SUMS_TMP="$(mktemp)"
cleanup() { rm -f "$TMP" "$SUMS_TMP"; }
trap cleanup EXIT
echo "下载中..."
if ! curl -fsSL --connect-timeout 10 --max-time 600 --retry 3 --retry-delay 2 "$URL" -o "$TMP"; then
  echo "下载失败：$URL"
  echo "可能原因：该版本没有此架构的产物，或服务器访问不了 GitHub。"
  echo "可手动下载后上传：https://github.com/$REPO/releases"
  exit 1
fi
[ -s "$TMP" ] || { echo "下载到空文件"; exit 1; }

# ---------- 完整性校验（SHA256SUMS；老版本 Release 没有该文件时跳过并提示） ----------
SUMS_URL="https://github.com/$REPO/releases/download/$VERSION/SHA256SUMS"
if curl -fsSL --connect-timeout 10 --max-time 60 --retry 2 "$SUMS_URL" -o "$SUMS_TMP" 2>/dev/null && [ -s "$SUMS_TMP" ]; then
  want="$(grep -E "[[:space:]]${ASSET}\$|[[:space:]]${ASSET}\.exe\$" "$SUMS_TMP" | awk '{print $1}' | head -1)"
  if [ -n "$want" ]; then
    got="$(sha256sum "$TMP" | awk '{print $1}')"
    if [ "$got" != "$want" ]; then
      echo "校验失败：SHA256 不匹配（期望 $want，实际 $got），已中止安装。"
      exit 1
    fi
    echo "SHA256 校验通过：$got"
  else
    echo "提示：SHA256SUMS 中没有 $ASSET 的条目，跳过完整性校验。"
  fi
else
  echo "提示：该版本没有 SHA256SUMS，跳过完整性校验。"
fi

# 端口被占就直接失败，别让 enable --now 起一个 bind 失败的服务再靠 Restart=always 反复重启
if command -v ss >/dev/null 2>&1 && ss -ltn "( sport = :${PORT} )" 2>/dev/null | grep -q LISTEN; then
  echo "端口 $PORT 已被其他进程占用。请用 PORT=别的端口 重跑，或先停掉占用者。"
  exit 1
fi

# 换二进制前先停服务并留一份可回滚的备份：旧实现直接 install 覆盖，
# 新产物起不来时 set -e 会在后面某步退出，留下「服务已停 + 旧程序已没了」的状态
systemctl stop fileserver 2>/dev/null || true
BIN_BAK=""
if [ -x "$BIN" ]; then
  BIN_BAK="$BIN.$(date +%Y%m%d-%H%M%S).bak"
  cp -a "$BIN" "$BIN_BAK" && echo "已备份当前版本到 $BIN_BAK"
fi
install -m 0755 "$TMP" "$BIN"
rm -f "$TMP"

# ---------- 服务账号与目录 ----------
# 这是一个直接吃上传流量的服务，用 root 跑等于把「被利用后的爆炸半径」
# 扩大到整台机器；建专用系统账号并只放开它需要的两个目录
FS_USER_NAME="${FS_SERVICE_USER:-fileserver}"
if ! id -u "$FS_USER_NAME" >/dev/null 2>&1; then
  useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$FS_USER_NAME" 2>/dev/null \
    || echo "提示：创建系统用户 $FS_USER_NAME 失败，服务将以 root 运行"
fi
mkdir -p "$DIR" "$DATA_DIR"
if id -u "$FS_USER_NAME" >/dev/null 2>&1; then
  chown -R "$FS_USER_NAME:$FS_USER_NAME" "$DATA_DIR" 2>/dev/null || true
  # 文件目录只在属主仍是默认值时改：已经是别人/别的目录时不动用户的数据
  chown "$FS_USER_NAME:$FS_USER_NAME" "$DIR" 2>/dev/null || true
  chmod 0750 "$DATA_DIR" 2>/dev/null || true
fi

# ---------- 配置 ----------
# 重跑/升级时保留用户已改过的配置（MAX_UPLOAD_MB/LOG/TRUST_PROXY 等），
# 只有当前会话没给、env 文件里也没有的键才写默认值
prev_max_upload="$(read_env_val MAX_UPLOAD_MB)"
prev_log="$(read_env_val LOG)"
prev_proxy="$(read_env_val TRUST_PROXY)"
prev_data_dir="$(read_env_val DATA_DIR)"
prev_trusted="$(read_env_val TRUSTED_PROXIES)"
[ -n "$prev_max_upload" ] || prev_max_upload=0
[ -n "$prev_log" ] || prev_log=1
[ -n "$prev_proxy" ] || prev_proxy="$FS_PROXY"
[ -n "$prev_data_dir" ] || prev_data_dir="$DATA_DIR"
[ -n "$prev_trusted" ] || prev_trusted="$FS_TRUSTED_CIDRS"

# 值统一用双引号包住（systemd 与 shell 的 source 都能正确解出带空格的路径），
# 读取时 read_env_val 会先把两侧引号剥掉 —— 老版本「写时加引号、读时留引号」
# 会让每次重跑多套一层引号，最终 AUTH_USER=""admin""，升级即锁死自己
if printf '%s' "$FS_PASS" | grep -qE '["`$\\]'; then
  echo "密码里含 \" \` \$ \\ 这类字符，写入 env 文件会被 shell/systemd 重新解释。"
  echo "请换一个，或安装后手工编辑 $ENVFILE。"
  exit 1
fi
cat > "$ENVFILE" <<EOF
PORT=$PORT
HOST=0.0.0.0
# ROOT_DIR 仅在首次初始化（config.json 不存在）时生效，之后以网页配置为准
ROOT_DIR="$DIR"
DATA_DIR="$prev_data_dir"
# 是否采信 X-Forwarded-* / X-Real-IP。0 = 不采信（直连暴露端口时必须保持 0）
TRUST_PROXY=$prev_proxy
# 打开上面这项后，除环回外还有哪些网段算自己的代理（CIDR 逗号分隔）。
# 留空表示只信同机反代；docker 网桥之类的来源必须显式列在这里
TRUSTED_PROXIES="$prev_trusted"
AUTH_USER="$FS_USER"
AUTH_PASS="$FS_PASS"
MAX_UPLOAD_MB=$prev_max_upload
LOG=$prev_log
EOF
chmod 0600 "$ENVFILE"

# ---------- systemd ----------
# 这个 unit 与 deploy/fileserver.service 保持一致的口径：专用账号 + 基本沙箱。
# 不用 ProtectSystem=strict/full —— 那会把 /usr 挂成只读，页面里的「一键更新」
# 替换自身二进制（/usr/local/bin/fileserver）必然失败
cat > "$SERVICE" <<EOF
[Unit]
Description=Self-hosted File Server
After=network.target

[Service]
Type=simple
User=$FS_USER_NAME
Group=$FS_USER_NAME
EnvironmentFile=$ENVFILE
ExecStart=$BIN
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  if systemctl enable --now fileserver; then
    sleep 1
    systemctl --no-pager status fileserver | head -12 || true
  elif [ -n "$BIN_BAK" ]; then
    # 新二进制起不来就回滚，不能把机器留在「服务已停、程序是坏的」状态
    echo "启动失败，回滚到旧版本 $BIN_BAK"
    install -m 0755 "$BIN_BAK" "$BIN"
    systemctl reset-failed fileserver 2>/dev/null || true
    systemctl restart fileserver 2>/dev/null || true
    exit 1
  else
    echo "启动失败，且没有可回滚的旧版本备份。请 systemctl status fileserver 查原因。"
    exit 1
  fi
else
  echo "未检测到 systemd（容器/精简系统），已跳过服务注册。"
  # 非 systemd 分支也必须加载配置文件，否则认证/端口/目录全走默认值
  LOGF=/var/log/fileserver.log
  touch "$LOGF" && chmod 0600 "$LOGF" || LOGF="$BIN.log" # /var/log 不可写时退回当前路径，别把日志丢进世界可读的 /tmp
  echo "手动启动：set -a; source $ENVFILE; set +a; setsid $BIN >$LOGF 2>&1 &"
  set -a
  # shellcheck disable=SC1090
  . "$ENVFILE"
  set +a
  setsid "$BIN" >"$LOGF" 2>&1 &
  sleep 1
fi

# ---------- 完成 ----------
IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
[ -z "$IP" ] && IP="服务器IP"
echo
echo "============================================"
echo "  部署完成"
echo "  本机访问:  http://127.0.0.1:$PORT"
echo "  局域网:    http://$IP:$PORT"
echo "  配置:      $ENVFILE（改完 systemctl restart fileserver）"
echo "  日志:      journalctl -u fileserver -f"
echo "============================================"
if [ -z "$FS_USER" ]; then
  echo "  警告：未设置访问密码，任何人都能管理文件！"
  echo "  设置方法：修改 $ENVFILE 里的 AUTH_USER/AUTH_PASS 后执行 systemctl restart fileserver"
fi
if [ -n "$FIREWALL_MSG" ]; then
  echo "$FIREWALL_MSG"
else
  echo "未检测到 ufw/firewalld，若访问不通请放行端口 $PORT/tcp"
fi
echo
echo "上 HTTPS（Nginx 反代，可选）："
echo "  apt install -y nginx certbot python3-certbot-nginx"
echo "  # 把 deploy/nginx.conf 放到 /etc/nginx/conf.d/ 并改域名，然后："
echo "  certbot --nginx -d 你的域名"
