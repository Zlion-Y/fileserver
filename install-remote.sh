#!/usr/bin/env bash
# =============================================================
#  文件服务 —— Linux 服务器一键部署
#  自动识别 CPU 架构 → 从 GitHub Release 下载对应二进制 → 注册 systemd 开机自启
#
#  用法（在服务器上执行）：
#    sudo bash install-remote.sh
#    sudo FS_USER=admin FS_PASS=123456 bash install-remote.sh     # 同时开启访问密码
#    sudo DIR=/mnt/disk/share PORT=9000 bash install-remote.sh    # 自定义目录与端口
#    sudo VERSION=v1.0.0 bash install-remote.sh                   # 指定版本
#    sudo bash install-remote.sh --dry-run                        # 只看会做什么，不改系统
#    sudo bash install-remote.sh --uninstall                      # 卸载（保留文件与分享记录）
#
#  可用环境变量：
#    DIR        文件根目录      默认 /data/files
#    DATA_DIR   配置/分享记录    默认 /var/lib/fileserver（务必持久化）
#    PORT       监听端口        默认 16666
#    FS_USER    管理端用户名     默认不启用认证（公网务必设置）
#    FS_PASS    管理端密码
#    FS_PROXY   1=信任反代头     默认 1（Nginx/Caddy 后面必开）
#    VERSION    Release 版本     默认取最新版
#    REPO       GitHub 仓库      默认 Zlion-Y/fileserver
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
FS_PROXY="${FS_PROXY:-1}"
VERSION="${VERSION:-}"
DRY=0
UNINSTALL=0
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "未知参数: $a"; exit 1 ;;
  esac
done

[ "$(id -u)" = "0" ] || { echo "请用 root 执行：sudo bash $0"; exit 1; }
[ "$(uname -s)" = "Linux" ] || { echo "仅支持 Linux 服务器（本机是 $(uname -s)）"; exit 1; }

BIN=/usr/local/bin/fileserver
SERVICE=/etc/systemd/system/fileserver.service
ENVFILE="${ENVFILE:-/etc/fileserver.env}"

# ---------- 卸载 ----------
if [ "$UNINSTALL" = 1 ]; then
  echo "== 卸载 =="
  systemctl stop fileserver 2>/dev/null || true
  systemctl disable fileserver 2>/dev/null || true
  rm -f "$SERVICE" "$BIN"
  systemctl daemon-reload 2>/dev/null || true
  echo "已卸载程序。数据仍保留在：$DATA_DIR（分享记录）与 $DIR（文件）"
  exit 0
fi

# ---------- 识别架构 ----------
detect_target() {
  local m; m="$(uname -m)"
  case "$m" in
    x86_64|amd64)      echo linux_amd64 ;;
    aarch64|arm64)     echo linux_arm64 ;;
    armv7*|armv6*|armhf) echo linux_armv7 ;;
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
  VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
             | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name":[[:space:]]*"([^"]+)".*/\1/' || true)"
fi
[ -n "$VERSION" ] || { echo "取不到最新版本号（服务器无法访问 GitHub？）。可先手动指定：sudo VERSION=v1.0.0 bash $0"; exit 1; }

ASSET="fileserver_${TARGET}"
URL="https://github.com/$REPO/releases/download/$VERSION/$ASSET"

# 重跑/升级时继承已有配置，避免忘记带参数导致认证被清空、目录被改回默认值
if [ -f "$ENVFILE" ]; then
  prev_user="$(grep -E '^AUTH_USER=' "$ENVFILE" 2>/dev/null | cut -d= -f2- || true)"
  prev_pass="$(grep -E '^AUTH_PASS=' "$ENVFILE" 2>/dev/null | cut -d= -f2- || true)"
  prev_dir="$(grep -E '^ROOT_DIR=' "$ENVFILE" 2>/dev/null | cut -d= -f2- || true)"
  prev_port="$(grep -E '^PORT=' "$ENVFILE" 2>/dev/null | cut -d= -f2- || true)"
  [ -z "$FS_USER" ] && FS_USER="$prev_user"
  [ -z "$FS_PASS" ] && FS_PASS="$prev_pass"
  [ -z "$DIR_GIVEN" ] && [ -n "$prev_dir" ] && DIR="$prev_dir"
  [ -z "$PORT_GIVEN" ] && [ -n "$prev_port" ] && PORT="$prev_port"
fi

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
echo "下载中..."
if ! curl -fsSL "$URL" -o "$TMP"; then
  rm -f "$TMP"
  echo "下载失败：$URL"
  echo "可能原因：该版本没有此架构的产物，或服务器访问不了 GitHub。"
  echo "可手动下载后上传：https://github.com/$REPO/releases"
  exit 1
fi
[ -s "$TMP" ] || { rm -f "$TMP"; echo "下载到空文件"; exit 1; }

systemctl stop fileserver 2>/dev/null || true
install -m 0755 "$TMP" "$BIN"
rm -f "$TMP"
"$BIN" --help >/dev/null 2>&1 || true

# ---------- 目录与配置 ----------
mkdir -p "$DIR" "$DATA_DIR"
cat > "$ENVFILE" <<EOF
PORT=$PORT
HOST=0.0.0.0
# ROOT_DIR 仅在首次初始化（config.json 不存在）时生效，之后以网页配置为准
ROOT_DIR=$DIR
DATA_DIR=$DATA_DIR
TRUST_PROXY=$FS_PROXY
AUTH_USER=$FS_USER
AUTH_PASS=$FS_PASS
MAX_UPLOAD_MB=0
LOG=1
EOF
chmod 0600 "$ENVFILE"

# ---------- systemd ----------
cat > "$SERVICE" <<'EOF'
[Unit]
Description=Self-hosted File Server
After=network.target

[Service]
Type=simple
EnvironmentFile=/etc/fileserver.env
ExecStart=/usr/local/bin/fileserver
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  systemctl enable --now fileserver
  sleep 1
  systemctl --no-pager status fileserver | head -12 || true
else
  echo "未检测到 systemd（容器/精简系统），已跳过服务注册。"
  echo "手动启动：setsid $BIN >/var/log/fileserver.log 2>&1 &"
  setsid "$BIN" >/tmp/fileserver.log 2>&1 &
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
