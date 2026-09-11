#!/usr/bin/env bash
# =============================================================
#  交叉编译：把 Go 版打包成各平台单个可执行文件（无需任何运行时依赖）
#  用法:
#    bash build.sh                      编译全部常用平台
#    bash build.sh linux/amd64 linux/arm/5
#    PLATFORMS="linux/arm/5" bash build.sh
#    VERSION=v1.2.0 bash build.sh
#  产物输出在 dist-go/
# =============================================================
set -euo pipefail

NAME="fileserver"
VERSION="${VERSION:-v1.0.0}"
OUT="${OUT:-dist-go}"
GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LDFLAGS="-s -w -X main.version=${VERSION} -X main.commit=${GIT_COMMIT} -X main.buildTime=${BUILD_TIME}"

# 目标平台（GOOS/GOARCH[/GOARM|GOAMD64 变体]）
DEFAULT_PLATFORMS="
linux/amd64
linux/arm64
linux/arm/7
linux/arm/5
linux/386
linux/mipsle
windows/amd64
darwin/arm64
"
PLATFORMS="${PLATFORMS:-$DEFAULT_PLATFORMS}"

command -v go >/dev/null 2>&1 || { echo "未检测到 Go，请先安装: https://go.dev/dl/ (apt/yum 安装亦可)"; exit 1; }
command -v gofmt >/dev/null 2>&1 && gofmt -l . | grep -v '^public/' || true

mkdir -p "$OUT"
echo "编译目标: $(echo $PLATFORMS)"
echo

for p in $PLATFORMS; do
  GOOS="${p%%/*}"
  rest="${p#*/}"
  GOARCH="${rest%%/*}"
  variant=""
  if [ "$rest" != "$GOARCH" ]; then variant="${rest#*/}"; fi
  [ "$GOOS" = "$p" ] && { echo "跳过非法目标: $p"; continue; }

  export CGO_ENABLED=0 GOOS GOARCH
  unset GOARM GOAMD64 GOMIPS GO386 2>/dev/null || true
  ARM_LDFLAGS=""

  suffix="${GOOS}_${GOARCH}"
  case "$GOARCH" in
    arm)
      if [ -n "$variant" ]; then export GOARM="$variant"; suffix="${suffix}v${variant}"; else export GOARM=7; suffix="${suffix}v7"; fi
      # GOARM 不是 runtime 公开 API，产物名/版本接口需要时经 ldflags 注入
      ARM_LDFLAGS="-X main.goarmBuild=${GOARM}"
      ;;
    amd64) [ -n "$variant" ] && export GOAMD64="$variant" ;;
    mips*)
      # 老路由器（MT7621 等）多为软浮点，默认 softfloat 更稳；需要硬浮点可写 linux/mipsle/hardfloat
      if [ -n "$variant" ]; then export GOMIPS="$variant"; else export GOMIPS=softfloat; fi
      ;;
    386) [ -n "$variant" ] && export GO386="$variant" ;;
  esac

  bin="$OUT/${NAME}_${suffix}"
  if [ "$GOOS" = "windows" ]; then bin="${bin}.exe"; fi

  printf '  -> %-28s' "$(basename "$bin")"
  if go build -trimpath -ldflags "$LDFLAGS $ARM_LDFLAGS" -o "$bin" . 2>/tmp/goerr; then
    printf 'OK  %s\n' "$(du -h "$bin" | cut -f1)"
  else
    printf '失败\n'; cat /tmp/goerr; exit 1
  fi
done

echo
echo "产物目录: $OUT"
ls -lh "$OUT" | tail -n +2 | awk '{printf "  %-28s %s\n", $9, $5}'
echo
echo "运行示例（Linux 服务器）:"
echo "  scp $OUT/${NAME}_linux_amd64 root@server:/usr/local/bin/fileserver"
echo "  ssh root@server 'chmod +x /usr/local/bin/fileserver && fileserver --port 16666 --dir /data/files --user admin --pass 123456'"
