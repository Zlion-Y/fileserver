# ---------- 构建阶段 ----------
FROM golang:1.22-alpine AS build
WORKDIR /src
# 传 --build-arg VERSION=v1.2.3 注入真实版本号；默认 dev 为非发布版本，
# 网页会显示「非发布版本」并禁用一键更新（容器里替换二进制 + 重启没有意义）
ARG VERSION=dev
COPY go.mod main.go ./
COPY public ./public
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION} -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o /out/fileserver .

# ---------- 运行阶段 ----------
FROM alpine:3.20

LABEL org.opencontainers.image.title="fileserver" \
      org.opencontainers.image.description="自建文件服务：上传/删除/带 token 的限时限次分享链接"

COPY --from=build /out/fileserver /usr/local/bin/fileserver

# 运行期数据（配置 + 分享记录）与文件目录
RUN mkdir -p /app/data /files
ENV DATA_DIR=/app/data \
    ROOT_DIR=/files \
    PORT=8080 \
    TRUST_PROXY=1

VOLUME ["/files", "/app/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1 || exit 1

CMD ["fileserver"]
