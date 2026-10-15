# ---------- 构建阶段 ----------
FROM golang:1.24-alpine AS build
WORKDIR /src
# 传 --build-arg VERSION=v1.2.3 注入真实版本号；默认 dev 为非发布版本，
# 网页会显示「非发布版本」并禁用一键更新（容器里替换二进制 + 重启没有意义）
ARG VERSION=dev
COPY go.mod *.go ./
COPY public ./public
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION} -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o /out/fileserver .

# ---------- 运行阶段 ----------
FROM alpine:3.21

LABEL org.opencontainers.image.title="fileserver" \
      org.opencontainers.image.description="自建文件服务：上传/删除/带 token 的限时限次分享链接"

COPY --from=build /out/fileserver /usr/local/bin/fileserver

# 以非 root 运行：这是一个直接吃上传流量的服务，root 容器里一旦被利用，
# 挂进来的目录之外还会再多一层可写的东西（/etc、/usr/local/bin）
RUN addgroup -g 1000 -S app && adduser -u 1000 -S -G app app \
    && mkdir -p /app/data /files && chown -R 1000:1000 /app/data /files

# 运行期数据（配置 + 分享记录）与文件目录。
# 注意：新建的命名卷会继承上面这份属主；但 compose 里那种 ./files 绑定挂载
# 用的是宿主机目录的属主，必须保证它对 uid 1000 可写（或在自己的 compose
# 里用 `user:` 覆盖成宿主机用户，见 docker-compose.yml）
ENV DATA_DIR=/app/data \
    ROOT_DIR=/files \
    PORT=8080 \
    # 默认不识别反代头：端口被 -p 直接发布时，直连来源是 docker 网桥（内网地址），
    # 旧默认 TRUST_PROXY=1 会把客户端送来的 X-Real-IP 当成真实来源
    TRUST_PROXY=0

VOLUME ["/files", "/app/data"]
EXPOSE 8080

USER 1000:1000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1 || exit 1

CMD ["fileserver"]
