FROM golang:1.27-alpine AS builder

ARG COMMIT=unknown
ARG BUILD_TIME=unknown

WORKDIR /src

COPY go.mod go.sum ./

RUN go mod download && go mod verify

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w \
        -X fdfz-student-id/internal/cfg.Commit=${COMMIT} \
        -X fdfz-student-id/internal/cfg.BuildTime=${BUILD_TIME}" \
    -trimpath \
    -o ./server \
    ./cmd/server/main.go

FROM alpine AS runtime

WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata curl \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && echo "Asia/Shanghai" > /etc/timezone \
    && apk del tzdata

RUN addgroup -S ffhub && adduser -S ffhub -G ffhub

# 运行用户需要写权限的目录：
#   - /app/shared：共享文件目录（SHARED_DIR），含上传临时目录；
#   - /app/storage：storage.EnsureDir() 创建的本地临时目录（相对 WORKDIR 的 ./storage）。
# 注意：必须显式创建并 chown，否则非 root 用户启动时 MkdirAll 会因 EACCES 直接退出。
RUN mkdir -p /app/shared /app/storage && chown -R ffhub:ffhub /app/shared /app/storage

USER ffhub

COPY --from=builder /src/server /app/server

EXPOSE 11400

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/healthz || exit 1

ENV APP_ENV=prod
ENV SHARED_DIR="./shared"
VOLUME /app/shared

ENTRYPOINT ["/app/server"]
