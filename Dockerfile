
 # 使用三方源的Go 镜像作为基础镜像
#FROM hub.rat.dev/library/golang:1.22 AS builder
FROM golang:1.22 AS builder
# RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories
# 设置工作目录
WORKDIR /app

ENV GOPROXY=https://goproxy.cn,direct
# 将本地文件复制到容器中的工作目录
COPY . .

# 下载项目的依赖包
RUN go mod tidy

# 编译项目
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o myapp .

# 使用一个更小的基础镜像来运行应用程序
FROM alpine:3.18

# 设置工作目录
WORKDIR /app

# 从构建阶段复制二进制文件到这个镜像
COPY --from=builder /app/myapp .
COPY config_prod.yaml .
COPY config_dev.yaml .
# 复制证书与私钥
COPY cert.pem key.pem ./
 # 如果需要，可以复制其他文件，例如配置文件
# COPY --from=builder /app/config_prod.yaml .

# 暴露应用程序使用的端口（假设应用程序在 8080 端口运行）
EXPOSE 2002

 # 运行应用程序
CMD ["./myapp", "--config=config_prod.yaml"]
