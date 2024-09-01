

# 使用官方的 Go 镜像作为基础镜像
FROM golang:1.20
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories
# 设置工作目录
WORKDIR /app

# 将本地文件复制到容器中的工作目录
COPY . .

# 下载项目的依赖包
RUN go mod tidy

# 编译项目
RUN go build -o myapp

# 指定容器启动时运行的命令
CMD ["./myapp"]
