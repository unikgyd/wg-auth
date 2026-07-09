# 阶段一：编译环境 (Builder)
FROM debian:12-slim AS builder

# 安装编译依赖
RUN apt-get update && apt-get install -y \
    build-essential cmake pkg-config \
    libsqlite3-dev libsodium-dev libmicrohttpd-dev libmnl-dev libcjson-dev

# 复制源码
WORKDIR /app
COPY . .

# 编译项目
RUN mkdir -p build && cd build && \
    cmake .. && \
    make

# 阶段二：运行环境 (Runner)
FROM debian:12-slim

# 安装运行时依赖 (包含 iptables 供可能的路由配置使用)
RUN apt-get update && apt-get install -y \
    libsqlite3-0 libsodium23 libmicrohttpd12 libmnl0 libcjson1 \
    iptables iproute2 procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 从 builder 复制编译好的二进制文件
COPY --from=builder /app/build/server/vpn-authd /usr/local/bin/
COPY --from=builder /app/build/server/vpn-add-user /usr/local/bin/

# 预创建挂载点所需的空目录
RUN mkdir -p /etc/vpn-authd /etc/wireguard /var/lib/vpn-authd

# 设置默认环境变量
ENV VPN_CONF=/etc/vpn-authd/authd.conf

# 启动服务端
CMD ["sh", "-c", "/usr/local/bin/vpn-authd $VPN_CONF"]
