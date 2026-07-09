# Auth-WG (WireGuard 动态认证管理平台)

Auth-WG 是一个为 WireGuard 打造的高性能、企业级动态身份认证系统。它完全使用 C 语言从内核级重写了控制面，取代了传统的 `wg-quick` 脚本，让 WireGuard 具备了商业 VPN 的动态鉴权、防泄漏和生命周期管理能力。

## ✨ 核心特性

* **动态密钥签发 (PFS)**：每次登录自动在内存中生成全新的 WireGuard 密钥对（阅后即焚），设备丢失也绝不威胁内网安全。
* **Argon2id 顶级防护**：采用现代密码学标杆 Argon2id 算法哈希密码，无惧彩虹表与暴力破解。
* **死神自动收割 (Auto-Reap)**：会话到期或异常断线后，服务端后台线程自动从 Linux 内核中物理拔除过期公钥，杜绝僵尸白名单。
* **完美兼容静态节点**：无缝兼容传统的静态配置文件（如固定的服务器、旁路由），动态与静态设备在同一网段内和平共处。
* **无感知续期**：纯 C 打造的极简客户端，后台自动发起 `/renew` 续期请求，只要电脑不关机，VPN 永不断线。
* **极致轻量 Docker 部署**：采用多阶段构建的干净镜像，配置与数据库通过原生绝对路径挂载，一键部署。

---

## 🚀 1. 服务端部署指南

### 前置准备
1. 你的服务器已安装 Docker 和 Docker Compose。
2. 确保内核已加载 WireGuard 模块（Linux 5.6+ 默认自带）。
3. **🚨 极度重要**：必须在云服务商（阿里云/腾讯云/AWS等）的安全组或防火墙中，放行你规划的 WireGuard 通信端口（默认 **UDP 65432**）。

### 第一步：准备配置目录
在宿主机创建与 Linux 系统标准对齐的目录，用于存放配置和持久化数据库：
```bash
sudo mkdir -p /etc/vpn-authd /etc/wireguard /var/lib/vpn-authd
```

### 第二步：编写配置文件
从本项目的模板拷贝出真实的配置文件：
```bash
sudo cp authd.conf.example /etc/vpn-authd/authd.conf
sudo cp wg0.conf.example /etc/wireguard/wg0.conf
```
*请务必使用 `wg genkey` 生成服务端的私钥填入 `wg0.conf`，并根据实际网络规划修改两份配置文件中的网段和 IP！*

### 第三步：启动容器
在本项目根目录执行：
```bash
docker compose up -d --build
```
> **⚠️ CentOS / RHEL / Fedora 用户注意 (SELinux 陷阱)**
> 如果你的系统开启了 SELinux，Docker 挂载目录会被拦截导致读取失败。请修改 `docker-compose.yml`，在挂载路径后追加 `:z` 或 `:Z`（例如 `- /etc/vpn-authd:/etc/vpn-authd:z`）。

---

## 👥 2. 账号管理

账号管理通过容器内置的 `vpn-add-user` 工具进行，直接操作挂载出的 SQLite 数据库。

**添加或重置用户密码：**
```bash
docker exec -it vpn-authd vpn-add-user /var/lib/vpn-authd/accounts.db <用户名> <密码>
```
*示例：`docker exec -it vpn-authd vpn-add-user /var/lib/vpn-authd/accounts.db alice mypassword123`*

---

## 💻 3. 客户端使用指南

客户端是一个纯 C 编写的独立二进制文件，无需安装臃肿的 WireGuard 客户端，它会自动接管内核级网卡创建与路由下发。

### 编译客户端 (Linux)
在需要连入 VPN 的电脑上，安装编译依赖并编译：
```bash
# Ubuntu / Debian
sudo apt-get install -y cmake build-essential libcurl4-openssl-dev libcjson-dev

mkdir -p build && cd build
cmake ..
make
```

### 登录并连接 (login)
执行客户端程序（必须带 `sudo`，因涉及网卡创建与内核路由表修改）：
```bash
sudo ./client/vpn-client login <用户名> <密码> --server https://<服务端API的IP或域名>:8443
```
*(如果服务端未配置 TLS 证书，请将 https 改为 http，并在末尾加上 `--insecure`)*

只要不关闭这个终端，客户端就会在后台默默守护，到期前自动续租。

### 查看状态 (status)
新开一个终端，你可以随时查看上下行流量与剩余存活时间：
```bash
sudo ./client/vpn-client status
```

### 登出与销毁 (logout)
在刚才运行 login 的终端按下 `Ctrl+C`，或者手动执行登出：
```bash
sudo ./client/vpn-client logout
```
客户端会通知服务端立刻清理内核白名单，并彻底销毁本地的 `wg-vpn` 虚拟网卡。
