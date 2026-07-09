# 混合认证 WireGuard VPN 服务 - 项目设计文档

## 1. 项目概述

在标准 WireGuard(纯公钥认证)基础上,叠加一层账号认证控制面,实现:

- **固定设备**:通过静态配置文件直接写入 wg 接口,长期有效,行为与原生 WireGuard 完全一致。
- **临时设备**:通过账号密码登录,由服务端动态生成 keypair、分配 IP、写入 wg 接口 peer 列表;登出或 session 过期后自动从 wg 接口移除该 peer。
- **数据面不变**:无论 peer 是静态写入还是动态添加,内核 WireGuard 接口(`wg0`)对它们一视同仁,协议层仍是纯 Noise_IKpsk2 密钥认证,账号系统只负责"谁在什么时间点能拥有哪个 peer 条目",不改变、不弱化协议本身的安全模型。
- **保留互通(mesh)能力**:所有已连接设备(无论固定还是临时)之间可以直接互相访问,不仅仅是设备到服务端/出口网络。

服务端只做 Linux,配置文件驱动,账号数据用 SQLite 存储。不涉及 Android/Windows 等客户端平台细节,聚焦服务端与协议/控制面设计。

---

## 2. 目标与非目标

### 目标
- 复用标准 WireGuard 内核模块,不修改协议、不修改内核。
- 固定设备走传统 `.conf` 静态配置,行为 100% 兼容原生 wg-quick。
- 临时设备走账号认证 HTTP API,动态签发/回收 key 和 peer 配置。
- 所有 peer 之间保持二层/三层可达(mesh-like),而不仅仅是 hub-to-spoke 出网。
- 全部用 C 实现(控制面 API 服务、wg 控制逻辑、数据库访问),不引入 Go。

### 非目标(本阶段不做)
- 不做多服务器/多节点的分布式路由同步。
- 不做客户端 GUI/移动端细节(单独文档处理)。
- 不做证书体系(mTLS 客户端证书),账号认证走用户名密码 + Token 即可。

---

## 3. 总体架构

```
                        ┌───────────────────────────────────────────┐
                        │              Linux 服务器                   │
                        │                                             │
   固定设备(电脑)         │  ┌───────────────┐      ┌────────────────┐ │
  (标准 wg .conf) ───────┼─▶│ wg0.conf 静态段 │─────▶│                │ │
   直接握手连接            │  └───────────────┘      │   wg0 内核接口   │ │
                        │                          │ (embeddable-wg- │ │
                        │  ┌───────────────┐       │  library 管理)   │ │
   临时设备 ──HTTPS登录──┼─▶│ 控制面 API (C) │──netlink▶│                │ │
   (账号密码认证)         │  │ auth/wg_ctl/  │       └────────────────┘ │
                        │  │ ip_pool/db     │              │           │
                        │  └───────┬───────┘              │           │
                        │          │                        │           │
                        │     ┌────▼────┐          IP转发+防火墙规则     │
                        │     │ SQLite  │          (允许peer间互访)      │
                        │     │ 账号/会话 │                              │
                        │     └─────────┘                              │
                        └───────────────────────────────────────────┘
```

关键点:临时设备的账号认证只发生在"控制面"(HTTPS API),一旦拿到配置(私钥+服务端公钥+AllowedIPs等)之后,实际隧道连接走的是标准 wg 协议握手,不再依赖账号系统在线与否——账号系统只决定 peer 存在与否,不参与每次连接的握手过程。

---

## 4. 配置文件设计

服务端使用两类配置文件:一类是标准 wg 接口配置(静态 peer 段),一类是控制面自身的运行配置。

### 4.1 `/etc/wireguard/wg0.conf`(标准 WireGuard 接口配置,含固定设备静态 peer)

```ini
[Interface]
PrivateKey = <服务端私钥>
Address = 10.8.0.1/16
ListenPort = 51820
# 由控制面在启动时读取本文件的 [Peer] 段,一次性写入内核,之后不再触碰这些条目

# ------- 固定设备(静态,由管理员手工维护) -------
[Peer]
# 电脑A
PublicKey = <电脑A公钥>
PresharedKey = <可选>
AllowedIPs = 10.8.0.2/32

[Peer]
# 电脑B
PublicKey = <电脑B公钥>
AllowedIPs = 10.8.0.3/32
```

说明:
- 地址段规划为 `10.8.0.0/16`,统一大段,固定设备与临时设备共用同一子网,天然支持互访(见第 6 节)。
- 固定设备段用 `10.8.0.2 ~ 10.8.0.254`(管理员手工分配,数量少)。
- 临时设备段由 IP 池自动分配,比如 `10.8.1.0 ~ 10.8.255.254`。

### 4.2 `/etc/vpn-authd/authd.conf`(控制面运行配置,自定义格式,ini 风格,程序自行解析)

```ini
[server]
wg_interface = wg0
wg_conf_path = /etc/wireguard/wg0.conf
endpoint_public_addr = vpn.example.com:51820
dns = 10.8.0.1

[api]
listen_addr = 0.0.0.0
listen_port = 8443
tls_cert = /etc/vpn-authd/tls/fullchain.pem
tls_key  = /etc/vpn-authd/tls/privkey.pem

[db]
path = /var/lib/vpn-authd/accounts.db

[ip_pool]
cidr = 10.8.1.0/23
exclude = 10.8.0.0/24    ; 排除固定设备段

[session]
default_ttl_seconds = 43200      ; 12小时
renew_grace_seconds = 300
reap_interval_seconds = 60       ; 后台扫描过期session的周期

[security]
argon2_time_cost = 3
argon2_mem_cost_kb = 65536
```

程序启动流程:
1. 解析 `authd.conf`。
2. 打开/初始化 SQLite 数据库(如不存在则建表)。
3. 读取 `wg0.conf`,解析出 `[Interface]` 与所有静态 `[Peer]` 段,调用 `wg_set_device` 一次性写入内核(等价于 `wg-quick up wg0`,但由控制面自身完成,不依赖 shell 脚本)。
4. 启动 HTTPS API 服务,同时启动后台线程做 session 过期扫描。

---

## 5. 数据库设计(SQLite)

```sql
-- 账号表
CREATE TABLE accounts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,       -- Argon2id 编码字符串
    created_at    INTEGER NOT NULL,
    disabled      INTEGER NOT NULL DEFAULT 0
);

-- 会话/临时设备表:一次登录对应一个临时peer
CREATE TABLE sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id      INTEGER NOT NULL REFERENCES accounts(id),
    device_pubkey   TEXT NOT NULL,      -- base64,本次登录生成的临时公钥
    allowed_ip      TEXT NOT NULL,      -- 分配到的 /32 地址
    session_token   TEXT UNIQUE NOT NULL,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    revoked         INTEGER NOT NULL DEFAULT 0,
    last_seen_at    INTEGER
);

-- 审计日志(可选但建议)
CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id  INTEGER,
    action      TEXT NOT NULL,     -- login/logout/renew/expired/revoke
    detail      TEXT,
    created_at  INTEGER NOT NULL
);

CREATE INDEX idx_sessions_expires ON sessions(expires_at);
CREATE INDEX idx_sessions_token   ON sessions(session_token);
```

设计要点:
- **私钥不入库**。临时设备的私钥仅在生成时短暂存在于服务端内存中,通过响应体一次性下发给客户端后,立即用 `sodium_memzero` 清零,数据库只保留公钥。
- `sessions` 表一行 = 一个当前活跃的临时 peer,`revoked=1` 或 `expires_at` 已过 = 该 peer 应从 wg0 移除。
- 支持同一账号多设备同时登录:只需不限制同一 `account_id` 对应多条 `sessions` 记录即可(如需限制并发数,在登录时查询该账号未过期 session 数量做校验)。

---

## 6. 网络规划与设备互访(保留原生 WireGuard 能力)

WireGuard 本身的转发规则由每个 peer 的 `AllowedIPs` 决定:服务端会把目的地址匹配某个 peer `AllowedIPs` 的包转发给该 peer。要让所有设备(固定+临时)互相访问,做法如下:

### 6.1 AllowedIPs 策略

- 服务端侧(写入内核的 peer 表)每个 peer 的 `AllowedIPs` 只需是**该 peer 自己的 /32**(如上面配置示例),这样服务端知道"这个地址应该发给谁"。
- **客户端侧**下发的配置里,`AllowedIPs` 要设置为整个 VPN 网段(如 `10.8.0.0/16`),而不是只有 `0.0.0.0/0` 指向服务端出网。客户端把整个网段的流量都发往服务端,由服务端根据自己 peer 表里的 `/32` 规则再转发给目标设备。

临时设备登录后下发的配置示例(由 client-core 使用,非用户手工编辑):

```ini
[Interface]
PrivateKey = <服务端生成并下发的临时私钥>
Address = 10.8.1.5/32
DNS = 10.8.0.1

[Peer]
PublicKey = <服务端公钥>
Endpoint = vpn.example.com:51820
AllowedIPs = 10.8.0.0/16      ; 整个VPN网段,而非仅0.0.0.0/0
PersistentKeepalive = 25
```

如果同时还需要访问公网(常规VPN出网),可以把 `AllowedIPs` 追加为 `0.0.0.0/0, ::/0`,由服务端做 NAT 出网,互不冲突。

### 6.2 服务端内核与防火墙设置

```bash
# 开启转发
sysctl -w net.ipv4.ip_forward=1

# nftables 示例:允许 wg0 接口内部互相转发
nft add rule inet filter forward iifname "wg0" oifname "wg0" accept

# 如果还需要NAT出网(可选)
nft add rule inet nat postrouting oifname "eth0" masquerade
```

这样固定设备与临时设备、临时设备与临时设备之间的流量都会在服务端完成路由转发,实现"局域网化"的互访效果,同时不需要给每个 peer 手动加对方的 `AllowedIPs`(避免 N×N 手工维护)。

### 6.3 IP 池管理(临时设备)

- 用一个位图(bitmap)或简单的 SQLite 表标记 `10.8.1.0/23` 内哪些 `/32` 已被占用。
- 登录时分配:找到第一个空闲位,标记占用,写入 `sessions.allowed_ip`。
- 登出/过期时回收:清除对应位标记。
- 并发安全:用一把互斥锁包住"查找+标记"这一整个操作,避免竞态下两个登录请求拿到同一个 IP。

---

## 7. 服务端模块设计(C 语言)

```
server/
├── src/
│   ├── main.c            # 启动:解析配置→初始化DB→加载静态peer→起HTTPS服务→起reaper线程
│   ├── config.c/.h       # 解析 authd.conf 和 wg0.conf
│   ├── wg_ctl.c/.h       # 封装 embeddable-wg-library:add/remove peer, 加载静态段
│   ├── auth.c/.h         # 账号密码校验(argon2)、session token生成校验
│   ├── db.c/.h           # sqlite3 封装:accounts/sessions/audit_log 的 CRUD
│   ├── ip_pool.c/.h      # 位图式IP分配与回收,互斥锁保护
│   ├── api_handlers.c/.h # HTTP路由处理:/login /logout /renew /status
│   ├── reaper.c/.h       # 后台线程:定期扫描过期session并调用wg_ctl移除
│   └── util.c/.h         # base64、随机数生成、日志
├── third_party/
│   └── wireguard.h/.c    # 官方 embeddable-wg-library(直接vendoring)
├── CMakeLists.txt
```

依赖库:
- `libmicrohttpd` 或 `civetweb` — HTTPS 服务
- `cJSON` — 请求/响应 JSON
- `libsodium` — Argon2id 密码哈希、Ed25519/X25519 密钥与随机数、内存清零
- `sqlite3` — 账号与会话存储
- `embeddable-wg-library`(`wireguard.h/.c`) — netlink 方式管理 wg0 设备与 peer

### 7.1 wg_ctl 关键接口

```c
// 启动时加载 wg0.conf 中的静态 peer,一次性写入内核
int wgctl_load_static_config(const char *ifname, const char *conf_path);

// 添加一个临时账号 peer
int wgctl_add_peer(const char *ifname,
                    const uint8_t pubkey[WG_KEY_LEN],
                    const uint8_t psk[WG_KEY_LEN],
                    const char *allowed_ip_cidr);   // 如 "10.8.1.5/32"

// 移除一个临时账号 peer(登出/过期/强制踢线共用)
int wgctl_remove_peer(const char *ifname, const uint8_t pubkey[WG_KEY_LEN]);

// 查询某peer当前流量统计(用于/status接口)
int wgctl_get_peer_stats(const char *ifname, const uint8_t pubkey[WG_KEY_LEN],
                          uint64_t *rx_bytes, uint64_t *tx_bytes);
```

### 7.2 reaper 线程逻辑

```
每隔 reap_interval_seconds:
    SELECT * FROM sessions WHERE revoked=0 AND expires_at < now()
    对每一条:
        wgctl_remove_peer(ifname, session.device_pubkey)
        ip_pool_release(session.allowed_ip)
        UPDATE sessions SET revoked=1 WHERE id=...
        INSERT INTO audit_log(action='expired', ...)
```

---

## 8. API 接口设计

### `POST /login`

请求:
```json
{ "username": "alice", "password": "xxxx" }
```

服务端流程:
1. 查 `accounts` 表,校验密码(argon2 verify)。
2. 生成一对临时 X25519 keypair。
3. 生成随机 PresharedKey。
4. 调用 `ip_pool_allocate()` 拿到空闲 `/32`。
5. 调用 `wgctl_add_peer()` 写入内核。
6. 生成 `session_token`(随机 32 字节,base64url 编码),写入 `sessions` 表,`expires_at = now + default_ttl_seconds`。
7. 私钥用完立即从服务端内存清零(响应发出后)。

响应:
```json
{
  "session_token": "……",
  "client_private_key": "……",
  "client_address": "10.8.1.5/32",
  "server_public_key": "……",
  "preshared_key": "……",
  "endpoint": "vpn.example.com:51820",
  "allowed_ips": "10.8.0.0/16",
  "dns": "10.8.0.1",
  "expires_at": 1730000000
}
```

### `POST /renew`

```json
{ "session_token": "……" }
```
校验 token 未过期/未撤销,延长 `expires_at`。

### `POST /logout`

```json
{ "session_token": "……" }
```
调用 `wgctl_remove_peer` + `ip_pool_release` + 标记 `revoked=1`。

### `GET /status`(需携带 token)

返回当前 session 的连接状态、流量统计(调用 `wgctl_get_peer_stats`),供客户端展示。

---

## 9. 安全设计要点

- **密码存储**:Argon2id,禁止明文/弱哈希(md5/sha1/单轮sha256)。
- **传输安全**:控制面 API 强制 TLS,不提供 HTTP 明文端口。
- **私钥最小暴露**:服务端不持久化临时设备私钥,只保留公钥;下发后内存清零。
- **Session Token**:随机性来自 `libsodium` 的 CSPRNG,不可预测;数据库存 token 本身即可(不需要额外哈希,因为 token 本身已是高熵随机值,可视同已加盐哈希的等效物;如需更严格可以只存 token 的哈希,校验时哈希后比对)。
- **限流与防爆破**:`/login` 接口按 IP/账号维度做失败次数限制(应用层实现,比如连续失败5次锁定该账号10分钟)。
- **审计**:所有 login/logout/renew/expired/revoke 动作写 `audit_log`,便于事后排查异常登录。
- **PresharedKey**:每个动态 peer 都配一个随机 PSK,增加一层对称密钥防护。
- **固定设备与账号系统完全隔离**:静态 peer 不受 session 生命周期管理影响,管理员手工维护,账号系统的任何 bug 都不会波及固定设备的连接。

---

## 10. 开发路线图

1. **阶段一:核心数据面验证**
   - 编写 `wgctl_load_static_config`,验证程序启动即可复现 `wg-quick up wg0` 的效果(固定设备可直接连接)。
   - 编写 `wgctl_add_peer` / `wgctl_remove_peer`,手动构造一对 keypair 测试动态增删。

2. **阶段二:账号与数据库**
   - 建 SQLite 表结构,实现 `db.c` 的 CRUD。
   - 实现 Argon2id 注册/登录校验(先写一个命令行小工具插入测试账号)。

3. **阶段三:API 与 IP 池**
   - 接入 `libmicrohttpd`,实现 `/login /logout /renew /status`。
   - 实现 `ip_pool.c` 的位图分配与并发保护。

4. **阶段四:后台任务与健壮性**
   - 实现 reaper 线程,验证过期 session 能被正确踢出内核 peer 表。
   - 补充审计日志、失败限流。

5. **阶段五:互访与网络验证**
   - 配置 nftables 转发规则,验证固定设备↔临时设备、临时设备↔临时设备之间可以互相 ping 通。
   - 压测:多个临时设备同时登录/登出,观察 IP 池与 wg0 peer 表是否保持一致(无泄漏、无冲突)。

---

## 11. 附:关键第三方组件清单

| 组件 | 用途 | 语言 |
|---|---|---|
| embeddable-wg-library (`wireguard.h/.c`) | netlink 方式管理 wg0 内核设备 | C |
| libsodium | 密钥生成、Argon2id、内存清零 | C |
| sqlite3 | 账号/会话持久化 | C |
| libmicrohttpd 或 civetweb | HTTPS API 服务 | C |
| cJSON | JSON 编解码 | C |
| nftables/iptables | 转发与NAT规则 | 系统工具,非代码依赖 |

全流程不引入 Go,数据面完全依赖 Linux 内核原生 WireGuard 模块 + embeddable-wg-library 控制,协议安全性与原生 WireGuard 完全一致。
