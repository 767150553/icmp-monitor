# ICMP 监控程序（Windows + Linux）

用于检测哪些主机正在对本机进行 Ping 操作（ICMP Echo 请求），支持 IPv4 与 IPv6。

## 功能

- 枚举所有可用抓包设备并在其上监听 ICMP/ICMPv6
- 仅记录目标为本机 IP 的 Echo 请求（避免无关流量）
- 实时事件输出（人类可读或 JSON 行）
- 周期性汇总来源主机、次数、最近时间、协议与网卡
- 支持筛选网卡、设置运行时长、切换输出格式
- 内置频率限制与黑名单防御（阈值可配置，支持声音告警）
- 提供 Web UI 与 API，支持 HTTP 基本认证与可选 HTTPS

## 运行环境与权限

- Windows：需安装 [Npcap](https://npcap.com/)，建议以管理员权限运行。
- Linux：建议以 `root` 运行；或为二进制授予能力：
  ```bash
  sudo setcap cap_net_raw,cap_net_admin=eip ./icmp-monitor
  ```

## 构建与运行

```bash
# 在项目根目录
go run .
# 或构建
go build -o icmp-monitor
```

## 常用参数

```bash
# 启动 Web UI（默认仅本机接口）
./icmp-monitor -web :8080

# 启用 Basic 认证（浏览器会弹出认证框）
./icmp-monitor -web :8080 -web-user user -web-token 305

# 启用 HTTPS（需提供证书与私钥）
./icmp-monitor -web :8443 -tls-cert server.crt -tls-key server.key \
  -web-user user -web-token 305

# 包含回环设备（自 Ping 检测需要）
./icmp-monitor -include-lo

# 使用 Linux 的 any 设备（汇聚所有接口）
./icmp-monitor -use-any

# 仅监听名称或描述包含“WLAN”的设备（子串匹配）
./icmp-monitor -interface WLAN

# JSON 行输出事件与 10s 汇总
./icmp-monitor -json -summary 10s

# 运行 2 分钟后自动退出
./icmp-monitor -duration 2m

# 开启调试（打印每个事件）
./icmp-monitor -debug
```

## Web 认证与安全

- 访问首页与 API 时，若提供了 `-web-user/-web-token`，将触发 HTTP Basic 认证挑战。
- 建议在局域网内使用或配合 `-tls-cert/-tls-key` 启用 HTTPS，避免明文凭据暴露。
- 认证参数：用户名通过 `-web-user` 指定，密码/令牌通过 `-web-token` 指定。

## 自 Ping 检测

- 本机对自身的 Ping（例如 `ping 127.0.0.1` 或 `ping ::1`）通常走回环接口，不经过物理网卡。
- 在 Windows 环境，需要安装并启用 "Npcap Loopback Adapter" 才能抓到回环流量。
- 在 Linux 环境，回环设备名称通常为 `lo`，可通过 `-include-lo` 启用；也可使用 `-use-any` 统一抓取。
- 启动示例：
  ```bash
  # Windows（确保 Npcap Loopback Adapter 存在）
  icmp-monitor -web :8080 -include-lo -web-user user -web-token 305

  # Linux（包含 lo 或使用 any）
  sudo icmp-monitor -include-lo
  sudo icmp-monitor -use-any
  ```
- 验证方式：在同一台主机执行 `ping 127.0.0.1` 与 `ping ::1`，然后在浏览器或终端调用 `/api/events`，应能看到来源与目标为本机地址的记录。

## 防御参数说明

- `-rate-limit-sec` 每秒最大 ICMP 请求数（默认 10）。
- `-rate-limit-min` 每分钟最大 ICMP 请求数（默认 100）。
- `-blacklist-time` 进入黑名单的持续时间（默认 10m）。
- `-alert-threshold` 每秒告警阈值（默认 5）。
- `-sound-alert` 是否启用声音告警（系统蜂鸣）。
- `-whitelist` 白名单 IP（逗号分隔，白名单内跳过防御检查）。

## 说明与局限

- 程序通过 libpcap/Npcap/WinPcap 进行抓包，并使用 gopacket 解析。
- 仅统计 Echo Request（ICMPv4 type 8，ICMPv6 type 128），不包含 Echo Reply。
- 若看不到事件，请检查：
  - 是否有主机正在 ping 本机；
  - 是否启用了回环设备（自 Ping 检测）；
  - 是否具备抓包权限（Windows 需管理员，Linux 需 root 或相应能力）。

## API

- `GET /api/events?limit=50&top=20` 返回最近事件与来源汇总（需认证时返回 401 并附带 WWW-Authenticate）。
- `GET /api/defense` 返回防御状态与黑名单信息。

## 浏览器访问

- 浏览器访问首页：`http://127.0.0.1:8080/`；若启用认证，将弹出登录框。
- 若启用 HTTPS：`https://127.0.0.1:8443/`，首次访问可能提示不受信任的证书（自签）。
