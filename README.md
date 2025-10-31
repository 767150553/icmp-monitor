# ICMP 监控程序（Windows + Linux）

用于检测哪些主机正在对本机进行 Ping 操作（ICMP Echo 请求），支持 IPv4 与 IPv6。可输出到终端或提供 Web UI/API，并带有限频与黑名单防御能力。
<img width="1559" height="1211" alt="image" src="https://github.com/user-attachments/assets/43e087c8-1536-4bbc-bc81-cad323b93d59" />


## 目录
- 概览与功能
- 运行环境与权限
- 快速开始（Windows / Linux）
- Web UI 与认证
- 常见命令与示例
- 防御参数与默认值
- 自 Ping（回环）抓取说明
- API 一览
- 故障排查
- 构建与发布

## 概览与功能
- 枚举所有可用抓包设备并在其上监听 ICMP/ICMPv6。
- 仅记录目标为本机 IP 的 Echo 请求（避免无关流量）。
- 实时事件输出（人类可读或 JSON 行）。
- 周期性汇总来源主机、次数、最近时间、协议与网卡。
- 支持筛选网卡、设置运行时长、切换输出格式。
- 内置频率限制与黑名单防御（阈值可配置，支持声音告警）。
- 提供 Web UI 与 API，支持 HTTP 基本认证与可选 HTTPS。

## 运行环境与权限
- Windows：需安装 `Npcap`，建议以管理员权限运行。
- Linux：建议以 `root` 运行；或为二进制授予能力：
  ```bash
  sudo setcap cap_net_raw,cap_net_admin=eip ./icmp-monitor
  ```

## 快速开始
### Windows（PowerShell）
```powershell
# 启动仅本机访问的 Web UI
 .\icmp-monitor.exe -web :8080

# 启用认证（浏览器会弹出登录框）
.\icmp-monitor.exe -web :8080 -web-user user -web-token 305

# 局域网访问（监听 0.0.0.0）
.\icmp-monitor.exe' -web 0.0.0.0:8080 -web-user user -web-token 305
```
访问地址：
- 本机：`http://127.0.0.1:8080/`
- 局域网：`http://<你的主机IP>:8080/`

### Linux
```bash
# 建议使用 root 或赋能后的二进制
./icmp-monitor -web :8080
# any 设备统一抓取
sudo ./icmp-monitor -use-any -web :8080
```

## Web UI 与认证
- 启动参数 `-web :8080` 会开启 Web 服务；未传 `-web` 时只在终端输出。
- 认证：提供 `-web-user` 与 `-web-token` 时启用 HTTP Basic 认证。
- HTTPS：通过 `-tls-cert` 与 `-tls-key` 指定证书与私钥启用 HTTPS。

## 常见命令与示例
```bash
# 过滤网卡（名称或描述包含“WLAN”的设备）
./icmp-monitor -interface WLAN

# JSON 行输出与 10s 汇总
./icmp-monitor -json -summary 10s

# 运行 2 分钟后自动退出
./icmp-monitor -duration 2m

# 开启调试（打印每个事件）
./icmp-monitor -debug
```

## 防御参数（默认值）
- `-rate-limit-sec 10` 每秒最大 ICMP 请求数。
- `-rate-limit-min 100` 每分钟最大 ICMP 请求数。
- `-blacklist-time 10m` 黑名单持续时间。
- `-alert-threshold 5` 每秒告警阈值。
- `-sound-alert` 启用系统蜂鸣。
- `-whitelist` 白名单 IP（逗号分隔，白名单内跳过防御检查）。

## 自 Ping（回环）抓取说明
- 本机对自身的 Ping（例如 `ping 127.0.0.1` 或 `ping ::1`）通常走回环接口，不经过物理网卡。
- Windows：安装并启用 "Npcap Loopback Adapter" 才能抓到回环流量。
- Linux：回环设备通常为 `lo`，可通过 `-include-lo` 启用；也可使用 `-use-any` 统一抓取。
示例：
```bash
# Windows（确保存在 Npcap Loopback Adapter）
icmp-monitor -web :8080 -include-lo -web-user user -web-token 305
# Linux（包含 lo 或使用 any）
sudo icmp-monitor -include-lo
sudo icmp-monitor -use-any
```

## API 一览
- `GET /api/events?limit=50&top=20` 返回最近事件与来源汇总（如启用认证，未提供凭据返回 401）。
- `GET /api/defense` 返回防御状态与黑名单信息。

## 故障排查
- 未传 `-web` 参数：默认不启用 Web，仅在终端输出。
- 端口被占用：更换端口，如 `-web :9090`。
- 绑定地址导致无法远程访问：使用 `-web 0.0.0.0:8080`。
- 防火墙拦截：第一次对外开放时允许该程序的入站连接。
- CMD vs PowerShell：
  - CMD 直接运行：`icmp-monitor.exe -web :8080`（不要写 `./`）。
  - PowerShell 可使用相对路径：`.\nicmp-monitor.exe -web :8080`，或调用运算符：`& 'E:\ICMP\dist\icmp-monitor.exe' ...`。
- 监听自检：
  ```powershell
  netstat -ano | findstr :8080
  Test-NetConnection 127.0.0.1 -Port 8080
  ```
