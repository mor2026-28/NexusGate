# NexusGate · 枢门 Sing-box 轻量中转与节点面板 (v2.6)

**NexusGate v2.6** 融合了 **NexusGate** 清爽的明暗双色响应式 UI 与强大的单机/中转节点编排及分流能力，以 **Sing-box** 为唯一轻量底层核心，专为 **低内存、小硬盘 VPS、专线/公网中转机与全协议落地机** 打造。

- **极致轻量与防爆内存**：零第三方 npm 依赖（纯 Node.js 原生标准库驱动），面板常驻内存仅 **~25 MB**，内置定时日志截断、Systemd Journald 64MB 自动轮转与缓存回收机制。
- **全协议入站与出站**：原生支持 **VLESS (Reality Vision / TLS / WS / gRPC / HTTPUpgrade)**、**AnyTLS (Sing-box 1.12+)**、**Hysteria 2 (HY2)**、**Shadowsocks (AES-128-GCM / AES-256-GCM / ChaCha20)**、**Shadowsocks 2022 (2022-blake3-aes-128-gcm / 2022-blake3-aes-256-gcm)**、**SOCKS5**、**Trojan**、**VMess**、**TUIC v5** 以及 **Direct 端口转发 (隧道中转)**。
- **灵活中转编排**：支持在任意入站节点一键指定转发至任意中转出站节点（`Inbound ➔ Outbound` 双向自动同步）、支持批量粘贴外部节点链接（`vless://`、`ss://`、`hy2://`、`anytls://` 等）一键解析为中转出站、支持多跳链式代理（`detour`）。
- **智能分流规则**：支持按入站 Tag、域名后缀/关键词、`geosite:*`、`geoip:*`、IP CIDR、端口、协议（`bittorrent`、`quic`、`tls`、`http`）及私有网络分流，默认内置禁止私有内网探测与禁 BT 规则，并提供 AI 专线、外贸跨境、流媒体与屏蔽广告一键分流预设。
- **3x-ui / X-Panel 通用备份一键无损迁移**：支持直接上传 `x-ui.db` 数据库文件、或包含 `/etc/x-ui/x-ui.db` + `/root/cert` + `/root/.acme.sh` 的通用 `.tar.gz` 备份包，100% 无损还原全部入站节点（完整保留原端口、UUID、密码、Reality 公私钥与 SNI、WS+TLS 路径与 ALPN、客户端流量统计与配额）、中转出站节点、路由转发规则、SSL 域名证书及 `acme.sh` 自动续签定时任务。
- **高强度安全防护**：支持面板随机端口、16 位随机安全根路径（默认禁止单 `IP+端口` 直接访问面板）、18 位随机管理员密码，以及 **20 位高强度随机安全码 (`subToken`) 聚合订阅防扫描保护**。

## 一键安装命令

在 Debian / Ubuntu / CentOS / AlmaLinux / Rocky / Alpine / Arch 服务器上以 `root` 权限执行：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/mor2026-28/NexusGate/main/install.sh)
```

如果你使用备用路径或指定分支，也可以执行：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/mor2026-28/NexusGate/main/scripts/install.sh)
```

## 支持协议矩阵

| 协议类别 | 入站搭建 (Inbound) | 中转出站 (Outbound) | 特色能力 |
| :--- | :--- | :--- | :--- |
| **VLESS** | 支持 | 支持 | 支持 Reality + XTLS Vision 免证书、TLS、WS、gRPC、HTTPUpgrade；内置毫秒级 X25519 密钥对生成 |
| **AnyTLS** | 支持 | 支持 | Sing-box 1.12+ 原生协议，支持 TLS 与自适应长度填充方案 (`padding_scheme`) |
| **Hysteria 2 (HY2)** | 支持 | 支持 | 基于 QUIC 的高速 UDP 协议，支持上下行带宽控制与 Salamander 混淆 |
| **SS 2022 (128 / 256)** | 支持 | 支持 | 支持 `2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm`、`2022-blake3-chacha20-poly1305`，一键生成合规 Base64 密钥 |
| **SS 经典 AEAD** | 支持 | 支持 | 支持 `aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305` |
| **SOCKS5** | 支持 | 支持 | 支持账号密码认证与 UDP 转发，适合前置中转或专线接入 |
| **Trojan / VMess / TUIC** | 支持 | 支持 | 全面兼容多平台客户端，支持 TLS / Reality / WS / gRPC |
| **Direct 端口转发** | 支持 | 支持 | 支持 TCP/UDP 端口直转或配合出站中转 |

## SSH 命令行运维菜单 (`nexusgate` / `ng`)

安装完成后，在 SSH 终端输入 `nexusgate` 或 `ng` 即可呼出交互式管理菜单（0–26）：

- `nexusgate` 或 `ng`：打开数字交互式管理菜单（0–26）
- `ng info`：查看当前面板访问地址、端口、安全路径、SSL 状态与节点统计
- `ng cert`：管理 SSL 证书（ACME 域名证书 / Cloudflare DNS / Let's Encrypt 短期 IP 证书 / 10 年自签证书）
- `ng bbr`：开启 BBR + FQ + HY2 64MB UDP 缓冲内核加速
- `ng migrate`：从 `/etc/x-ui/x-ui.db` 或 `/root/3xui_backup.tar.gz` 一键无损迁移全部节点、中转配置与 SSL 证书
- `ng clean`：一键收缩系统日志并释放内存
- `ng update`：从 GitHub 一键拉取最新源码并平滑重启生效
