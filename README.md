# NexusGate · 枢门 Sing-box 轻量中转与节点面板 (v2.0)

**NexusGate v2.0** 融合了 **NexusGate** 极简清爽的明暗双色响应式 UI 与 **3x-ui** 强大的单机/中转节点编排与分流能力，以 **Sing-box** 为唯一轻量底层核心，专为 **低内存、小硬盘 VPS、专线/公网中转机与全协议落地机** 打造。

- **极致轻量**：零第三方 npm 依赖（纯 Node.js 原生标准库驱动），面板常驻内存仅 **~25 MB**，源码体积不足 **200 KB**。
- **全协议入站与出站**：原生支持 **VLESS (Reality Vision / TLS / WS / gRPC)**、**AnyTLS (Sing-box 1.12+)**、**Hysteria 2 (HY2)**、**Shadowsocks (AES-128-GCM / AES-256-GCM / ChaCha20)**、**Shadowsocks 2022 (2022-blake3-aes-128-gcm / 2022-blake3-aes-256-gcm)**、**SOCKS5**、**Trojan**、**VMess**、**TUIC v5** 以及 **Direct 端口转发 (Dokodemo-door 隧道中转)**。
- **灵活中转编排**：支持在任意入站节点一键指定转发至任意中转出站节点（`Inbound -> Outbound` 直接绑定）、支持粘贴外部节点链接（`vless://`、`ss://`、`hy2://`、`anytls://` 等）一键解析为中转出站、支持多跳链式代理（`detour`）。
- **3x-ui 风格分流规则**：支持按入站 Tag、域名后缀/关键词、`geosite:*`、`geoip:*`、IP CIDR、端口、协议（`bittorrent`、`quic`、`tls`、`http`）及私有网络分流，内置屏蔽广告、屏蔽 BT、大陆直连、AI（OpenAI/Claude/Gemini）与流媒体（Netflix/YouTube/Disney+）一键分流模板。
- **3x-ui 一键无损迁移**：支持直接上传 3x-ui 的 SQLite 数据库文件（`x-ui.db`）、自动扫描本机 `/etc/x-ui/x-ui.db` 或粘贴 JSON，100% 无损迁移全部入站节点（保留原端口、UUID、密码、Reality 公私钥、shortIds、证书配置、客户端流量统计）、Dokodemo 端口转发、中转出站节点与路由分流规则。
- **完善的安全与系统管理**：支持实时监控 CPU / 内存 / Swap / 硬盘 / 实时网速 / TCP&UDP 连接数；支持在线更换 Sing-box 内核版本；支持 ACME 自动签发 SSL 证书（HTTP-01 / Cloudflare DNS / 3x-ui 同款短期 IP 证书）与一键生成 10 年自签证书；支持自定义或随机面板端口、随机安全根路径（`webBasePath`）、修改管理员账号密码及 `nexusgate` (`ng`) 交互式命令行菜单。

## 一键安装命令

在 Debian / Ubuntu / CentOS / AlmaLinux / Rocky / Alpine / Arch 服务器上以 `root` 权限执行：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/mor2026-28/NexusGate/main/install.sh)
```

如果你使用备用路径或指定分支，也可以执行：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/mor2026-28/NexusGate/main/scripts/install.sh)
```

安装过程中支持直接回车自动生成**随机高位端口**、**随机管理员账号密码**与**随机安全根路径**（类似 `3x-ui`）；如果检测到本机已安装 `3x-ui`（存在 `/etc/x-ui/x-ui.db`），安装器还会提示是否**一键无损迁移全部节点与中转分流规则**。

## 支持协议矩阵

| 协议类别 | 入站搭建 (Inbound) | 中转出站 (Outbound) | 特色能力 |
| :--- | :--- | :--- | :--- |
| **VLESS** | 支持 | 支持 | 支持 Reality + XTLS Vision 免证书、TLS、WS、gRPC、HTTPUpgrade；内置毫秒级 X25519 密钥对生成 |
| **AnyTLS** | 支持 | 支持 | Sing-box 1.12+ 原生协议，支持 TLS 与自适应长度填充方案 (`padding_scheme`) |
| **Hysteria 2 (HY2)** | 支持 | 支持 | 基于 QUIC 的高速 UDP 协议，支持上下行带宽控制与 Salamander 混淆 |
| **SS 2022 (128 / 256)** | 支持 | 支持 | 支持 `2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm`、`2022-blake3-chacha20-poly1305`，一键生成合规 Base64 密钥 |
| **SS 经典 AEAD** | 支持 | 支持 | 支持 `aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305` |
| **SOCKS5** | 支持 | 支持 | 支持账号密码认证与 UDP 转发，适合前置中转或专线接入 |
| **Trojan / VMess / TUIC** | 支持 | 支持 | 全面兼容旧版与多平台客户端，支持 TLS / Reality / WS / gRPC |
| **Direct 端口转发** | 支持 | 支持 | 对应 3x-ui 的 Dokodemo-door (`tunnel`)，支持 TCP/UDP 端口直转或配合出站中转 |

## SSH 命令行运维菜单 (`nexusgate` / `ng`)

安装完成后，在 SSH 终端输入 `nexusgate` 或 `ng` 即可打开交互式管理菜单：

- `nexusgate` 或 `ng`：打开数字交互式管理菜单（1-12）
- `ng info`：查看当前面板访问地址、端口、安全路径 (`webBasePath`) 与管理员账号
- `ng account`：重置管理员登录账号与密码
- `ng port`：修改面板监听端口（支持一键随机端口）
- `ng path`：修改面板安全访问根路径（支持一键随机路径）
- `ng cert`：一键生成 10 年自签 SSL 证书或绑定已有证书开启面板 HTTPS
- `ng version`：在线切换或升级 Sing-box 内核版本
- `ng migrate`：从本机 `/etc/x-ui/x-ui.db` 一键无损迁移全部节点与中转配置
- `ng restart` / `ng stop` / `ng logs`：重启、停止服务或查看实时运行日志

## 3x-ui 无损迁移指南

1. **Web 面板上传迁移**：登录面板 → 点击左侧导航栏 **【3x-ui 无损迁移】** → 直接将备份的 `x-ui.db` 文件拖入上传框 → 可先点击 **【预览上传文件解析结果】** 核对识别出的入站、客户端、出站与分流规则数量，再点击 **【上传并立即执行无损迁移】**。
2. **本机直读迁移**：如果本机此前运行过 `3x-ui`，直接在面板点击 **【一键迁移本机 3x-ui】** 或在终端运行 `ng migrate`，面板将自动读取 `/etc/x-ui/x-ui.db` 并转换为 Sing-box 配置。
3. **JSON 粘贴迁移**：支持将 `3x-ui` 后台的 `xrayTemplateConfig` 或 `config.json` 直接粘贴至迁移框完成导入。
