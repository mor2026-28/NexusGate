# NexusGate · 枢门 (v3.4)

**NexusGate v3.4** 融合了 **NexusGate** 清爽的明暗双色响应式 UI 与强大的单机/中转节点编排及分流能力，以 **Sing-box** 为唯一轻量底层核心，专为 **低内存、小硬盘 VPS、专线/公网中转机与全协议落地机** 打造。

- **极致轻量与防爆内存**：零第三方 npm 依赖（纯 Node.js 原生标准库驱动），面板常驻内存仅 **~25 MB**，内置定时日志截断、Systemd Journald 64MB 自动轮转与缓存回收机制。
- **全协议入站与出站**：原生支持 **VLESS (Reality Vision / TLS / WS / gRPC / HTTPUpgrade)**、**AnyTLS (Sing-box 1.12+)**、**Hysteria 2 (HY2)**、**Shadowsocks (AES-128-GCM / AES-256-GCM / ChaCha20)**、**Shadowsocks 2022 (2022-blake3-aes-128-gcm / 2022-blake3-aes-256-gcm)**、**SOCKS5**、**Trojan**、**VMess**、**TUIC v5** 以及 **Direct 端口转发 (隧道中转)**。
- **实时在线设备/IP 统计与严格限制**：精准解析 Sing-box Clash API (`metadata.type`) 与 Linux 内核套接字，支持 60 秒活跃会话租约统计与实时拦截（超出设定 IP 数或设备数的连接自动通过 Clash API 与 `ss -K` 双重强制断开）。
- **灵活中转编排与防误删保护**：支持在任意入站节点一键指定转发至任意中转出站节点（`Inbound ➔ Outbound` 双向自动同步），删除路由规则、节点与证书均设有二次确认弹窗防止误操作。
- **备份迁移一键恢复**：支持直接上传 `x-ui.db` 数据库文件、或包含 `/etc/x-ui/x-ui.db` + `/root/cert` + `/root/.acme.sh` 的通用 `.tar.gz` 备份包，完整还原全部入站节点、中转出站、路由转发规则、SSL 域名证书及 `acme.sh` 自动续签定时任务。

## 一键安装命令

在 Debian / Ubuntu / CentOS / AlmaLinux / Rocky / Alpine / Arch 服务器上以 `root` 权限执行：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/mor2026-28/NexusGate/main/install.sh)
```

如果你使用备用路径或指定分支，也可以执行：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/mor2026-28/NexusGate/main/scripts/install.sh)
```

## SSH 命令行运维菜单 (`nexusgate` / `ng`)

安装完成后，在 SSH 终端输入 `nexusgate` 或 `ng` 即可呼出交互式管理菜单（0–26）：

- `nexusgate` 或 `ng`：打开数字交互式管理菜单（0–26）
- `ng info`：查看当前面板访问地址、端口、安全路径、SSL 状态与节点统计
- `ng cert`：管理 SSL 证书（ACME 域名证书 / Cloudflare DNS / Let's Encrypt 短期 IP 证书 / 10 年自签证书）
- `ng bbr`：开启 BBR + FQ + HY2 64MB UDP 缓冲内核加速
- `ng migrate`：从 `/etc/x-ui/x-ui.db` 或 `/root/3xui_backup.tar.gz` 一键备份迁移恢复全部节点、中转配置与 SSL 证书
- `ng clean`：一键收缩系统日志并释放内存
- `ng update`：从 GitHub 一键拉取最新源码并平滑重启生效
