#!/usr/bin/env bash
set -Eeuo pipefail

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
cyan='\033[0;36m'
plain='\033[0m'

REPO="${NG_REPO:-mor2026-28/NexusGate}"
BRANCH="${NG_BRANCH:-main}"
SB_VERSION="${NG_SINGBOX_VERSION:-1.12.23}"
INSTALL_DIR="/opt/nexusgate"
DATA_DIR="/var/lib/nexusgate"
CONF_DIR="/etc/nexusgate"

die() { echo -e "${red}[错误]${plain} $*" >&2; exit 1; }
info() { echo -e "${cyan}[NexusGate]${plain} $*"; }
ok() { echo -e "${green}[成功]${plain} $*"; }
warn() { echo -e "${yellow}[提示]${plain} $*"; }

[[ "${EUID}" -eq 0 ]] || die "请使用 root 权限运行此安装脚本 (sudo -i)"

gen_random_str() {
  local len="${1:-16}"
  openssl rand -base64 64 2>/dev/null | tr -dc 'a-zA-Z0-9' | cut -c1-"$len" | tr -d '\r\n '
}

gen_random_port() {
  shuf -i 15000-60000 -n 1 2>/dev/null || echo $(( (RANDOM % 45000) + 15000 ))
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|x64|amd64) echo "amd64" ;;
    aarch64|arm64|armv8*) echo "arm64" ;;
    armv7*|arm) echo "armv7" ;;
    *) die "不支持的 CPU 架构: $(uname -m)" ;;
  esac
}

install_dependencies() {
  info "正在检查并安装轻量系统依赖 (curl, tar, openssl, sqlite3, python3, nodejs)..."
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq || true
    apt-get install -y -qq ca-certificates curl tar openssl sqlite3 python3
    if ! command -v node >/dev/null 2>&1 || (( $(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0) < 18 )); then
      info "安装 Node.js 20 LTS 运行时..."
      curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null 2>&1 || true
      apt-get install -y -qq nodejs
    fi
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q ca-certificates curl tar openssl sqlite python3 nodejs
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q ca-certificates curl tar openssl sqlite python3 nodejs
  elif command -v apk >/dev/null 2>&1; then
    apk update && apk add --no-cache ca-certificates curl tar openssl sqlite python3 nodejs
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm ca-certificates curl tar openssl sqlite python nodejs
  fi

  command -v node >/dev/null 2>&1 || die "Node.js 安装失败，请先安装 Node.js >= 18"
}

install_singbox_binary() {
  local arch
  arch="$(detect_arch)"
  local ver="${SB_VERSION#v}"
  local tarball="sing-box-${ver}-linux-${arch}.tar.gz"
  local url="https://github.com/SagerNet/sing-box/releases/download/v${ver}/${tarball}"

  if [[ -x /usr/local/bin/sing-box ]]; then
    info "检测到已安装 Sing-box: $(/usr/local/bin/sing-box version | head -n 1 || true)"
    return 0
  fi

  info "正在下载官方 Sing-box v${ver} (${arch}) 轻量内核..."
  local tmp
  tmp="$(mktemp -d /tmp/ng-sb.XXXXXX)"
  if curl -fL --retry 3 --connect-timeout 15 "$url" -o "$tmp/$tarball"; then
    tar -xzf "$tmp/$tarball" -C "$tmp" --strip-components=1
    install -m 0755 "$tmp/sing-box" /usr/local/bin/sing-box
    ok "Sing-box v${ver} 内核安装完成 (/usr/local/bin/sing-box)"
  else
    warn "自动下载 Sing-box Release 失败，稍后可在面板或执行 ng 手动切换版本"
  fi
  rm -rf -- "$tmp"
}

download_panel_source() {
  local tmp
  tmp="$(mktemp -d /tmp/nexusgate-src.XXXXXX)"
  trap 'rm -rf -- "$tmp"' RETURN

  if [[ -f "./server.js" && -f "./public/app.js" ]]; then
    info "检测到当前目录包含完整源码，直接从本地复制安装..."
    mkdir -p "$INSTALL_DIR"
    cp -a ./* "$INSTALL_DIR/"
  else
    info "正在从 GitHub (${REPO}@${BRANCH}) 下载最新面板源码..."
    curl -fL --retry 3 "https://github.com/${REPO}/archive/refs/heads/${BRANCH}.tar.gz" -o "$tmp/source.tar.gz"
    mkdir -p "$INSTALL_DIR"
    tar -xzf "$tmp/source.tar.gz" -C "$INSTALL_DIR" --strip-components=1
  fi

  [[ -f "$INSTALL_DIR/server.js" ]] || die "安装包不完整，未找到 server.js"
}

enable_bbr_and_hy2_tuning() {
  info "正在优化内核网络参数 (启用 BBR + FQ 队列与 Hysteria 2 64MB UDP 高速缓冲区)..."
  modprobe tcp_bbr 2>/dev/null || true
  mkdir -p /etc/sysctl.d
  cat > /etc/sysctl.d/99-nexusgate-acceleration.conf <<'EOF'
# NexusGate Sing-box BBR + FQ + HY2 Kernel Tuning
fs.file-max = 2097152
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 250000
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 10240 65535
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 2097152
net.core.wmem_default = 2097152
EOF
  sysctl --system >/dev/null 2>&1 || true
}

configure_panel() {
  mkdir -p "$DATA_DIR" "$CONF_DIR/sing-box" "$CONF_DIR/certs" /root/cert
  chmod 0700 "$DATA_DIR" "$CONF_DIR"

  systemctl stop nexusgate.service 2>/dev/null || true

  local default_port default_user default_pass default_path
  default_port="$(gen_random_port)"
  default_user="ng_$(gen_random_str 10)"
  default_pass="$(gen_random_str 18)"
  default_path="/$(gen_random_str 16)/"

  local panel_port="$default_port"
  local admin_user="$default_user"
  local admin_pass="$default_pass"
  local base_path="$default_path"

  if [[ -r /dev/tty && "${NG_NONINTERACTIVE:-0}" != "1" ]]; then
    echo ""
    echo -e "${cyan}=== NexusGate Sing-box 面板初始化安全配置 (直接回车使用高强度随机值，同 3x-ui) ===${plain}"
    read -r -p "请输入面板端口 [默认随机: ${default_port}]: " input_port </dev/tty || true
    [[ -n "${input_port:-}" ]] && panel_port="${input_port//[^0-9]/}"

    read -r -p "请输入管理员账号 [默认随机: ${default_user}]: " input_user </dev/tty || true
    [[ -n "${input_user:-}" ]] && admin_user="$(echo "$input_user" | tr -d '\r\n ')"

    read -r -p "请输入管理员密码 [默认随机 18 位: ${default_pass}]: " input_pass </dev/tty || true
    [[ -n "${input_pass:-}" ]] && admin_pass="$(echo "$input_pass" | tr -d '\r\n ')"

    read -r -p "请输入面板 16 位安全路径 [默认随机: ${default_path}]: " input_path </dev/tty || true
    [[ -n "${input_path:-}" ]] && base_path="$(echo "$input_path" | tr -d '\r\n ')"
  fi

  local pub_ip=""
  pub_ip="$(curl -fsSL4 --max-time 5 https://api.ipify.org 2>/dev/null || curl -fsSL4 --max-time 5 https://ip.sb 2>/dev/null || hostname -I | awk '{print $1}')"
  pub_ip="$(echo "$pub_ip" | tr -d '\r\n ')"

  cat > "${CONF_DIR}/nexusgate.env" <<EOF
NODE_ENV=production
NG_DATA_FILE=${DATA_DIR}/nexusgate.json
NG_SINGBOX_BIN=/usr/local/bin/sing-box
NG_SINGBOX_CONFIG=${CONF_DIR}/sing-box/config.json
EOF
  chmod 0600 "${CONF_DIR}/nexusgate.env"

  rm -rf /etc/nexusgate/certs/www.bing.com /root/cert/www.bing.com 2>/dev/null || true

  NG_DATA_FILE="${DATA_DIR}/nexusgate.json" node "$INSTALL_DIR/server.js" --set-account "$admin_user" "$admin_pass" >/dev/null
  NG_DATA_FILE="${DATA_DIR}/nexusgate.json" node "$INSTALL_DIR/server.js" --set-port "$panel_port" >/dev/null
  NG_DATA_FILE="${DATA_DIR}/nexusgate.json" node "$INSTALL_DIR/server.js" --set-path "$base_path" >/dev/null

  if [[ -n "$pub_ip" ]]; then
    python3 - "$DATA_DIR/nexusgate.json" "$pub_ip" <<'PY' 2>/dev/null || true
import json, sys
p, ip = sys.argv[1], sys.argv[2]
d = json.load(open(p))
d.setdefault("settings", {})["publicIPv4"] = ip.strip()
json.dump(d, open(p, "w"))
PY
  fi

  # Auto-detect existing ACME domain cert first; if none exists, generate 10-year self-signed cert
  NG_DATA_FILE="${DATA_DIR}/nexusgate.json" node "$INSTALL_DIR/server.js" --issue-selfsigned "www.apple.com" "$pub_ip" >/dev/null

  # Auto-detect existing 3x-ui database or backup archive
  if [[ -f /etc/x-ui/x-ui.db || -f /root/3xui_backup.tar.gz ]]; then
    local found_xui="/etc/x-ui/x-ui.db"
    [[ ! -f "$found_xui" && -f /root/3xui_backup.tar.gz ]] && found_xui="/root/3xui_backup.tar.gz"
    warn "检测到本机已存在 3x-ui 数据 (${found_xui})！"
    local do_mig="y"
    if [[ -r /dev/tty && "${NG_NONINTERACTIVE:-0}" != "1" ]]; then
      read -r -p "是否立即无损迁移 3x-ui 全部入站节点、中转出站与分流规则？[Y/n]: " do_mig </dev/tty || true
    fi
    if [[ "${do_mig:-y}" =~ ^[Yy]?$ ]]; then
      NG_DATA_FILE="${DATA_DIR}/nexusgate.json" node "$INSTALL_DIR/server.js" --migrate-3xui "$found_xui" merge || warn "自动迁移可在登录面板后通过【3x-ui 无损迁移】页面操作"
    fi
  fi

  # Open firewall ports automatically across ufw / firewalld / iptables
  NG_DATA_FILE="${DATA_DIR}/nexusgate.json" node "$INSTALL_DIR/server.js" --open-firewall >/dev/null 2>&1 || true

  # Setup systemd services & CLI symlinks
  install -m 0644 "$INSTALL_DIR/systemd/nexusgate.service" /etc/systemd/system/nexusgate.service
  install -m 0644 "$INSTALL_DIR/systemd/nexusgate-singbox.service" /etc/systemd/system/nexusgate-singbox.service
  install -m 0755 "$INSTALL_DIR/nexusgate.sh" /usr/local/bin/nexusgate
  ln -sf /usr/local/bin/nexusgate /usr/local/bin/ng
  if [[ ! -e /usr/local/bin/x-ui ]]; then
    ln -sf /usr/local/bin/nexusgate /usr/local/bin/x-ui
  fi

  if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    systemctl daemon-reload
    systemctl enable --now nexusgate.service
    systemctl restart nexusgate.service
    systemctl enable --now nexusgate-singbox.service || true
    systemctl restart nexusgate-singbox.service || true
  else
    pkill -f "node $INSTALL_DIR/server.js" 2>/dev/null || true
    nohup env NG_DATA_FILE="${DATA_DIR}/nexusgate.json" node "$INSTALL_DIR/server.js" >/var/log/nexusgate.log 2>&1 &
  fi

  local info_json login_url cert_domain
  info_json="$(NG_DATA_FILE="${DATA_DIR}/nexusgate.json" node "$INSTALL_DIR/server.js" --show-info)"
  login_url="$(echo "$info_json" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("url",""))' 2>/dev/null || echo "")"
  cert_domain="$(echo "$info_json" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("defaultNodeTlsDomain",""))' 2>/dev/null || echo "")"

  echo ""
  echo -e "${green}==================================================================${plain}"
  echo -e "${green} 🎉 NexusGate Sing-box 轻量中转面板 v2.3 安装成功！${plain}"
  echo -e "${green}==================================================================${plain}"
  echo -e " 面板访问地址 : ${cyan}${login_url}${plain}"
  echo -e " 面板端口     : ${yellow}${panel_port}${plain}"
  echo -e " 安全根路径   : ${yellow}${base_path}${plain} (已启用安全模式：单 IP+端口 禁止直接访问)"
  echo -e " 管理员账号   : ${green}${admin_user}${plain}"
  echo -e " 管理员密码   : ${green}${admin_pass}${plain}"
  echo -e " 默认证书域名 : ${green}${cert_domain}${plain}"
  echo -e " 内核加速状态 : ${green}已开启 BBR + FQ + HY2 64MB UDP 缓冲优化${plain}"
  echo -e " SSH 管理命令 : 输入 ${cyan}ng${plain} 或 ${cyan}nexusgate${plain} 呼出 0-25 完整管理菜单 (同 3x-ui)"
  echo -e "${green}==================================================================${plain}"
}

install_dependencies
install_singbox_binary
enable_bbr_and_hy2_tuning
download_panel_source
configure_panel
