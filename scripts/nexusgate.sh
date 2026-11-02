#!/usr/bin/env bash
set -Eeuo pipefail

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
cyan='\033[0;36m'
plain='\033[0m'

REPO="${NG_REPO:-mor2026-28/NexusGate}"
BRANCH="${NG_BRANCH:-main}"
INSTALL_DIR="/opt/nexusgate"
DATA_FILE="${NG_DATA_FILE:-/var/lib/nexusgate/nexusgate.json}"

die() { echo -e "${red}[错误]${plain} $*" >&2; exit 1; }
info() { echo -e "${cyan}[NexusGate]${plain} $*"; }
ok() { echo -e "${green}[成功]${plain} $*"; }

need_root() { [[ "${EUID}" -eq 0 ]] || die "请使用 root 运行此命令"; }

show_info() {
  NG_DATA_FILE="$DATA_FILE" node "$INSTALL_DIR/server.js" --show-info
}

change_account() {
  need_root
  local u="" p=""
  read -r -p "请输入新的管理员账号: " u </dev/tty
  read -r -p "请输入新的管理员密码: " p </dev/tty
  [[ -n "$u" && -n "$p" ]] || die "账号和密码不能为空"
  NG_DATA_FILE="$DATA_FILE" node "$INSTALL_DIR/server.js" --set-account "$u" "$p"
  systemctl restart nexusgate.service 2>/dev/null || true
  ok "管理员账号密码已更新并生效！"
}

change_port() {
  need_root
  local rand_port=$(( (RANDOM % 45000) + 15000 ))
  local p=""
  read -r -p "请输入新的面板端口 [直接回车使用随机端口 ${rand_port}]: " p </dev/tty
  p="${p:-$rand_port}"
  NG_DATA_FILE="$DATA_FILE" node "$INSTALL_DIR/server.js" --set-port "$p"
  systemctl restart nexusgate.service 2>/dev/null || true
  ok "面板端口已更改为: ${p}"
}

change_path() {
  need_root
  local rand_str
  rand_str="$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | fold -w 8 | head -n 1 || echo 'secret88')"
  local bp=""
  read -r -p "请输入新的面板安全根路径 [回车使用随机路径 /${rand_str}/ ，输入 / 则关闭后缀]: " bp </dev/tty
  bp="${bp:-/$rand_str/}"
  NG_DATA_FILE="$DATA_FILE" node "$INSTALL_DIR/server.js" --set-path "$bp"
  systemctl restart nexusgate.service 2>/dev/null || true
  ok "面板安全根路径已更改为: ${bp}"
}

setup_cert() {
  need_root
  echo -e "${cyan}1.${plain} 一键生成 10 年自签 SSL 证书并绑定到面板"
  echo -e "${cyan}2.${plain} 指定服务器已有的证书与私钥路径"
  echo -e "${cyan}3.${plain} 关闭面板 HTTPS (恢复 HTTP 访问)"
  local c=""
  read -r -p "请选择 [1-3]: " c </dev/tty
  if [[ "$c" == "1" ]]; then
    mkdir -p /etc/nexusgate/certs/panel
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 3650 -nodes \
      -subj "/CN=NexusGate" \
      -keyout /etc/nexusgate/certs/panel/privkey.pem \
      -out /etc/nexusgate/certs/panel/fullchain.pem
    chmod 600 /etc/nexusgate/certs/panel/privkey.pem
    NG_DATA_FILE="$DATA_FILE" node "$INSTALL_DIR/server.js" --set-cert "/etc/nexusgate/certs/panel/fullchain.pem" "/etc/nexusgate/certs/panel/privkey.pem"
    systemctl restart nexusgate.service 2>/dev/null || true
    ok "自签 SSL 证书已生成并绑定至面板 HTTPS！"
  elif [[ "$c" == "2" ]]; then
    local cf="" kf=""
    read -r -p "公钥证书路径 (fullchain.pem): " cf </dev/tty
    read -r -p "私钥文件路径 (privkey.pem): " kf </dev/tty
    [[ -f "$cf" && -f "$kf" ]] || die "证书或私钥文件不存在"
    NG_DATA_FILE="$DATA_FILE" node "$INSTALL_DIR/server.js" --set-cert "$cf" "$kf"
    systemctl restart nexusgate.service 2>/dev/null || true
    ok "自定义 SSL 证书已绑定至面板 HTTPS！"
  elif [[ "$c" == "3" ]]; then
    NG_DATA_FILE="$DATA_FILE" node "$INSTALL_DIR/server.js" --set-cert "" ""
    systemctl restart nexusgate.service 2>/dev/null || true
    ok "已恢复为 HTTP 模式"
  fi
}

switch_singbox_version() {
  need_root
  local ver=""
  read -r -p "请输入要安装的 Sing-box 版本号 [默认 1.12.23]: " ver </dev/tty
  ver="${ver:-1.12.23}"
  ver="${ver#v}"
  local arch="amd64"
  case "$(uname -m)" in
    aarch64|arm64) arch="arm64" ;;
    armv7*) arch="armv7" ;;
  esac
  local tmp
  tmp="$(mktemp -d /tmp/ng-sb-up.XXXXXX)"
  local url="https://github.com/SagerNet/sing-box/releases/download/v${ver}/sing-box-${ver}-linux-${arch}.tar.gz"
  info "正在下载 ${url} ..."
  curl -fL --retry 3 "$url" -o "$tmp/sb.tar.gz"
  tar -xzf "$tmp/sb.tar.gz" -C "$tmp" --strip-components=1
  install -m 0755 "$tmp/sing-box" /usr/local/bin/sing-box
  rm -rf -- "$tmp"
  systemctl restart nexusgate-singbox.service 2>/dev/null || true
  ok "Sing-box 内核已成功切换至: $(/usr/local/bin/sing-box version | head -n 1)"
}

migrate_3xui() {
  need_root
  local db_path="/etc/x-ui/x-ui.db"
  read -r -p "请输入 3x-ui 数据库路径 [默认 /etc/x-ui/x-ui.db]: " input_db </dev/tty || true
  [[ -n "${input_db:-}" ]] && db_path="$input_db"
  NG_DATA_FILE="$DATA_FILE" node "$INSTALL_DIR/server.js" --migrate-3xui "$db_path" merge
  systemctl restart nexusgate-singbox.service 2>/dev/null || true
}

update_panel() {
  need_root
  info "正在从 GitHub (${REPO}@${BRANCH}) 更新 NexusGate 面板..."
  local tmp
  tmp="$(mktemp -d /tmp/ng-update.XXXXXX)"
  curl -fL --retry 3 "https://github.com/${REPO}/archive/refs/heads/${BRANCH}.tar.gz" -o "$tmp/src.tar.gz"
  tar -xzf "$tmp/src.tar.gz" -C "$INSTALL_DIR" --strip-components=1
  install -m 0755 "$INSTALL_DIR/nexusgate.sh" /usr/local/bin/nexusgate
  rm -rf -- "$tmp"
  systemctl restart nexusgate.service 2>/dev/null || true
  ok "NexusGate 面板已更新至最新版本！"
}

uninstall_panel() {
  need_root
  read -r -p "确定要卸载 NexusGate 面板吗？[y/N]: " confirm </dev/tty
  [[ "$confirm" =~ ^[Yy]$ ]] || exit 0
  systemctl stop nexusgate.service nexusgate-singbox.service 2>/dev/null || true
  systemctl disable nexusgate.service nexusgate-singbox.service 2>/dev/null || true
  rm -f /etc/systemd/system/nexusgate.service /etc/systemd/system/nexusgate-singbox.service
  systemctl daemon-reload 2>/dev/null || true
  rm -rf "$INSTALL_DIR" /usr/local/bin/nexusgate /usr/local/bin/ng
  ok "NexusGate 面板已卸载（数据文件保留在 /var/lib/nexusgate 以防误删）"
}

menu() {
  clear || true
  echo -e "${cyan}┌──────────────────────────────────────────────────────────┐${plain}"
  echo -e "${cyan}│      NexusGate · 枢门 Sing-box 轻量中转管理脚本 v2.0     │${plain}"
  echo -e "${cyan}├──────────────────────────────────────────────────────────┤${plain}"
  echo -e "  ${green}1.${plain} 查看面板当前配置与访问链接 (info)"
  echo -e "  ${green}2.${plain} 修改管理员账号与密码 (account)"
  echo -e "  ${green}3.${plain} 修改面板端口 / 随机端口 (port)"
  echo -e "  ${green}4.${plain} 修改面板安全根路径 / 随机路径 (path)"
  echo -e "  ${green}5.${plain} 配置面板 SSL 证书 / 一键生成自签证书 (cert)"
  echo -e "  ${green}6.${plain} 切换 / 升级 Sing-box 内核版本 (version)"
  echo -e "  ${green}7.${plain} 一键无损迁移本机 3x-ui 全部节点与分流 (migrate)"
  echo -e "  ${green}8.${plain} 重启面板与 Sing-box 内核服务 (restart)"
  echo -e "  ${green}9.${plain} 停止面板与 Sing-box 内核服务 (stop)"
  echo -e "  ${green}10.${plain} 查看实时运行日志 (logs)"
  echo -e "  ${green}11.${plain} 在线更新面板 (update)"
  echo -e "  ${green}12.${plain} 卸载面板 (uninstall)"
  echo -e "  ${green}0.${plain} 退出菜单"
  echo -e "${cyan}└──────────────────────────────────────────────────────────┘${plain}"
  read -r -p "请输入选项数字 [0-12]: " num </dev/tty
  case "$num" in
    1) show_info ;;
    2) change_account ;;
    3) change_port ;;
    4) change_path ;;
    5) setup_cert ;;
    6) switch_singbox_version ;;
    7) migrate_3xui ;;
    8) systemctl restart nexusgate.service nexusgate-singbox.service && ok "服务已重启" ;;
    9) systemctl stop nexusgate.service nexusgate-singbox.service && ok "服务已停止" ;;
    10) journalctl -u nexusgate.service -u nexusgate-singbox.service -n 80 --no-pager ;;
    11) update_panel ;;
    12) uninstall_panel ;;
    0) exit 0 ;;
    *) die "无效选项" ;;
  esac
}

case "${1:-menu}" in
  info|status) show_info ;;
  account) change_account ;;
  port) change_port ;;
  path) change_path ;;
  cert) setup_cert ;;
  version) switch_singbox_version ;;
  migrate) migrate_3xui ;;
  restart) systemctl restart nexusgate.service nexusgate-singbox.service ;;
  stop) systemctl stop nexusgate.service nexusgate-singbox.service ;;
  logs) journalctl -u nexusgate.service -u nexusgate-singbox.service -n 100 --no-pager ;;
  update) update_panel ;;
  uninstall) uninstall_panel ;;
  *) menu ;;
esac
