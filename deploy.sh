#!/bin/bash
# OpenGit 服务器快速部署脚本
# 用法: curl -fsSL https://raw.githubusercontent.com/youbanzhishi/OpenGit/master/deploy.sh | bash
# 或下载后执行: ./deploy.sh

set -e

# 配置
VERSION=${VERSION:-"latest"}
INSTALL_DIR=${INSTALL_DIR:-"/opt/opengit"}
SERVICE_USER=${SERVICE_USER:-"opengit"}
SERVICE_NAME="opengit-server"
PORT=${PORT:-"9418"}

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 检测系统
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
    else
        OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    fi
    
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="x86_64-unknown-linux-gnu" ;;
        aarch64|arm64) ARCH="aarch64-unknown-linux-gnu" ;;
        *) log_error "不支持的架构: $ARCH"; exit 1 ;;
    esac
}

# 下载二进制
download_binary() {
    log_info "检测系统: $OS, 架构: $ARCH"
    
    if [[ "$VERSION" == "latest" ]]; then
        DOWNLOAD_URL="https://github.com/youbanzhishi/OpenGit/releases/latest/download/opengit-${ARCH}.tar.gz"
    else
        DOWNLOAD_URL="https://github.com/youbanzhishi/OpenGit/releases/download/${VERSION}/opengit-${ARCH}.tar.gz"
    fi
    
    log_info "下载地址: $DOWNLOAD_URL"
    
    TMP_FILE=$(mktemp)
    curl -fsSL "$DOWNLOAD_URL" -o "$TMP_FILE" || {
        log_error "下载失败"
        exit 1
    }
    
    log_info "解压到 $INSTALL_DIR..."
    mkdir -p "$INSTALL_DIR"
    tar -xzf "$TMP_FILE" -C "$INSTALL_DIR"
    rm "$TMP_FILE"
    
    chmod +x "$INSTALL_DIR"/opengit-*
}

# 创建 systemd 服务
create_service() {
    log_info "创建 systemd 服务..."
    
    cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=OpenGit Server
Documentation=https://github.com/youbanzhishi/OpenGit
After=network.target

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/opengit-server --config ${INSTALL_DIR}/config/server.toml
Restart=always
RestartSec=5

# 环境变量
Environment=PORT=${PORT}
Environment=RUST_LOG=info

# 安全加固
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${INSTALL_DIR}

[Install]
WantedBy=multi-user.target
EOF
    
    # 创建用户（如果不存在）
    id "$SERVICE_USER" &>/dev/null || useradd -r -s /bin/false "$SERVICE_USER"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
    
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
}

# 启动服务
start_service() {
    log_info "启动服务..."
    systemctl start "$SERVICE_NAME"
    
    sleep 2
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log_info "✅ 服务已启动!"
        log_info "访问 http://localhost:${PORT}"
    else
        log_error "服务启动失败"
        journalctl -u "$SERVICE_NAME" --no-pager -n 20
        exit 1
    fi
}

# 主流程
main() {
    echo "╔══════════════════════════════════════════╗"
    echo "║     OpenGit 服务器快速部署脚本             ║"
    echo "╚══════════════════════════════════════════╝"
    echo ""
    
    # 检查 root 权限
    if [[ $EUID -ne 0 ]]; then
        log_warn "建议使用 root 权限运行以创建系统服务"
        read -p "是否继续? (y/N) " -n 1 -r
        echo
        [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
    fi
    
    detect_os
    download_binary
    create_service
    start_service
    
    echo ""
    log_info "部署完成!"
    echo ""
    echo "📝 常用命令:"
    echo "   systemctl status opengit-server   # 查看状态"
    echo "   systemctl restart opengit-server  # 重启"
    echo "   journalctl -u opengit-server -f   # 查看日志"
    echo ""
    echo "📁 配置目录: $INSTALL_DIR/config"
}

main "$@"
