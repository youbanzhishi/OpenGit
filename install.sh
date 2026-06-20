#!/bin/bash
#===============================================================================
# OpenGit 一键安装脚本
# 
# 用法:
#   curl -sSL https://raw.githubusercontent.com/youbanzhishi/OpenGit/main/install.sh | bash
#   curl -sSL https://raw.githubusercontent.com/youbanzhishi/OpenGit/main/install.sh | bash -s -- --channel=beta
#
# 选项:
#   --channel=stable|beta|nightly    选择发布通道 (默认: stable)
#   --install-dir=/path               安装目录 (默认: /usr/local/bin)
#   --data-dir=/path                  数据目录 (默认: /var/lib/opengit)
#   --user=username                   运行用户 (默认: 当前用户)
#   --with-tls                        启用 HTTPS
#   --skip-prompts                    跳过交互式提示
#
#===============================================================================

set -e

# 默认配置
CHANNEL="stable"
INSTALL_DIR="/usr/local/bin"
DATA_DIR="/var/lib/opengit"
CONFIG_DIR="/etc/opengit"
RUN_USER=""
WITH_TLS="false"
SKIP_PROMPTS="false"
SYSTEMD_SERVICE="true"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 帮助信息
show_help() {
    cat << EOF
OpenGit 一键安装脚本

用法:
    $(basename "$0") [选项]

选项:
    --channel=stable|beta|nightly    选择发布通道 (默认: stable)
    --install-dir=/path               安装目录 (默认: /usr/local/bin)
    --data-dir=/path                  数据目录 (默认: /var/lib/opengit)
    --config-dir=/path                配置目录 (默认: /etc/opengit)
    --user=username                   运行用户 (默认: 当前用户)
    --with-tls                        启用 HTTPS (自签名证书)
    --no-systemd                       不安装 systemd 服务
    --skip-prompts                    跳过交互式提示
    -h, --help                        显示此帮助信息

示例:
    $(basename "$0") --channel=stable --user=git
    $(basename "$0") --with-tls --skip-prompts
EOF
}

# 解析参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --channel=*)
            CHANNEL="${1#*=}"
            shift
            ;;
        --install-dir=*)
            INSTALL_DIR="${1#*=}"
            shift
            ;;
        --data-dir=*)
            DATA_DIR="${1#*=}"
            shift
            ;;
        --config-dir=*)
            CONFIG_DIR="${1#*=}"
            shift
            ;;
        --user=*)
            RUN_USER="${1#*=}"
            shift
            ;;
        --with-tls)
            WITH_TLS="true"
            shift
            ;;
        --no-systemd)
            SYSTEMD_SERVICE="false"
            shift
            ;;
        --skip-prompts)
            SKIP_PROMPTS="true"
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            log_error "未知参数: $1"
            show_help
            exit 1
            ;;
    esac
done

# 检查是否为 root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        IS_ROOT="true"
    else
        IS_ROOT="false"
    fi
}

# 检测系统
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_NAME=$ID
        OS_VERSION=$VERSION_ID
    elif [[ -f /etc/redhat-release ]]; then
        OS_NAME="rhel"
    elif [[ -f /etc/debian_version ]]; then
        OS_NAME="debian"
    else
        OS_NAME="unknown"
    fi
    
    log_info "检测到操作系统: $OS_NAME $OS_VERSION"
}

# 检测架构
detect_arch() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            ARCH_NAME="x86_64"
            ;;
        aarch64|arm64)
            ARCH_NAME="aarch64"
            ;;
        armv7l)
            ARCH_NAME="armv7"
            ;;
        *)
            log_error "不支持的架构: $ARCH"
            exit 1
            ;;
    esac
    log_info "检测到架构: $ARCH_NAME"
}

# 下载二进制
download_binary() {
    log_info "正在下载 OpenGit $CHANNEL 版本..."
    
    # 构建下载 URL
    case $CHANNEL in
        stable)
            TAG="v0.6.1"
            ;;
        beta)
            TAG=$(curl -sSL https://api.github.com/repos/youbanzhishi/OpenGit/releases | grep -o '"tag_name": "[^"]*"' | head -1 | cut -d'"' -f4)
            ;;
        nightly)
            TAG="nightly"
            ;;
    esac
    
    FILENAME="opengit-${OS_NAME}-${ARCH_NAME}"
    if [[ "$CHANNEL" == "nightly" ]]; then
        DOWNLOAD_URL="https://github.com/youbanzhishi/OpenGit/releases/nightly/${FILENAME}"
    else
        DOWNLOAD_URL="https://github.com/youbanzhishi/OpenGit/releases/download/${TAG}/${FILENAME}"
    fi
    
    log_info "下载地址: $DOWNLOAD_URL"
    
    # 创建临时目录
    TEMP_DIR=$(mktemp -d)
    trap "rm -rf $TEMP_DIR" EXIT
    
    # 下载
    if command -v curl &> /dev/null; then
        curl -sSL "$DOWNLOAD_URL" -o "$TEMP_DIR/opengit" || {
            log_error "下载失败"
            exit 1
        }
    elif command -v wget &> /dev/null; then
        wget -q "$DOWNLOAD_URL" -O "$TEMP_DIR/opengit" || {
            log_error "下载失败"
            exit 1
        }
    else
        log_error "需要 curl 或 wget"
        exit 1
    fi
    
    # 安装
    mkdir -p "$INSTALL_DIR"
    cp "$TEMP_DIR/opengit" "$INSTALL_DIR/opengit"
    chmod +x "$INSTALL_DIR/opengit"
    
    log_success "安装完成: $INSTALL_DIR/opengit"
}

# 创建用户
create_user() {
    if [[ -z "$RUN_USER" ]]; then
        return
    fi
    
    if id "$RUN_USER" &>/dev/null; then
        log_info "用户 $RUN_USER 已存在"
    else
        log_info "创建用户 $RUN_USER"
        useradd -r -s /bin/false -d "$DATA_DIR" "$RUN_USER" || {
            log_warn "无法创建系统用户，将使用当前用户"
            RUN_USER=""
        }
    fi
}

# 创建目录结构
create_dirs() {
    log_info "创建目录结构..."
    
    mkdir -p "$DATA_DIR"/{repos,data,logs}
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$DATA_DIR"/config/tls 2>/dev/null || true
    
    # 权限
    if [[ -n "$RUN_USER" ]]; then
        chown -R "$RUN_USER:$RUN_USER" "$DATA_DIR"
        chown -R "$RUN_USER:$RUN_USER" "$CONFIG_DIR"
    fi
    
    log_success "目录创建完成"
}

# 生成配置文件
generate_config() {
    log_info "生成配置文件..."
    
    # Server 配置
    cat > "$CONFIG_DIR/server.toml" << EOF
# OpenGit 服务器配置

# 服务绑定地址
bind = "0.0.0.0:9418"

# 仓库存储目录
repos_dir = "$DATA_DIR/repos"

# 身份文件
identity_file = "$CONFIG_DIR/identities.yaml"

# 策略文件
policy_file = "$CONFIG_DIR/policies.yaml"

# 审计日志
audit_file = "$DATA_DIR/data/audit.json"

# Webhook 配置
webhook_file = "$CONFIG_DIR/webhooks.yaml"

# 插件配置
plugin_file = "$CONFIG_DIR/plugins.toml"

# 镜像配置
mirror_file = "$CONFIG_DIR/mirrors.yaml"

# 速率限制配置
rate_limit_file = "$CONFIG_DIR/rate-limit.toml"

# TLS 配置 (可选)
# tls_cert = "$CONFIG_DIR/tls/cert.pem"
# tls_key = "$CONFIG_DIR/tls/key.pem"
EOF

    # 初始策略
    cat > "$CONFIG_DIR/policies.yaml" << EOF
# OpenGit 策略配置

rules:
  # 允许所有操作
  - repo: "*"
    identity: "admin"
    action: "admin"
    permission: "allow"
    reason: "Admin has full access"

  # Agent 权限限制
  - repo: "*"
    identity: "agent-*"
    action: "delete"
    permission: "deny"
    reason: "Agents cannot delete repositories"

  # 匿名用户只读
  - repo: "*"
    identity: "anonymous"
    action: "read"
    permission: "allow"
    reason: "Anonymous read allowed"

  # 匿名用户禁止写入
  - repo: "*"
    identity: "anonymous"
    action: "write"
    permission: "deny"
    reason: "Anonymous write denied"
EOF

    # 初始身份
    cat > "$CONFIG_DIR/identities.yaml" << EOF
# OpenGit 身份配置

identities:
  - name: "admin"
    kind: "human"
    display_name: "Administrator"
    tokens:
      - label: "default"
        # 运行后使用 opengit identity regenerate 生成实际 token
        token: "CHANGEME"
        created: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
EOF

    # 速率限制
    cat > "$CONFIG_DIR/rate-limit.toml" << EOF
# OpenGit 速率限制配置

enabled = true
message = "Rate limit exceeded. Please try again later."

whitelist = [
    "127.0.0.0/8",
    "::1",
]

[ip]
enabled = true
read_limit = 100
write_limit = 10
window_secs = 60
burst = 20

[identity]
enabled = true
read_limit = 500
write_limit = 50
window_secs = 60
burst = 100
EOF

    if [[ -n "$RUN_USER" ]]; then
        chown -R "$RUN_USER:$RUN_USER" "$CONFIG_DIR"
    fi
    
    log_success "配置文件生成完成"
}

# 生成 TLS 证书
generate_tls() {
    if [[ "$WITH_TLS" != "true" ]]; then
        return
    fi
    
    log_info "生成自签名 TLS 证书..."
    
    mkdir -p "$CONFIG_DIR/tls"
    
    # 使用 OpenSSL 生成自签名证书
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$CONFIG_DIR/tls/key.pem" \
        -out "$CONFIG_DIR/tls/cert.pem" \
        -subj "/CN=localhost" 2>/dev/null || {
        log_warn "TLS 证书生成失败，跳过"
        return
    }
    
    if [[ -n "$RUN_USER" ]]; then
        chown "$RUN_USER:$RUN_USER" "$CONFIG_DIR/tls/"*
    fi
    
    log_success "TLS 证书生成完成"
}

# 创建 systemd 服务
create_systemd_service() {
    if [[ "$SYSTEMD_SERVICE" != "true" ]]; then
        return
    fi
    
    if [[ ! -d /etc/systemd/system ]]; then
        log_warn "systemd 不可用，跳过服务安装"
        return
    fi
    
    log_info "创建 systemd 服务..."
    
    cat > /etc/systemd/system/opengit.service << EOF
[Unit]
Description=OpenGit - AI-Ready Git Gateway
Documentation=https://github.com/youbanzhishi/OpenGit
After=network.target

[Service]
Type=simple
User=${RUN_USER:-root}
Group=${RUN_USER:-root}
WorkingDirectory=$DATA_DIR
ExecStart=$INSTALL_DIR/opengit serve --config $CONFIG_DIR/server.toml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# 安全加固
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR $CONFIG_DIR

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable opengit
    
    log_success "systemd 服务创建完成"
}

# 配置 Shell 自动补全
setup_completion() {
    log_info "配置 Shell 自动补全..."
    
    SHELL_TYPE=$(basename "$SHELL")
    
    case $SHELL_TYPE in
        bash)
            COMPLETION_DIR="/etc/bash_completion.d"
            mkdir -p "$COMPLETION_DIR"
            "$INSTALL_DIR/opengit" completion bash > "$COMPLETION_DIR/opengit" 2>/dev/null || true
            ;;
        zsh)
            COMPLETION_DIR="${ZDOTDIR:-$HOME/.zsh}"
            mkdir -p "$COMPLETION_DIR/completions"
            "$INSTALL_DIR/opengit" completion zsh > "$COMPLETION_DIR/completions/_opengit" 2>/dev/null || true
            ;;
        fish)
            mkdir -p "$HOME/.config/fish/completions"
            "$INSTALL_DIR/opengit" completion fish > "$HOME/.config/fish/completions/opengit.fish" 2>/dev/null || true
            ;;
    esac
    
    log_success "Shell 自动补全配置完成"
}

# 启动服务
start_service() {
    if [[ "$SYSTEMD_SERVICE" == "true" ]]; then
        log_info "启动 OpenGit 服务..."
        systemctl start opengit
        sleep 2
        
        if systemctl is-active --quiet opengit; then
            log_success "OpenGit 服务已启动"
        else
            log_error "OpenGit 服务启动失败"
            systemctl status opengit
        fi
    else
        log_info "手动启动 OpenGit:"
        echo "    $INSTALL_DIR/opengit serve --config $CONFIG_DIR/server.toml"
    fi
}

# 显示完成信息
show_completion() {
    echo ""
    echo "============================================"
    log_success "OpenGit 安装完成!"
    echo "============================================"
    echo ""
    echo "配置目录: $CONFIG_DIR"
    echo "数据目录: $DATA_DIR"
    echo "安装路径: $INSTALL_DIR/opengit"
    echo ""
    
    if [[ "$SYSTEMD_SERVICE" == "true" ]]; then
        echo "服务管理命令:"
        echo "    systemctl start opengit   # 启动"
        echo "    systemctl stop opengit    # 停止"
        echo "    systemctl restart opengit  # 重启"
        echo "    systemctl status opengit  # 状态"
        echo ""
    fi
    
    echo "Web UI 访问: http://localhost:9418"
    echo ""
    
    if [[ "$WITH_TLS" == "true" ]]; then
        echo "HTTPS 访问: https://localhost:9443"
        echo "注意: 自签名证书需要浏览器信任"
        echo ""
    fi
    
    echo "后续步骤:"
    echo "    1. 编辑 $CONFIG_DIR/identities.yaml 设置管理员 token"
    echo "    2. 重启服务: systemctl restart opengit"
    echo "    3. 访问 Web UI 创建第一个仓库"
    echo ""
}

# 主函数
main() {
    echo ""
    echo "============================================"
    echo "  OpenGit 一键安装脚本"
    echo "============================================"
    echo ""
    
    check_root
    detect_os
    detect_arch
    
    log_info "安装配置:"
    log_info "    通道: $CHANNEL"
    log_info "    安装目录: $INSTALL_DIR"
    log_info "    数据目录: $DATA_DIR"
    log_info "    配置目录: $CONFIG_DIR"
    
    if [[ -n "$RUN_USER" ]]; then
        log_info "    运行用户: $RUN_USER"
    fi
    
    if [[ "$WITH_TLS" == "true" ]]; then
        log_info "    TLS: 启用"
    fi
    
    echo ""
    
    if [[ "$SKIP_PROMPTS" != "true" ]]; then
        read -p "继续安装? [Y/n] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]] && [[ ! -z $REPLY ]]; then
            exit 0
        fi
    fi
    
    download_binary
    create_user
    create_dirs
    generate_config
    generate_tls
    create_systemd_service
    setup_completion
    start_service
    show_completion
}

main "$@"
