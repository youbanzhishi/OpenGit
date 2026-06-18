#!/bin/bash
# OpenGit 一键启动脚本 (macOS/Linux)

set -e

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# 确保必要目录存在
mkdir -p repos data

# 默认配置
REPOS_DIR="${REPOS_DIR:-$SCRIPT_DIR/repos}"
BIND="${BIND:-0.0.0.0:9418}"

echo "🐉 OpenGit v1.0.0"
echo "=================="
echo "Repos:  $REPOS_DIR"
echo "Bind:   http://$BIND"
echo ""
echo "📂 Creating directories if needed..."
mkdir -p "$REPOS_DIR" data logs

# 检查二进制文件
if [[ ! -f "./opengit" ]]; then
    echo "❌ Error: opengit binary not found!"
    echo "   Please download from: https://github.com/youbanzhishi/OpenGit/releases/tag/v1.0.0"
    exit 1
fi

# macOS 安全提示
if [[ "$(uname)" == "Darwin" ]]; then
    # 第一次运行需要允许
    xattr -d com.apple.quarantine ./opengit 2>/dev/null || true
fi

echo "🚀 Starting OpenGit..."
echo ""

# 启动服务
./opengit serve \
    --repos-dir "$REPOS_DIR" \
    --bind "$BIND" \
    --config config/server.toml
