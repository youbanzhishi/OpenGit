#!/bin/bash
# OpenGit Release 构建脚本
# 用法: ./release.sh [version]
# 例如: ./release.sh v0.5.0

set -e

REPO="youbanzhishi/OpenGit"
VERSION=${1:-"v0.5.0"}

echo "📦 开始构建 OpenGit $VERSION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 检查 git 状态
if [[ -n $(git status --porcelain) ]]; then
    echo "⚠️  警告: 有未提交的更改"
    git status --short
    read -p "是否继续? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# 检查是否在 master 分支
CURRENT_BRANCH=$(git branch --show-current)
if [[ "$CURRENT_BRANCH" != "master" && "$CURRENT_BRANCH" != "main" ]]; then
    echo "⚠️  警告: 当前不在 master/main 分支"
fi

# 确保代码已推送
echo "📤 确保代码已推送到远程..."
git push origin $CURRENT_BRANCH --quiet

# 创建 tag
echo "🏷️  创建 tag: $VERSION"
git tag -f $VERSION 2>/dev/null || git tag $VERSION
git push origin $VERSION --quiet

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ 已触发构建!"
echo ""
echo "📋 下一步操作:"
echo "1. 打开 GitHub Actions 查看构建状态:"
echo "   https://github.com/$REPO/actions"
echo ""
echo "2. 构建完成后，在 Release 页面下载:"
echo "   https://github.com/$REPO/releases/tag/$VERSION"
echo ""
echo "📦 将包含:"
echo "   - opengit-x86_64-unknown-linux-gnu.tar.gz"
echo "   - opengit-aarch64-unknown-linux-gnu.tar.gz"
echo "   - opengit-x86_64-apple-darwin.tar.gz"
echo "   - opengit-aarch64-apple-darwin.tar.gz"
echo "   - opengit-x86_64-pc-windows-gnu.zip"
echo "   - Docker 镜像 (ghcr.io/$REPO:$VERSION)"
echo "   - SHA256SUMS.txt 校验和文件"
