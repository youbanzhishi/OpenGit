# 🐉 OpenGit — AI-Ready Git Gateway

> **v1.0.0** — Agent-first, Human-friendly, Production-ready Git Gateway

## Why OpenGit?

On 2026-06-03, an AI agent accidentally deleted branches across 18 GitHub repositories. The existing Git hosting solutions (Gitea, GitLab, GitHub) lack per-action permission granularity — they can restrict at repo level, but not at the operation level (force-push? delete-branch? reset-staging?).

OpenGit was born from that incident. Every rule in its default policy is a lesson learned the hard way.

## Core Features

### Security
- 🔒 **Per-Action Permission Model** — push-only, no-force-push, no-delete-branch, no-delete-repo
- 🛡️ **AI Guard** — Semantic code analysis to detect dangerous operations before push
- 📊 **AI Audit Log** — Automatic anomaly detection in operation patterns
- 🔑 **Token Policy** — Dynamic token lifecycle management with automatic rotation
- 📝 **Code Fingerprint** — Traceable code provenance with content hashing
- 🚫 **Rate Limiting** — Token bucket + sliding window, IP/identity dual dimension
- 🔐 **Security Hardening** — Input validation, path traversal prevention, injection detection
- 🌐 **TLS/HTTPS** — Built-in HTTPS support with self-signed certificate generation
- 📋 **Security Headers** — HSTS, CSP, X-Frame-Options, and more

### Performance
- 💾 **Object Cache** — In-memory Git object cache with LRU eviction
- 🔄 **Connection Pool** — HTTP/HTTPS connection pooling
- 🏷️ **Ref Cache** — Branch/tag resolution caching
- ⚡ **Lazy Loading** — On-demand repository scanning

### Developer Experience
- 🤖 **Agent-First Design** — Default safe policies for AI agents
- 👤 **Human-Friendly** — Humans get full control with audit logging
- 📦 **Zero Migration** — Reads existing Git bare repos directly
- 🔌 **Plugin System** — Hook plugins with trait-based extensibility
- 📊 **Full Audit Trail** — Every Git operation logged
- ⚡ **Lightweight** — Single binary, zero database dependency
- 🔗 **Webhooks** — Post-receive notifications with HMAC-SHA256
- 🖥️ **CLI Tool** — `og` command-line tool
- 🔑 **SSH Gateway** — `opengit-sshd` manages SSH access
- 📡 **Streaming** — Smart HTTP with streaming pack transfer
- 🖥️ **Web Dashboard** — Built-in management UI
- 🤖 **Agent API** — Remote management interface

## Permission Model

| Action | Agent | Human |
|--------|-------|-------|
| push | ✅ Allow | ✅ Allow |
| force-push | ❌ Deny | ⚠️ Audit-Log |
| delete-branch | ❌ Deny | ✅ Allow |
| delete-repo | ❌ Deny | 🔐 Confirm |
| merge | ✅ Allow | ✅ Allow |
| tag | ✅ Allow | ✅ Allow |
| add-all | ❌ Deny | ✅ Allow |
| reset-staging | ❌ Deny | ✅ Allow |
| stash | ❌ Deny | ✅ Allow |
| admin | ❌ Deny | ✅ Allow |
| read | ✅ Allow | ✅ Allow |

## Quick Start

```bash
# Build
cargo build --release

# Run with defaults
./target/release/opengit

# Run with custom config
./target/release/opengit --config /path/to/server.toml --repos-dir /path/to/repos

# Point any git client
git clone http://localhost:9418/my-repo
```

## CLI Tool (`og`)

```bash
# Health check
og health

# List repos
og repos

# Create a repo
og repos --create my-project

# List identities
og identities list

# Register an agent
og identities register my-bot --kind agent --display-name "My Bot"

# Generate a token
og identities token agent-my-bot --label ci-key

# List policy rules
og policy rules

# Add a policy rule
og policy add-rule --identity agent-deploy --action push --permission allow

# Evaluate a policy (dry run)
og policy eval --repo my-project --identity agent-deploy --action push

# View audit log
og audit

# View denied operations only
og audit --denied

# Manage webhooks
og webhooks list
og webhooks add https://ci.example.com/hook --secret my-secret

# Server stats
og stats
```

## Web Dashboard

OpenGit 提供内置的 Web 管理面板：

```bash
# 启动服务器（Dashboard 默认启用）
./target/release/opengit

# 访问 Dashboard
open http://localhost:9418/
```

### Dashboard 功能

| 模块 | 功能 |
|------|------|
| 📦 仓库管理 | 创建、删除、搜索仓库，查看仓库详情 |
| 🛡️ 访问策略 | 可视化配置权限规则，添加/删除策略 |
| 🔗 Webhooks | 管理 webhook 通知，配置触发事件 |
| 🪞 镜像同步 | 配置仓库镜像，监控同步状态 |
| ⚡ 自动化规则 | 配置触发条件和执行动作 |
| 📋 审计日志 | 查看所有操作的审计记录 |
| ⚙️ 配置文件 | 可视化编辑 server.toml、policies.yaml 等 |
| 📥 导入迁移 | 从 Git URL 或 Gitea 服务器批量导入仓库 |

## Agent API

支持 AI 智能体远程管理配置：

```bash
# 1. 注册 Agent 身份
curl -X POST http://localhost:9418/api/agent/register \
  -H "Content-Type: application/json" \
  -d '{"name": "deploy-agent", "display_name": "部署代理"}'

# 2. 获取 Agent Token
curl -X POST http://localhost:9418/api/agent/token \
  -H "Content-Type: application/json" \
  -d '{"name": "deploy-agent"}'

# 3. Agent 可用操作
curl http://localhost:9418/api/repos \
  -H "Authorization: Bearer og_agent-deploy-xxx"

# 4. Agent 创建仓库（允许）
curl -X POST http://localhost:9418/api/repos \
  -H "Authorization: Bearer og_agent-deploy-xxx" \
  -H "Content-Type: application/json" \
  -d '{"name": "new-project"}'

# 5. Agent 删除仓库（禁止 ❌）
curl -X DELETE http://localhost:9418/api/repos/new-project \
  -H "Authorization: Bearer og_agent-deploy-xxx"
# 返回 403 Forbidden
```

### Agent 权限矩阵

| 操作 | Agent | Human |
|------|-------|-------|
| 读取配置 | ✅ | ✅ |
| 创建仓库 | ✅ | ✅ |
| 修改策略 | ✅ | ✅ |
| **删除仓库** | ❌ | ✅ |
| 删除策略 | ❌ | ✅ |
| 配置 Webhooks | ✅ | ✅ |
| 删除 Webhook | ❌ | ✅ |
| 配置镜像 | ✅ | ✅ |
| 导入仓库 | ✅ | ✅ |

## REST API

### Authentication

All authenticated endpoints require a token. Pass it via:

- `Authorization: Bearer <token>`
- `Authorization: Basic <base64(user:token)>`
- Query parameter: `?token=<token>`

## Webhooks

Webhooks are triggered after a successful push. Each webhook can be configured with:

- **URL** — Target endpoint
- **Secret** — HMAC-SHA256 signing key (optional)
- **Events** — `push`, `tag`, `delete-branch` (default: all)

### Webhook Payload

```json
{
  "repo": "my-project",
  "identity": "agent-deploy",
  "event": "push",
  "ref_name": "refs/heads/master",
  "old_sha": "abc123...",
  "new_sha": "def456...",
  "timestamp": "2026-06-11T12:00:00+00:00"
}
```

### Verification

```python
import hmac, hashlib
signature = "sha256=" + hmac.new(secret, payload, hashlib.sha256).hexdigest()
# Compare with X-OpenGit-Signature header
```

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Git Client   │────▶│  OpenGit     │     │  og CLI      │
│  (agent/human)│     │  Server      │◀────│  Management  │
└──────────────┘     │              │     └──────────────┘
                     │ ┌──────────┐ │     ┌──────────────┐
                     │ │ Policy   │ │     │ opengit-sshd │
                     │ │ Engine   │ │     │ SSH Gateway  │
                     │ └────┬─────┘ │     └──────┬───────┘
                     │      │       │            │
                     │ ┌────▼─────┐ │            │ identity-
                     │ │ Plugin   │ │◀───────────┘ mapped
                     │ │ System   │ │   authorized_keys
                     │ └────┬─────┘ │
                     │      │       │
                     │ ┌────▼─────┐ │
                     │ │ Hook     │ │  ← Git hooks (enforcement)
                     │ │ Pipeline │ │
                     │ └────┬─────┘ │
                     │      │       │
                     │ ┌────▼─────┐ │
                     │ │ Storage  │ │  ← Bare repos (zero migration)
                     │ └──────────┘ │
                     │              │
                     │ ┌──────────┐ │
                     │ │ Webhooks │ │  ← Post-receive notifications
                     │ └──────────┘ │
                     └──────────────┘
```

## Project Status

| Phase | Status | Features |
|-------|--------|----------|
| P0 | ✅ | Core: Policy Engine + Identity + Hook Pipeline + Repository |
| P1 | ✅ | Smart HTTP + Auth Middleware + Force Push Detection + REST API |
| P2 | ✅ | Streaming + Persistent State + Webhooks + Stats |
| P3 | ✅ | CLI Tool + Repo Size + Bulk Operations + Precise Webhook Refs |
| P4 | ✅ | SSH Gateway + Hook Plugin System (BranchProtection + PushLimit) |
| P5 | ✅ | Docker Deployment + Repository Mirroring |
| P6 | ✅ | Web Dashboard + Agent API |

## Installation

### 下载预编译二进制

```bash
# Linux x86_64
curl -fsSL https://github.com/youbanzhishi/OpenGit/releases/latest/download/opengit-x86_64-unknown-linux-gnu.tar.gz | tar -xz

# Linux ARM64
curl -fsSL https://github.com/youbanzhishi/OpenGit/releases/latest/download/opengit-aarch64-unknown-linux-gnu.tar.gz | tar -xz

# macOS (Apple Silicon)
curl -fsSL https://github.com/youbanzhishi/OpenGit/releases/latest/download/opengit-aarch64-apple-darwin.tar.gz | tar -xz

# macOS (Intel)
curl -fsSL https://github.com/youbanzhishi/OpenGit/releases/latest/download/opengit-x86_64-apple-darwin.tar.gz | tar -xz

# Windows
# 从 https://github.com/youbanzhishi/OpenGit/releases 下载 zip 文件
```

### 一键部署到服务器

```bash
# 在服务器上执行
curl -fsSL https://raw.githubusercontent.com/youbanzhishi/OpenGit/master/deploy.sh | bash

# 指定版本
VERSION=v0.5.0 curl -fsSL https://raw.githubusercontent.com/youbanzhishi/OpenGit/master/deploy.sh | bash

# 自定义安装目录
INSTALL_DIR=/data/opengit curl -fsSL https://raw.githubusercontent.com/youbanzhishi/OpenGit/master/deploy.sh | bash
```

部署脚本会自动：
1. 检测系统架构
2. 下载对应平台的二进制
3. 创建 systemd 服务
4. 启动服务

### Docker 部署

```bash
# 拉取镜像
docker pull ghcr.io/youbanzhishi/opengit:latest

# 运行
docker run -d \
  --name opengit \
  -p 9418:9418 \
  -v /path/to/repos:/app/repos \
  -v /path/to/config:/app/config \
  ghcr.io/youbanzhishi/opengit:latest

# Docker Compose
curl -fsSL https://raw.githubusercontent.com/youbanzhishi/OpenGit/master/docker-compose.yml
docker-compose up -d
```

### 从源码编译

```bash
# 克隆仓库
git clone https://github.com/youbanzhishi/OpenGit.git
cd OpenGit

# 编译
cargo build --release

# 二进制位置
ls -la target/release/opengit
ls -la target/release/opengit-server
```

## License

MIT
