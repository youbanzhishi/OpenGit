# 🐉 OpenGit — Lightweight Private Git Service

> **Agent-first, Human-friendly** — Fine-grained permission model designed for AI agents and human collaboration.

## Why OpenGit?

On 2026-06-03, an AI agent accidentally deleted branches across 18 GitHub repositories. The existing Git hosting solutions (Gitea, GitLab, GitHub) lack per-action permission granularity — they can restrict at repo level, but not at the operation level (force-push? delete-branch? reset-staging?).

OpenGit was born from that incident. Every rule in its default policy is a lesson learned the hard way.

## Core Features

- 🔒 **Per-Action Permission Model** — push-only, no-force-push, no-delete-branch, no-delete-repo, no-add-all, no-stash, no-reset-staging
- 🤖 **Agent-First Design** — Default safe policies for AI agents; agents can only push by default
- 👤 **Human-Friendly** — Humans get full control with audit logging on dangerous operations
- 📦 **Zero Migration** — Reads existing Git bare repos directly, no import needed
- 🔌 **Plugin System** — Hook plugins with trait-based extensibility (branch protection, push limits, custom rules)
- 📊 **Full Audit Trail** — Every Git operation logged with identity, action, and result
- ⚡ **Lightweight** — Single binary, zero database dependency, pure filesystem
- 🔗 **Webhooks** — Post-receive notifications with HMAC-SHA256 signatures for CI/CD integration
- 🖥️ **CLI Tool** — `og` command-line tool for managing your OpenGit server
- 🔑 **SSH Gateway** — `opengit-sshd` manages system sshd with identity-mapped authorized_keys
- 📡 **Streaming** — Smart HTTP with streaming pack transfer, prevents OOM on large repos
- 💾 **Persistent State** — Identity, policy, and webhook configs survive server restarts
- 📈 **Server Stats** — Atomic counters tracking pushes, clones, denials, webhooks, uptime
- 🖥️ **Web Dashboard** — Built-in management UI for visual control
- 🤖 **Agent API** — Remote management interface for AI agents with restricted permissions

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

## License

MIT
