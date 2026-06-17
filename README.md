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

## SSH Gateway (`opengit-sshd`)

OpenGit provides an SSH gateway that integrates with the system's `sshd` for secure Git operations over SSH, with identity-based access control.

```bash
# Setup SSH configuration (generates sshd_config + authorized_keys)
opengit-sshd setup --repos-dir /path/to/repos --identity-dir /path/to/identities

# Print authorized_keys content for manual review
opengit-sshd authorized-keys --identity-dir /path/to/identities

# Print sshd_config content
opengit-sshd config --repos-dir /path/to/repos
```

### How It Works

1. Each OpenGit identity maps to a system SSH key in `authorized_keys`
2. SSH keys use forced commands that set `OPENGIT_IDENTITY` environment variable
3. The Smart HTTP pipeline reads this identity for permission evaluation
4. No custom SSH server needed — leverages battle-tested system `sshd`

## Hook Plugin System

OpenGit includes a plugin system for extending hook behavior beyond the built-in policy engine.

### Built-in Plugins

| Plugin | Description |
|--------|-------------|
| **BranchProtection** | Enforces branch protection rules (e.g., no push to `main`/`master` by agents) |
| **PushLimit** | Limits push frequency and file size per identity |

### Plugin Configuration (`config/plugins.toml`)

```toml
[[plugin]]
name = "branch_protection"
enabled = true

[plugin.config]
protected_branches = ["main", "master"]
allow_force_push = false

[[plugin]]
name = "push_limit"
enabled = true

[plugin.config]
max_pushes_per_hour = 100
max_file_size_mb = 50
```

### Custom Plugins

Implement the `HookPlugin` trait to create custom plugins:

```rust
use opengit_core::plugin::{HookPlugin, HookContext, HookResult};

struct MyPlugin;

impl HookPlugin for MyPlugin {
    fn name(&self) -> &str { "my_plugin" }
    
    fn on_pre_receive(&self, ctx: &HookContext) -> HookResult {
        // Your logic here
        Ok(())
    }
    
    fn on_post_receive(&self, ctx: &HookContext) -> HookResult {
        Ok(())
    }
}
```

## API

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | No | Health check |
| `/api/repos` | GET | Yes | List repositories |
| `/api/repos` | POST | Yes | Create repository |
| `/api/repos/{name}` | GET | Yes | Get repository info |
| `/api/repos/{name}` | DELETE | Yes | Delete repository (moves to trash) |
| `/api/repos/{name}/refs` | GET | Yes | List refs |
| `/api/repos/{name}/reflog/{ref}` | GET | Yes | Get reflog |
| `/api/repos/{name}/size` | GET | Yes | Get repository disk size |
| `/api/repos/bulk/create` | POST | Yes | Create multiple repositories |
| `/api/policy/eval` | POST | Yes | Evaluate a policy |
| `/api/policy/rules` | GET | Yes | List policy rules |
| `/api/policy/rules` | POST | Yes | Add a policy rule |
| `/api/identities` | GET | Yes | List identities |
| `/api/identities` | POST | Yes | Register identity |
| `/api/identities/{name}` | GET | Yes | Get identity info |
| `/api/identities/{name}` | DELETE | Yes | Delete identity |
| `/api/identities/{name}/tokens` | POST | Yes | Generate token |
| `/api/audit` | GET | Yes | Get audit log |
| `/api/audit/denied` | GET | Yes | Get denied operations |
| `/api/webhooks` | GET | Yes | List webhooks |
| `/api/webhooks` | POST | Yes | Add webhook |
| `/api/webhooks/{idx}` | DELETE | Yes | Delete webhook |
| `/api/stats` | GET | Yes | Server statistics |
| `/{repo}/info/refs` | GET | Optional | Git Smart HTTP discovery |
| `/{repo}/git-upload-pack` | POST | Optional | Git fetch/clone |
| `/{repo}/git-receive-pack` | POST | Optional | Git push |

### Authentication

All `/api/*` endpoints require a Bearer token:
```
Authorization: Bearer og_human-admin_default_xxxxxxxx
```

Smart HTTP endpoints support optional auth via:
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
| P6 | ✅ | Web Dashboard — 可视化管理所有仓库、策略、Webhooks、镜像 |

## Web Dashboard

OpenGit 提供内置的 Web 管理面板，无需额外安装：

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

### 界面预览

Dashboard 采用深色主题，支持以下特性：

- **响应式布局** — 适配桌面和移动设备
- **实时状态** — 服务器连接状态实时显示
- **操作确认** — 危险操作需要二次确认
- **Token 认证** — 支持 Bearer Token 认证

## License

MIT
