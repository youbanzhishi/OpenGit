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
- 🔌 **Unlimited Extension** — WASM plugin system planned for custom workflows
- 📊 **Full Audit Trail** — Every Git operation logged with identity, action, and result
- ⚡ **Lightweight** — Single binary, zero database dependency, pure filesystem
- 🔗 **Webhooks** — Post-receive notifications with HMAC-SHA256 signatures for CI/CD integration
- 🖥️ **CLI Tool** — `og` command-line tool for managing your OpenGit server
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
                     │ ┌──────────┐ │
                     │ │ Policy   │ │  ← Permission engine
                     │ │ Engine   │ │
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
| P4 | 🔄 | SSH Protocol + WASM Plugins |

## License

MIT
