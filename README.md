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
- 🔌 **Unlimited Extension** — Plugin system (WASM planned) for custom workflows
- 📊 **Full Audit Trail** — Every Git operation logged with identity, action, and result
- ⚡ **Lightweight** — Single binary, zero database dependency, pure filesystem

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

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/repos` | GET | List repositories |
| `/api/repos/:name` | GET | Get repository info |
| `/api/repos/:name/refs` | GET | List refs |
| `/api/policy/eval` | POST | Evaluate a policy |
| `/api/identities` | GET | List identities |
| `/api/audit` | GET | Get audit log |
| `/:repo/info/refs` | GET | Git Smart HTTP discovery |
| `/:repo/git-upload-pack` | POST | Git fetch/clone |
| `/:repo/git-receive-pack` | POST | Git push |

## Architecture

```
┌──────────────┐     ┌──────────────┐
│  Git Client   │────▶│  OpenGit     │
│  (agent/human)│     │  Server      │
└──────────────┘     │              │
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
└─────────────────────────────────────┘
```

## License

MIT
