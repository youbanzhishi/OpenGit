# ADR-002: Agent API 远程管理接口

## Status
已接受 (2026-06-17)

## Context
用户将 OpenGit 部署在 EAS/ECS 服务器上，需要：
1. 通过域名/IP 远程调用 API 管理服务
2. Agent（AI 智能体）可以调用 API 修改配置
3. Agent 权限受限：可修改配置，但禁止删除仓库
4. 需要与人类管理员区分的权限级别

## Decision
实现 **Agent API** 模块，提供细粒度权限控制的远程管理接口。

### 权限级别设计

| 身份类型 | 权限 | 说明 |
|----------|------|------|
| `human` | 完全控制 | 管理员，可删除仓库 |
| `agent` | 受限控制 | 可修改配置，禁止删除仓库 |

### Agent 权限矩阵

| 操作 | Agent 权限 | 说明 |
|------|------------|------|
| 读取配置 | ✅ | 读取策略、identities、webhooks |
| 创建仓库 | ✅ | 创建新仓库 |
| 修改策略 | ✅ | 添加/修改规则 |
| 配置 Webhooks | ✅ | 添加/修改 webhook |
| 配置镜像 | ✅ | 添加/修改镜像 |
| **删除仓库** | ❌ | 明确禁止 |
| 删除策略 | ⚠️ | 仅允许人类操作 |
| 删除 Webhook | ⚠️ | 仅允许人类操作 |

### API 设计

#### Agent 认证
```bash
curl -X POST http://your-server:9418/api/agent/config \
  -H "Authorization: Bearer agent-token-xxx" \
  -H "X-Identity-Type: agent" \
  -H "Content-Type: application/json" \
  -d '{"action": "get_policy"}'
```

#### 身份注册（Agent 专用）
```bash
# 注册 Agent 身份
POST /api/agent/register
{
  "name": "deploy-agent",
  "display_name": "部署代理",
  "capabilities": ["read", "write_config", "create_repo"]
}

# 获取 Agent Token
POST /api/agent/token
{
  "name": "deploy-agent",
  "permissions": ["read", "write_config", "create_repo"]
}
```

#### Agent 可用端点
| 方法 | 端点 | Agent 权限 |
|------|------|------------|
| GET | /api/repos | ✅ 读取 |
| POST | /api/repos | ✅ 创建仓库 |
| POST | /api/repos/bulk/create | ✅ 批量创建 |
| GET | /api/policy/rules | ✅ 读取 |
| POST | /api/policy/rules | ✅ 添加规则 |
| GET | /api/webhooks | ✅ 读取 |
| POST | /api/webhooks | ✅ 添加 |
| GET | /api/mirrors | ✅ 读取 |
| POST | /api/mirrors | ✅ 添加 |
| POST | /api/import | ✅ 导入 |
| POST | /api/import/gitea | ✅ 迁移 |
| **DELETE** | **/api/repos/{name}** | ❌ **禁止** |
| DELETE | /api/policy/rules/{idx} | ❌ 禁止 |
| DELETE | /api/webhooks/{idx} | ❌ 禁止 |
| DELETE | /api/mirrors/{idx} | ❌ 禁止 |

### 实现方案

1. **身份类型扩展**
   - `IdentityKind` 增加 `Agent` 变体
   - Agent 身份自带权限标签

2. **Agent 专用中间件**
   - 拦截 Agent 请求，检查操作权限
   - 删除操作直接拒绝，返回 403

3. **独立 Agent API 前缀**
   - `/api/agent/*` - Agent 专用端点
   - 包含注册、token 生成、能力查询

### 配置示例

```toml
# config/agent_policy.toml
[agent_defaults]
can_create_repo = true
can_modify_policy = true
can_delete_repo = false  # 明确禁止

[[agent_permissions]]
name = "deploy-agent"
permissions = ["read", "write_config", "create_repo", "import"]

[[agent_permissions]]
name = "ci-agent"
permissions = ["read", "create_repo", "trigger_webhook"]
```

## Consequences
### 正面
- Agent 可远程管理配置，无需 SSH
- 权限明确分离，安全可控
- 审计日志可区分 human/agent 操作

### 负面
- 需要额外的身份注册流程
- Agent token 管理复杂

## References
- P6.1: Agent API 远程管理接口
