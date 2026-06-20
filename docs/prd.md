# OpenGit 产品需求文档 (PRD)

> 最后更新：2026-06-17

## 项目概述

**OpenGit** — 轻量级私有 Git 服务，Agent-First 设计。

### 核心问题
2026-06-03，一次 AI agent 误操作导致 18 个 GitHub 仓库分支被删除。现有 Git 托管方案（Gitea、GitLab、GitHub）缺乏细粒度的操作级权限控制。

### 解决方案
OpenGit 提供每个操作的独立权限控制，配合完整审计日志和 Agent 专属安全策略。

---

## 功能需求

### P0-P5 已完成

| Phase | 状态 | 功能 |
|-------|------|------|
| P0 | ✅ | 核心：策略引擎 + 身份 + Hook + 仓库 |
| P1 | ✅ | Smart HTTP + 认证中间件 + 强制推送检测 + REST API |
| P2 | ✅ | 流式传输 + 持久化状态 + Webhooks + 统计 |
| P3 | ✅ | CLI 工具 + 仓库大小 + 批量操作 + 精确 Webhook |
| P4 | ✅ | SSH 网关 + Hook 插件系统 |
| P5 | ✅ | Docker 部署 + 仓库镜像 |
| P6 | ✅ | Web Dashboard + Agent API |

---

## P6 功能详情

### 6.1 Web Dashboard

**用户故事**：作为管理员，我希望通过浏览器管理 OpenGit，无需 SSH 或命令行。

**功能列表**：
- [x] 仓库管理（创建、删除、搜索）
- [x] 访问策略可视化配置
- [x] Webhooks CRUD
- [x] 镜像同步配置
- [x] 自动化规则配置器
- [x] 审计日志查看
- [x] 配置文件在线编辑
- [x] Git URL / Gitea 迁移导入

**验收标准**：
- 启动后访问 `http://server:9418/` 可看到管理界面
- 所有功能无需刷新页面
- 深色主题，移动端适配

### 6.2 Agent API

**用户故事**：作为 AI Agent，我希望通过 API 远程管理 OpenGit 配置，但不能删除仓库。

**功能列表**：
- [ ] Agent 身份注册端点
- [ ] Agent Token 生成（带权限标签）
- [ ] Agent 专用 API 前缀 `/api/agent/*`
- [ ] Agent 权限中间件（禁止删除操作）
- [ ] 权限矩阵配置

**Agent 权限矩阵**：

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

**验收标准**：
- Agent Token 请求删除仓库返回 403 Forbidden
- Agent Token 可正常创建仓库和修改配置
- 操作日志区分 human/agent 身份

**API 端点示例**：
```bash
# Agent 注册
POST /api/agent/register
{
  "name": "deploy-agent",
  "display_name": "部署代理"
}

# Agent 登录
POST /api/agent/token
{
  "name": "deploy-agent"
}

# Agent 读取配置（允许）
GET /api/policy/rules
Authorization: Bearer agent-token-xxx

# Agent 删除仓库（拒绝）
DELETE /api/repos/my-repo
Authorization: Bearer agent-token-xxx
# 返回 403 Forbidden
```

---

## 非功能需求

### 安全性
- Token 使用 HMAC-SHA256 签名验证
- Agent 权限默认禁止危险操作
- 所有操作记录审计日志

### 可用性
- Web Dashboard 零配置启用
- Agent API 支持 Bearer Token 和 Basic Auth
- Docker 一键部署

### 性能
- 单二进制部署，无数据库依赖
- 流式传输防止大仓库 OOM
- 原子计数器统计，无锁竞争

---

## 部署场景

### 场景 1: 本地开发
```bash
docker run -p 9418:9418 ghcr.io/youbanzhishi/opengit:latest
```

### 场景 2: EAS/ECS 生产部署
```bash
# 使用自定义配置
docker run -d \
  --name opengit \
  -p 9418:9418 \
  -v /data/opengit/config:/app/config \
  -v /data/opengit/repos:/app/repos \
  ghcr.io/youbanzhishi/opengit:latest
```

### 场景 3: Agent 远程管理
```bash
# Agent 调用
curl -X POST http://your-server:9418/api/repos \
  -H "Authorization: Bearer agent-token-xxx" \
  -H "Content-Type: application/json" \
  -d '{"name": "new-project"}'
```

---

## 决策记录

| ADR | 标题 | 状态 | 日期 |
|-----|------|------|------|
| ADR-001 | Web Dashboard 实现 | 已接受 | 2026-06-17 |
| ADR-002 | Agent API 远程管理接口 | 已接受 | 2026-06-17 |

---

## 未来规划

### P7: 多语言 + Webhooks 增强
- [ ] 多语言支持（国际化）
- [ ] Webhook 事件重试机制
- [ ] Webhook 历史记录

### P8: 集群 + 高可用
- [ ] 多节点复制
- [ ] 负载均衡
- [ ] 故障转移

### P9: 企业功能
- [ ] LDAP/SSO 集成
- [ ] 仓库分组/组织
- [ ] 合并请求 (Merge Requests)

---

## 联系与反馈

- 项目地址：https://github.com/youbanzhishi/OpenGit
- 问题反馈：GitHub Issues
