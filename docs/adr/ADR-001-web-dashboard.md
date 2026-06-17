# ADR-001: OpenGit Web Dashboard 实现

## Status
已接受 (2026-06-17)

## Context
用户需要一个可视化的管理界面来管理 OpenGit 服务，无需 SSH 或命令行即可：
- 管理仓库（创建、删除、查看）
- 配置访问策略
- 管理 Webhooks
- 配置镜像同步
- 查看审计日志
- 从其他服务导入仓库

## Decision
实现内置 Web Dashboard（P6），使用嵌入式 HTML/CSS/JS：

### 技术方案
- 使用 Axum 静态文件服务
- HTML/CSS/JS 内嵌在 Rust 代码中，无需额外构建
- RESTful API 调用后端接口
- Bearer Token 认证

### Dashboard 功能模块
| 模块 | 路由 | 功能 |
|------|------|------|
| 仓库管理 | / | 创建、删除、搜索仓库 |
| 访问策略 | / | 可视化规则管理 |
| Webhooks | / | 钩子配置 |
| 镜像同步 | / | 多端镜像 |
| 自动化规则 | / | 触发-动作配置器 |
| 审计日志 | / | 操作记录 |
| 配置文件 | / | 在线编辑 |
| 导入迁移 | / | Git URL / Gitea |

### 权限设计
- 默认 admin 身份拥有所有权限
- Dashboard 需要登录认证
- Token 存储在 localStorage

## Consequences
### 正面
- 用户无需安装额外工具即可管理服务
- 深色主题，移动端适配
- 零外部依赖

### 负面
- HTML/CSS/JS 内嵌导致代码较大
- 复杂 UI 交互受限

## References
- P6: Web Dashboard for management UI
