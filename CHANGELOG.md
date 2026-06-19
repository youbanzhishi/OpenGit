# Changelog

## v1.1.0 (开发中)

### 新功能
- P8.2: 邮件通知系统
  - SMTP 配置支持
  - Web Dashboard 邮件设置页面
  - 推送成功通知
  - 镜像同步结果通知
- P8.3: API 追加文件功能
  - `POST /api/repos/{name}/append` - 直接追加文件，无需克隆
  - `GET /api/repos/{name}/files` - 列出仓库文件
  - `GET /api/repos/{name}/files/exists` - 检查文件是否存在
  - 只允许追加新文件，禁止覆盖已有文件

## v1.0.0
- 初始版本
