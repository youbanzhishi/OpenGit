//! OpenGit Dashboard - Web UI for OpenGit management
//!
//! P6: Dashboard module providing static file serving and embedded HTML

use axum::{
    response::{Html, IntoResponse},
    routing::get,
    Router,
};

/// Dashboard state (lightweight, mostly for config reference)
pub struct DashboardState {
    pub server_version: String,
}

/// Build the dashboard router with embedded HTML
pub fn build_router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::<S>::new()
        .route("/", get(dashboard_index))
        .route("/dashboard.js", get(dashboard_js))
        .route("/dashboard.css", get(dashboard_css))
        .route("/api/config/server", get(get_server_config))
        .route("/api/config/policy", get(get_policy_config))
        .route("/api/config/webhooks", get(get_webhooks_config))
        .route("/api/config/mirrors", get(get_mirrors_config))
}

/// Embedded HTML - Main Dashboard Page
async fn dashboard_index() -> impl IntoResponse {
    Html(DASHBOARD_HTML)
}

/// Embedded JavaScript
async fn dashboard_js() -> impl IntoResponse {
    (
        axum::http::HeaderMap::from_iter([
            (axum::http::HeaderName::from_static("content-type"), "application/javascript".parse().unwrap()),
        ]),
        DASHBOARD_JS,
    )
}

/// Embedded CSS
async fn dashboard_css() -> impl IntoResponse {
    (
        axum::http::HeaderMap::from_iter([
            (axum::http::HeaderName::from_static("content-type"), "text/css".parse().unwrap()),
        ]),
        DASHBOARD_CSS,
    )
}

/// Server configuration endpoint for dashboard
async fn get_server_config() -> impl IntoResponse {
    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "features": ["repos", "policy", "webhooks", "mirrors", "audit", "import"]
    }))
}

/// Placeholder - actual policy config fetched from server API
async fn get_policy_config() -> impl IntoResponse {
    Json(serde_json::json!({
        "message": "Policy config via /api/policy/rules"
    }))
}

/// Placeholder - actual webhooks config
async fn get_webhooks_config() -> impl IntoResponse {
    Json(serde_json::json!({
        "message": "Webhooks config via /api/webhooks"
    }))
}

/// Placeholder - actual mirrors config
async fn get_mirrors_config() -> impl IntoResponse {
    Json(serde_json::json!({
        "message": "Mirrors config via /api/mirrors"
    }))
}

use axum::Json;

const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenGit Dashboard</title>
    <link rel="stylesheet" href="/dashboard.css">
</head>
<body>
    <div id="app">
        <!-- Header -->
        <header class="header">
            <div class="header-left">
                <span class="logo">🐉</span>
                <h1>OpenGit Dashboard</h1>
                <span class="version" id="version"></span>
            </div>
            <div class="header-right">
                <span class="status" id="server-status">连接中...</span>
            </div>
        </header>

        <!-- Main Content -->
        <main class="main">
            <!-- Sidebar -->
            <nav class="sidebar">
                <button class="nav-btn active" data-tab="repos">
                    <span class="icon">📦</span> 仓库管理
                </button>
                <button class="nav-btn" data-tab="policy">
                    <span class="icon">🛡️</span> 访问策略
                </button>
                <button class="nav-btn" data-tab="webhooks">
                    <span class="icon">🔗</span> Webhooks
                </button>
                <button class="nav-btn" data-tab="mirrors">
                    <span class="icon">🪞</span> 镜像同步
                </button>
                <button class="nav-btn" data-tab="automation">
                    <span class="icon">⚡</span> 自动化规则
                </button>
                <button class="nav-btn" data-tab="audit">
                    <span class="icon">📋</span> 审计日志
                </button>
                <button class="nav-btn" data-tab="config">
                    <span class="icon">⚙️</span> 配置文件
                </button>
                <button class="nav-btn" data-tab="import">
                    <span class="icon">📥</span> 导入迁移
                </button>
            </nav>

            <!-- Content Area -->
            <div class="content">
                <!-- Repos Tab -->
                <section id="tab-repos" class="tab-content active">
                    <div class="section-header">
                        <h2>仓库管理</h2>
                        <div class="actions">
                            <input type="text" id="repo-search" placeholder="搜索仓库..." class="search-input">
                            <button class="btn btn-primary" onclick="showCreateRepoModal()">+ 新建仓库</button>
                            <button class="btn" onclick="refreshRepos()">🔄 刷新</button>
                        </div>
                    </div>
                    <div id="repos-list" class="card-grid"></div>
                </section>

                <!-- Policy Tab -->
                <section id="tab-policy" class="tab-content">
                    <div class="section-header">
                        <h2>访问策略</h2>
                        <button class="btn btn-primary" onclick="showAddPolicyModal()">+ 添加规则</button>
                    </div>
                    <div id="policy-list" class="list-table"></div>
                </section>

                <!-- Webhooks Tab -->
                <section id="tab-webhooks" class="tab-content">
                    <div class="section-header">
                        <h2>Webhooks</h2>
                        <button class="btn btn-primary" onclick="showAddWebhookModal()">+ 添加 Webhook</button>
                    </div>
                    <div id="webhooks-list" class="list-table"></div>
                </section>

                <!-- Mirrors Tab -->
                <section id="tab-mirrors" class="tab-content">
                    <div class="section-header">
                        <h2>镜像同步</h2>
                        <button class="btn btn-primary" onclick="showAddMirrorModal()">+ 添加镜像</button>
                    </div>
                    <div id="mirrors-list" class="list-table"></div>
                </section>

                <!-- Automation Tab -->
                <section id="tab-automation" class="tab-content">
                    <div class="section-header">
                        <h2>自动化规则</h2>
                        <button class="btn btn-primary" onclick="showAddAutomationModal()">+ 添加规则</button>
                    </div>
                    <div class="automation-builder">
                        <div class="rule-card">
                            <h3>触发条件</h3>
                            <select id="trigger-type">
                                <option value="push">代码推送</option>
                                <option value="tag">创建标签</option>
                                <option value="branch">分支操作</option>
                                <option value="merge">合并请求</option>
                            </select>
                            <select id="trigger-repo">
                                <option value="*">所有仓库</option>
                            </select>
                        </div>
                        <div class="rule-card">
                            <h3>执行动作</h3>
                            <select id="action-type">
                                <option value="webhook">触发 Webhook</option>
                                <option value="mirror">同步到镜像</option>
                                <option value="backup">备份仓库</option>
                                <option value="notify">发送通知</option>
                                <option value="deploy">触发部署</option>
                            </select>
                            <input type="text" id="action-config" placeholder="动作配置...">
                        </div>
                    </div>
                    <div id="automation-rules" class="list-table"></div>
                </section>

                <!-- Audit Tab -->
                <section id="tab-audit" class="tab-content">
                    <div class="section-header">
                        <h2>审计日志</h2>
                        <select id="audit-filter">
                            <option value="all">全部</option>
                            <option value="denied">拒绝访问</option>
                            <option value="push">代码推送</option>
                            <option value="clone">仓库克隆</option>
                        </select>
                    </div>
                    <div id="audit-list" class="audit-log"></div>
                </section>

                <!-- Config Tab -->
                <section id="tab-config" class="tab-content">
                    <div class="section-header">
                        <h2>配置文件管理</h2>
                        <button class="btn btn-primary" onclick="saveAllConfig()">💾 保存所有配置</button>
                    </div>
                    <div class="config-editor">
                        <div class="config-file">
                            <h3>server.toml</h3>
                            <textarea id="config-server" rows="12" readonly></textarea>
                            <button class="btn" onclick="editConfig('server')">编辑</button>
                        </div>
                        <div class="config-file">
                            <h3>policies.yaml</h3>
                            <textarea id="config-policy" rows="12" readonly></textarea>
                            <button class="btn" onclick="editConfig('policy')">编辑</button>
                        </div>
                        <div class="config-file">
                            <h3>webhooks.yaml</h3>
                            <textarea id="config-webhooks" rows="12" readonly></textarea>
                            <button class="btn" onclick="editConfig('webhooks')">编辑</button>
                        </div>
                        <div class="config-file">
                            <h3>mirrors.toml</h3>
                            <textarea id="config-mirrors" rows="12" readonly></textarea>
                            <button class="btn" onclick="editConfig('mirrors')">编辑</button>
                        </div>
                    </div>
                </section>

                <!-- Import Tab -->
                <section id="tab-import" class="tab-content">
                    <div class="section-header">
                        <h2>导入与迁移</h2>
                    </div>
                    <div class="import-form">
                        <div class="form-group">
                            <label>导入来源</label>
                            <select id="import-source">
                                <option value="git">Git URL</option>
                                <option value="gitea">Gitea 服务器</option>
                            </select>
                        </div>
                        <div id="git-import" class="import-source-config">
                            <div class="form-group">
                                <label>仓库 URL</label>
                                <input type="text" id="import-url" placeholder="https://github.com/user/repo.git">
                            </div>
                            <div class="form-group">
                                <label>仓库名称（可选）</label>
                                <input type="text" id="import-name" placeholder="my-repo">
                            </div>
                        </div>
                        <div id="gitea-import" class="import-source-config" style="display:none;">
                            <div class="form-group">
                                <label>Gitea 服务器地址</label>
                                <input type="text" id="gitea-url" placeholder="https://gitea.com">
                            </div>
                            <div class="form-group">
                                <label>API Token</label>
                                <input type="password" id="gitea-token">
                            </div>
                            <div class="form-group">
                                <label>仓库列表（逗号分隔，留空则全部）</label>
                                <input type="text" id="gitea-repos" placeholder="repo1, repo2">
                            </div>
                        </div>
                        <button class="btn btn-primary" onclick="startImport()">开始导入</button>
                    </div>
                    <div id="import-status"></div>
                </section>
            </div>
        </main>

        <!-- Modal -->
        <div id="modal" class="modal">
            <div class="modal-content">
                <span class="modal-close" onclick="closeModal()">&times;</span>
                <div id="modal-body"></div>
            </div>
        </div>
    </div>
    <script src="/dashboard.js"></script>
</body>
</html>
"#;

const DASHBOARD_CSS: &str = r#"
:root {
    --primary: #6366f1;
    --primary-dark: #4f46e5;
    --bg: #0f172a;
    --bg-light: #1e293b;
    --bg-card: #1e293b;
    --text: #e2e8f0;
    --text-muted: #94a3b8;
    --border: #334155;
    --success: #22c55e;
    --warning: #f59e0b;
    --danger: #ef4444;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
}

.header {
    background: var(--bg-light);
    border-bottom: 1px solid var(--border);
    padding: 1rem 1.5rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.header-left { display: flex; align-items: center; gap: 0.75rem; }
.logo { font-size: 1.5rem; }
.header h1 { font-size: 1.25rem; font-weight: 600; }
.version { font-size: 0.75rem; color: var(--text-muted); background: var(--bg); padding: 0.25rem 0.5rem; border-radius: 4px; }
.status { font-size: 0.875rem; }
.status.online { color: var(--success); }
.status.offline { color: var(--danger); }

.main { display: flex; min-height: calc(100vh - 60px); }

.sidebar {
    width: 200px;
    background: var(--bg-light);
    border-right: 1px solid var(--border);
    padding: 1rem 0;
}

.nav-btn {
    width: 100%;
    padding: 0.75rem 1rem;
    background: none;
    border: none;
    color: var(--text-muted);
    text-align: left;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.875rem;
    transition: all 0.2s;
}
.nav-btn:hover { background: var(--bg); color: var(--text); }
.nav-btn.active { background: var(--primary); color: white; }
.icon { font-size: 1rem; }

.content {
    flex: 1;
    padding: 1.5rem;
    overflow-y: auto;
}

.tab-content { display: none; }
.tab-content.active { display: block; }

.section-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
}
.section-header h2 { font-size: 1.25rem; }
.actions { display: flex; gap: 0.5rem; align-items: center; }

.btn {
    padding: 0.5rem 1rem;
    background: var(--bg-card);
    border: 1px solid var(--border);
    color: var(--text);
    border-radius: 6px;
    cursor: pointer;
    font-size: 0.875rem;
    transition: all 0.2s;
}
.btn:hover { background: var(--border); }
.btn-primary { background: var(--primary); border-color: var(--primary); }
.btn-primary:hover { background: var(--primary-dark); }

.search-input {
    padding: 0.5rem 1rem;
    background: var(--bg-card);
    border: 1px solid var(--border);
    color: var(--text);
    border-radius: 6px;
    width: 200px;
}

.card-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 1rem;
}

.repo-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1rem;
    cursor: pointer;
    transition: all 0.2s;
}
.repo-card:hover { border-color: var(--primary); transform: translateY(-2px); }
.repo-card h3 { font-size: 1rem; margin-bottom: 0.5rem; }
.repo-card .meta { font-size: 0.75rem; color: var(--text-muted); }
.repo-card .actions { margin-top: 0.75rem; }

.list-table {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
}
.list-table table { width: 100%; border-collapse: collapse; }
.list-table th, .list-table td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--border); }
.list-table th { background: var(--bg); font-weight: 500; font-size: 0.875rem; }
.list-table tr:last-child td { border-bottom: none; }
.list-table tr:hover td { background: rgba(99, 102, 241, 0.1); }

.audit-log { max-height: 500px; overflow-y: auto; }
.audit-entry {
    padding: 0.75rem;
    border-bottom: 1px solid var(--border);
    font-size: 0.875rem;
}
.audit-entry:last-child { border-bottom: none; }
.audit-entry .time { color: var(--text-muted); font-size: 0.75rem; }
.audit-entry .action { margin: 0.25rem 0; }
.audit-entry.denied { border-left: 3px solid var(--danger); }
.audit-entry.allowed { border-left: 3px solid var(--success); }

.config-editor { display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; }
.config-file { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; }
.config-file h3 { margin-bottom: 0.75rem; font-size: 0.875rem; color: var(--text-muted); }
.config-file textarea { width: 100%; background: var(--bg); border: 1px solid var(--border); color: var(--text); border-radius: 4px; padding: 0.5rem; font-family: monospace; font-size: 0.875rem; resize: vertical; }
.config-file .btn { margin-top: 0.5rem; }

.automation-builder { display: flex; gap: 1rem; margin-bottom: 1.5rem; }
.rule-card { flex: 1; background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; }
.rule-card h3 { margin-bottom: 0.75rem; font-size: 0.875rem; color: var(--primary); }
.rule-card select, .rule-card input { width: 100%; padding: 0.5rem; background: var(--bg); border: 1px solid var(--border); color: var(--text); border-radius: 4px; margin-bottom: 0.5rem; }

.import-form { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; max-width: 600px; }
.form-group { margin-bottom: 1rem; }
.form-group label { display: block; margin-bottom: 0.5rem; font-size: 0.875rem; color: var(--text-muted); }
.form-group input, .form-group select { width: 100%; padding: 0.75rem; background: var(--bg); border: 1px solid var(--border); color: var(--text); border-radius: 6px; }

#import-status { margin-top: 1rem; }

.modal { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); z-index: 1000; align-items: center; justify-content: center; }
.modal.active { display: flex; }
.modal-content { background: var(--bg-light); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; max-width: 500px; width: 90%; max-height: 80vh; overflow-y: auto; position: relative; }
.modal-close { position: absolute; top: 1rem; right: 1rem; font-size: 1.5rem; cursor: pointer; color: var(--text-muted); }
.modal-close:hover { color: var(--text); }

@media (max-width: 768px) {
    .main { flex-direction: column; }
    .sidebar { width: 100%; display: flex; overflow-x: auto; }
    .nav-btn { width: auto; white-space: nowrap; }
    .config-editor { grid-template-columns: 1fr; }
}
"#;

const DASHBOARD_JS: &str = r#"
// OpenGit Dashboard JavaScript

const API_BASE = '/api';
let currentToken = localStorage.getItem('opengit_token') || '';

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
    // Tab navigation
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const tab = btn.dataset.tab;
            switchTab(tab);
        });
    });

    // Import source toggle
    document.getElementById('import-source').addEventListener('change', (e) => {
        document.getElementById('git-import').style.display = e.target.value === 'git' ? 'block' : 'none';
        document.getElementById('gitea-import').style.display = e.target.value === 'gitea' ? 'block' : 'none';
    });

    // Load initial data
    await checkConnection();
    if (currentToken) {
        loadRepos();
        loadPolicy();
        loadWebhooks();
        loadMirrors();
        loadAudit();
        loadServerConfig();
    }
});

function switchTab(tab) {
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    document.querySelector(`[data-tab="${tab}"]`).classList.add('active');
    document.getElementById(`tab-${tab}`).classList.add('active');
}

async function checkConnection() {
    try {
        const res = await fetch('/health');
        if (res.ok) {
            document.getElementById('server-status').textContent = '🟢 在线';
            document.getElementById('server-status').className = 'status online';
            
            // Try to get version
            const info = await fetchWithAuth('/api/config/server');
            if (info) {
                document.getElementById('version').textContent = 'v' + (info.version || '0.5.0');
            }
        }
    } catch {
        document.getElementById('server-status').textContent = '🔴 离线';
        document.getElementById('server-status').className = 'status offline';
    }
}

async function fetchWithAuth(url, options = {}) {
    const headers = { 'Content-Type': 'application/json', ...options.headers };
    if (currentToken) {
        headers['Authorization'] = `Bearer ${currentToken}`;
    }
    return fetch(url, { ...options, headers }).then(r => r.json()).catch(() => null);
}

async function api(url, method = 'GET', body = null) {
    const options = { method, headers: { 'Content-Type': 'application/json' } };
    if (currentToken) options.headers['Authorization'] = `Bearer ${currentToken}`;
    if (body) options.body = JSON.stringify(body);
    return fetch(API_BASE + url, options).then(async r => {
        if (!r.ok) {
            if (r.status === 401) {
                showLoginModal();
                throw new Error('Unauthorized');
            }
            throw new Error(await r.text());
        }
        return r.json();
    });
}

// Repos
async function loadRepos() {
    const repos = await api('/repos');
    const container = document.getElementById('repos-list');
    if (!repos || repos.length === 0) {
        container.innerHTML = '<p style="color:var(--text-muted)">暂无仓库</p>';
        return;
    }
    container.innerHTML = repos.map(r => `
        <div class="repo-card" onclick="showRepoDetail('${r.name}')">
            <h3>${r.name}</h3>
            <div class="meta">${r.path}</div>
            <div class="actions">
                <button class="btn" onclick="event.stopPropagation(); cloneRepo('${r.name}')">克隆</button>
                <button class="btn" onclick="event.stopPropagation(); deleteRepo('${r.name}')">删除</button>
            </div>
        </div>
    `).join('');
}

function cloneRepo(name) {
    navigator.clipboard.writeText(`git clone http://localhost:9418/${name}.git`);
    alert(`克隆地址已复制: http://localhost:9418/${name}.git`);
}

async function deleteRepo(name) {
    if (!confirm(`确定要删除仓库 ${name} 吗？此操作不可恢复！`)) return;
    try {
        await api(`/repos/${name}`, 'DELETE');
        loadRepos();
    } catch (e) {
        alert('删除失败: ' + e.message);
    }
}

function showCreateRepoModal() {
    document.getElementById('modal-body').innerHTML = `
        <h2>新建仓库</h2>
        <div class="form-group" style="margin-top:1rem">
            <label>仓库名称</label>
            <input type="text" id="new-repo-name" placeholder="my-project">
        </div>
        <button class="btn btn-primary" style="margin-top:1rem" onclick="createRepo()">创建</button>
    `;
    document.getElementById('modal').classList.add('active');
}

async function createRepo() {
    const name = document.getElementById('new-repo-name').value.trim();
    if (!name) return alert('请输入仓库名称');
    try {
        await api('/repos', 'POST', { name });
        closeModal();
        loadRepos();
    } catch (e) {
        alert('创建失败: ' + e.message);
    }
}

// Policy
async function loadPolicy() {
    const rules = await api('/policy/rules');
    const container = document.getElementById('policy-list');
    if (!rules || rules.length === 0) {
        container.innerHTML = '<p style="padding:1rem;color:var(--text-muted)">暂无规则</p>';
        return;
    }
    container.innerHTML = `
        <table>
            <thead><tr><th>仓库</th><th>身份</th><th>动作</th><th>权限</th><th>原因</th></tr></thead>
            <tbody>${rules.map(r => `<tr><td>${r.repo || '*'}</td><td>${r.identity}</td><td>${r.action}</td><td>${r.permission}</td><td>${r.reason || '-'}</td></tr>`).join('')}</tbody>
        </table>
    `;
}

function showAddPolicyModal() {
    document.getElementById('modal-body').innerHTML = `
        <h2>添加策略规则</h2>
        <div class="form-group" style="margin-top:1rem">
            <label>仓库（* 表示所有）</label>
            <input type="text" id="policy-repo" value="*">
        </div>
        <div class="form-group">
            <label>身份</label>
            <input type="text" id="policy-identity" placeholder="admin">
        </div>
        <div class="form-group">
            <label>动作</label>
            <select id="policy-action">
                <option value="Read">读取</option>
                <option value="Push">推送</option>
                <option value="CreateRepo">创建仓库</option>
                <option value="DeleteRepo">删除仓库</option>
                <option value="Admin">管理</option>
            </select>
        </div>
        <div class="form-group">
            <label>权限</label>
            <select id="policy-permission">
                <option value="Allow">允许</option>
                <option value="Deny">拒绝</option>
            </select>
        </div>
        <button class="btn btn-primary" style="margin-top:1rem" onclick="addPolicyRule()">添加</button>
    `;
    document.getElementById('modal').classList.add('active');
}

async function addPolicyRule() {
    const rule = {
        repo: document.getElementById('policy-repo').value || '*',
        identity: document.getElementById('policy-identity').value,
        action: document.getElementById('policy-action').value,
        permission: document.getElementById('policy-permission').value,
    };
    if (!rule.identity) return alert('请输入身份');
    try {
        await api('/policy/rules', 'POST', rule);
        closeModal();
        loadPolicy();
    } catch (e) {
        alert('添加失败: ' + e.message);
    }
}

// Webhooks
async function loadWebhooks() {
    const webhooks = await api('/webhooks');
    const container = document.getElementById('webhooks-list');
    if (!webhooks || webhooks.length === 0) {
        container.innerHTML = '<p style="padding:1rem;color:var(--text-muted)">暂无 Webhooks</p>';
        return;
    }
    container.innerHTML = `
        <table>
            <thead><tr><th>URL</th><th>事件</th><th>状态</th><th>操作</th></tr></thead>
            <tbody>${webhooks.map((w, i) => `<tr>
                <td>${w.url}</td>
                <td>${w.events?.join(', ') || 'all'}</td>
                <td>${w.active ? '🟢 启用' : '🔴 禁用'}</td>
                <td><button class="btn" onclick="deleteWebhook(${i})">删除</button></td>
            </tr>`).join('')}</tbody>
        </table>
    `;
}

function showAddWebhookModal() {
    document.getElementById('modal-body').innerHTML = `
        <h2>添加 Webhook</h2>
        <div class="form-group" style="margin-top:1rem">
            <label>URL</label>
            <input type="text" id="webhook-url" placeholder="https://example.com/webhook">
        </div>
        <div class="form-group">
            <label>Secret（可选）</label>
            <input type="password" id="webhook-secret">
        </div>
        <div class="form-group">
            <label>事件</label>
            <select id="webhook-events" multiple>
                <option value="push" selected>Push</option>
                <option value="tag">Tag</option>
                <option value="delete-branch">删除分支</option>
            </select>
        </div>
        <button class="btn btn-primary" style="margin-top:1rem" onclick="addWebhook()">添加</button>
    `;
    document.getElementById('modal').classList.add('active');
}

async function addWebhook() {
    const url = document.getElementById('webhook-url').value;
    if (!url) return alert('请输入 URL');
    const webhook = {
        url,
        secret: document.getElementById('webhook-secret').value || null,
        events: Array.from(document.getElementById('webhook-events').selectedOptions).map(o => o.value),
    };
    try {
        await api('/webhooks', 'POST', webhook);
        closeModal();
        loadWebhooks();
    } catch (e) {
        alert('添加失败: ' + e.message);
    }
}

async function deleteWebhook(idx) {
    if (!confirm('确定要删除这个 Webhook 吗？')) return;
    try {
        await api(`/webhooks/${idx}`, 'DELETE');
        loadWebhooks();
    } catch (e) {
        alert('删除失败: ' + e.message);
    }
}

// Mirrors
async function loadMirrors() {
    const mirrors = await api('/mirrors');
    const container = document.getElementById('mirrors-list');
    if (!mirrors || mirrors.length === 0) {
        container.innerHTML = '<p style="padding:1rem;color:var(--text-muted)">暂无镜像</p>';
        return;
    }
    container.innerHTML = `
        <table>
            <thead><tr><th>名称</th><th>目标 URL</th><th>仓库</th><th>状态</th><th>操作</th></tr></thead>
            <tbody>${mirrors.map((m, i) => `<tr>
                <td>${m.name}</td>
                <td>${m.url}</td>
                <td>${m.repos?.join(', ') || 'all'}</td>
                <td>${m.enabled ? '🟢 运行中' : '⏸️ 已暂停'}</td>
                <td><button class="btn" onclick="deleteMirror(${i})">删除</button></td>
            </tr>`).join('')}</tbody>
        </table>
    `;
}

function showAddMirrorModal() {
    document.getElementById('modal-body').innerHTML = `
        <h2>添加镜像</h2>
        <div class="form-group" style="margin-top:1rem">
            <label>名称</label>
            <input type="text" id="mirror-name" placeholder="backup-gitea">
        </div>
        <div class="form-group">
            <label>目标 URL</label>
            <input type="text" id="mirror-url" placeholder="https://gitea.com/user/repo.git">
        </div>
        <div class="form-group">
            <label>仓库（逗号分隔，空表示全部）</label>
            <input type="text" id="mirror-repos" placeholder="repo1, repo2">
        </div>
        <button class="btn btn-primary" style="margin-top:1rem" onclick="addMirror()">添加</button>
    `;
    document.getElementById('modal').classList.add('active');
}

async function addMirror() {
    const name = document.getElementById('mirror-name').value;
    const url = document.getElementById('mirror-url').value;
    if (!name || !url) return alert('请填写名称和 URL');
    const mirror = {
        name,
        url,
        repos: document.getElementById('mirror-repos').value ? document.getElementById('mirror-repos').value.split(',').map(s => s.trim()) : null,
    };
    try {
        await api('/mirrors', 'POST', mirror);
        closeModal();
        loadMirrors();
    } catch (e) {
        alert('添加失败: ' + e.message);
    }
}

async function deleteMirror(idx) {
    if (!confirm('确定要删除这个镜像吗？')) return;
    try {
        await api(`/mirrors/${idx}`, 'DELETE');
        loadMirrors();
    } catch (e) {
        alert('删除失败: ' + e.message);
    }
}

// Audit
async function loadAudit() {
    const entries = await api('/audit');
    const container = document.getElementById('audit-list');
    if (!entries || entries.length === 0) {
        container.innerHTML = '<p style="padding:1rem;color:var(--text-muted)">暂无日志</p>';
        return;
    }
    container.innerHTML = entries.slice(0, 100).map(e => `
        <div class="audit-entry ${e.allowed ? 'allowed' : 'denied'}">
            <div class="time">${new Date(e.timestamp).toLocaleString()}</div>
            <div class="action"><b>${e.identity}</b> ${e.action} <b>${e.repo}</b></div>
            <div class="result">${e.allowed ? '✅ 允许' : '❌ 拒绝'}${e.reason ? ': ' + e.reason : ''}</div>
        </div>
    `).join('');
}

// Config
async function loadServerConfig() {
    // Config files would be fetched from a dedicated endpoint
    // For now, show placeholders
    const serverExample = `# OpenGit Server Configuration
repos_dir = "./repos"
bind = "0.0.0.0:9418"
policy_file = "config/policies.yaml"
identity_file = "config/identities.yaml"
webhook_file = "config/webhooks.yaml"`;
    
    document.getElementById('config-server').value = serverExample;
}

function editConfig(type) {
    const textarea = document.getElementById(`config-${type}`);
    textarea.readOnly = !textarea.readOnly;
    if (!textarea.readOnly) {
        textarea.focus();
    }
}

async function saveAllConfig() {
    alert('配置保存功能需要后端支持，当前为只读模式');
}

// Import
async function startImport() {
    const source = document.getElementById('import-source').value;
    const statusDiv = document.getElementById('import-status');
    
    if (source === 'git') {
        const url = document.getElementById('import-url').value;
        if (!url) return alert('请输入仓库 URL');
        
        statusDiv.innerHTML = '<p>正在导入...</p>';
        try {
            const result = await api('/import', 'POST', {
                url,
                name: document.getElementById('import-name').value || null,
            });
            statusDiv.innerHTML = result.success 
                ? `<p style="color:var(--success)">✅ 导入成功！${result.name} (${result.branches} 分支, ${result.tags} 标签)</p>`
                : `<p style="color:var(--danger)">❌ 导入失败: ${result.error}</p>`;
            loadRepos();
        } catch (e) {
            statusDiv.innerHTML = `<p style="color:var(--danger)">❌ 导入失败: ${e.message}</p>`;
        }
    } else {
        const giteaUrl = document.getElementById('gitea-url').value;
        const token = document.getElementById('gitea-token').value;
        if (!giteaUrl || !token) return alert('请填写 Gitea 服务器和 Token');
        
        statusDiv.innerHTML = '<p>正在从 Gitea 迁移...</p>';
        try {
            const result = await api('/import/gitea', 'POST', {
                server_url: giteaUrl,
                token,
                repos: document.getElementById('gitea-repos').value ? document.getElementById('gitea-repos').value.split(',').map(s => s.trim()) : [],
            });
            statusDiv.innerHTML = `
                <p>迁移完成: ${result.imported}/${result.total} 成功</p>
                <p>耗时: ${result.elapsed_secs.toFixed(1)}s</p>
            `;
            loadRepos();
        } catch (e) {
            statusDiv.innerHTML = `<p style="color:var(--danger)">❌ 迁移失败: ${e.message}</p>`;
        }
    }
}

function refreshRepos() { loadRepos(); }

function showLoginModal() {
    document.getElementById('modal-body').innerHTML = `
        <h2>登录 OpenGit</h2>
        <div class="form-group" style="margin-top:1rem">
            <label>身份名称</label>
            <input type="text" id="login-name" value="admin">
        </div>
        <div class="form-group">
            <label>Token</label>
            <input type="password" id="login-token" placeholder="输入你的 token">
        </div>
        <p style="font-size:0.75rem;color:var(--text-muted);margin-bottom:1rem">
            首次使用请先注册身份并生成 Token
        </p>
        <button class="btn btn-primary" onclick="login()">登录</button>
    `;
    document.getElementById('modal').classList.add('active');
}

async function login() {
    const name = document.getElementById('login-name').value;
    const token = document.getElementById('login-token').value;
    if (!name || !token) return alert('请填写身份和 token');
    
    currentToken = token;
    localStorage.setItem('opengit_token', token);
    closeModal();
    
    // Reload data
    loadRepos();
    loadPolicy();
    loadWebhooks();
    loadMirrors();
    loadAudit();
}

function closeModal() {
    document.getElementById('modal').classList.remove('active');
}
"#;
