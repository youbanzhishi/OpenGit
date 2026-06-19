//! AI Guard — 代码语义分析，检测 AI Agent 推送的危险操作
//!
//! 功能：
//! - 危险命令检测（rm -rf, git push --force）
//! - 保护分支检测
//! - 批量删除检测
//! - 自定义规则引擎

use crate::audit::{AuditEntry, AuditLog};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

/// 危险等级
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical, // 阻断
    High,     // 阻断
    Medium,   // 警告
    Low,     // 记录
}

/// Guard 规则评估结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardResult {
    /// 是否允许操作
    pub allowed: bool,
    /// 触发的规则
    pub matched_rules: Vec<MatchedRule>,
    /// 消息
    pub message: String,
}

/// 匹配的规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedRule {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub pattern: String,
    pub action: String,
}

/// 一条 Guard 规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardRule {
    /// 规则 ID
    pub id: String,
    /// 规则名称
    pub name: String,
    /// 危险等级
    pub severity: Severity,
    /// 操作：block / warn / log
    pub action: String,
    /// 匹配模式（正则）
    pub pattern: Option<String>,
    /// 保护分支列表
    pub protected_branches: Option<Vec<String>>,
    /// 批量操作阈值
    pub batch_threshold: Option<usize>,
    /// 自定义消息
    pub message: Option<String>,
}

impl Default for GuardRule {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            severity: Severity::High,
            action: "block".to_string(),
            pattern: None,
            protected_branches: None,
            batch_threshold: None,
            message: None,
        }
    }
}

/// AI Guard 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiGuardConfig {
    /// 是否启用
    pub enabled: bool,
    /// 默认规则
    pub default_rules: Vec<GuardRule>,
    /// 自定义规则
    pub custom_rules: Vec<GuardRule>,
    /// 保护分支列表
    pub protected_branches: Vec<String>,
    /// 批量删除阈值
    pub batch_delete_threshold: usize,
    /// 审计配置
    pub audit: AuditConfig,
}

/// 审计配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// 记录所有事件
    pub log_all: bool,
    /// 记录警告
    pub log_warnings: bool,
    /// 警告 Webhook
    pub notify_webhook: Option<String>,
}

impl Default for AiGuardConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_rules: Self::default_rules(),
            custom_rules: Vec::new(),
            protected_branches: vec![
                "master".to_string(),
                "main".to_string(),
                "develop".to_string(),
            ],
            batch_delete_threshold: 10,
            audit: AuditConfig {
                log_all: true,
                log_warnings: true,
                notify_webhook: None,
            },
        }
    }
}

impl AiGuardConfig {
    /// 默认危险规则
    pub fn default_rules() -> Vec<GuardRule> {
        vec![
            GuardRule {
                id: "no-rm-rf".to_string(),
                name: "禁止 rm -rf 命令".to_string(),
                severity: Severity::Critical,
                action: "block".to_string(),
                pattern: Some(r"rm\s+-rf".to_string()),
                message: Some("检测到危险命令 rm -rf，操作已被阻断".to_string()),
                ..Default::default()
            },
            GuardRule {
                id: "no-force-push".to_string(),
                name: "禁止 force push".to_string(),
                severity: Severity::High,
                action: "block".to_string(),
                pattern: Some(r"git\s+push\s+--force".to_string()),
                message: Some("Force push 已禁用，请使用 merge".to_string()),
                ..Default::default()
            },
            GuardRule {
                id: "no-git-reset-hard".to_string(),
                name: "检测 git reset --hard".to_string(),
                severity: Severity::Medium,
                action: "warn".to_string(),
                pattern: Some(r"git\s+reset\s+--hard".to_string()),
                message: Some("检测到 hard reset，操作将被记录".to_string()),
                ..Default::default()
            },
            GuardRule {
                id: "no-git-reflog".to_string(),
                name: "检测 git reflog 操作".to_string(),
                severity: Severity::Medium,
                action: "warn".to_string(),
                pattern: Some(r"git\s+reflog".to_string()),
                message: Some("检测到 reflog 操作".to_string()),
                ..Default::default()
            },
            GuardRule {
                id: "no-chmod-git".to_string(),
                name: "检测 chmod 修改 .git".to_string(),
                severity: Severity::High,
                action: "block".to_string(),
                pattern: Some(r"chmod\s+.*\.git".to_string()),
                message: Some("禁止修改 .git 目录权限".to_string()),
                ..Default::default()
            },
            GuardRule {
                id: "no-remove-origin".to_string(),
                name: "检测删除 remote".to_string(),
                severity: Severity::Medium,
                action: "warn".to_string(),
                pattern: Some(r"git\s+remote\s+remove".to_string()),
                message: Some("检测到删除 remote 操作".to_string()),
                ..Default::default()
            },
        ]
    }

    /// 获取所有规则
    pub fn all_rules(&self) -> Vec<GuardRule> {
        let mut rules = self.default_rules.clone();
        rules.extend(self.custom_rules.clone());
        rules
    }
}

/// AI Guard 评估器
pub struct AiGuard {
    config: RwLock<AiGuardConfig>,
    audit_log: AuditLog,
}

impl AiGuard {
    /// 创建新的 AI Guard
    pub fn new(config: AiGuardConfig, audit_log: AuditLog) -> Self {
        Self {
            config: RwLock::new(config),
            audit_log,
        }
    }

    /// 从默认配置创建
    pub fn with_defaults(audit_log: AuditLog) -> Self {
        Self::new(AiGuardConfig::default(), audit_log)
    }

    /// 更新配置
    pub fn update_config(&self, config: AiGuardConfig) {
        if let Ok(mut cfg) = self.config.write() {
            *cfg = config;
        }
    }

    /// 获取当前配置
    pub fn config(&self) -> Option<AiGuardConfig> {
        self.config.read().ok().map(|c| c.clone())
    }

    /// 评估提交消息
    pub fn evaluate_commit_message(&self, msg: &str) -> GuardResult {
        let config = match self.config.read() {
            Ok(c) => c,
            Err(_) => return GuardResult::blocked("配置读取失败"),
        };

        if !config.enabled {
            return GuardResult::allowed();
        }

        let mut matched_rules = Vec::new();

        for rule in config.all_rules() {
            if let Some(pattern) = &rule.pattern {
                if let Ok(re) = regex::Regex::new(pattern) {
                    if re.is_match(msg) {
                        matched_rules.push(MatchedRule {
                            rule_id: rule.id.clone(),
                            rule_name: rule.name.clone(),
                            severity: rule.severity,
                            pattern: pattern.clone(),
                            action: rule.action.clone(),
                        });

                        // 记录审计
                        self.audit_log.log(AuditEntry {
                            id: uuid::Uuid::new_v4().to_string(),
                            timestamp: chrono::Utc::now().to_rfc3339(),
                            operation: crate::audit::AuditOperation::MirrorPush,
                            repo: "N/A".to_string(),
                            branch: None,
                            actor: Some("ai-guard".to_string()),
                            identity: Some("ai-guard".to_string()),
                            action: format!("guard:{}", rule.id),
                            ref_name: None,
                            allowed: rule.action != "block",
                            reason: Some(rule.message.clone().unwrap_or_default()),
                        });

                        // Critical/High 直接阻断
                        if rule.severity == Severity::Critical || rule.severity == Severity::High {
                            if rule.action == "block" {
                                return GuardResult::blocked(
                                    rule.message
                                        .clone()
                                        .unwrap_or_else(|| format!("规则 {} 阻断操作", rule.name)),
                                );
                            }
                        }
                    }
                }
            }
        }

        if matched_rules.is_empty() {
            GuardResult::allowed()
        } else {
            let messages: Vec<String> = matched_rules
                .iter()
                .filter(|r| r.action == "warn" || r.action == "block")
                .map(|r| format!("[{}] {}", format!("{:?}", r.severity).to_uppercase(), r.rule_name))
                .collect();

            GuardResult::warning(&matched_rules, &messages.join("; "))
        }
    }

    /// 评估分支保护
    pub fn evaluate_branch_protection(
        &self,
        branch: &str,
        is_delete: bool,
    ) -> GuardResult {
        let config = match self.config.read() {
            Ok(c) => c,
            Err(_) => return GuardResult::blocked("配置读取失败"),
        };

        if !config.enabled {
            return GuardResult::allowed();
        }

        // 检查是否保护分支
        if config.protected_branches.contains(&branch.to_string()) {
            return GuardResult::blocked(&format!(
                "禁止删除保护分支: {}",
                branch
            ));
        }

        GuardResult::allowed()
    }

    /// 评估批量删除
    pub fn evaluate_batch_delete(&self, deleted_files: &[String]) -> GuardResult {
        let config = match self.config.read() {
            Ok(c) => c,
            Err(_) => return GuardResult::blocked("配置读取失败"),
        };

        if !config.enabled {
            return GuardResult::allowed();
        }

        let count = deleted_files.len();
        if count >= config.batch_delete_threshold {
            return GuardResult::blocked(&format!(
                "批量删除超过阈值: 删除 {} 个文件 (阈值: {})",
                count, config.batch_delete_threshold
            ));
        }

        GuardResult::allowed()
    }

    /// 评估 Git diff（分析变更内容）
    pub fn evaluate_diff(&self, diff_content: &str) -> GuardResult {
        let config = match self.config.read() {
            Ok(c) => c,
            Err(_) => return GuardResult::blocked("配置读取失败"),
        };

        if !config.enabled {
            return GuardResult::allowed();
        }

        let mut matched_rules = Vec::new();
        let mut blocked = false;
        let mut block_message = String::new();

        for rule in config.all_rules() {
            if let Some(pattern) = &rule.pattern {
                if let Ok(re) = regex::Regex::new(pattern) {
                    if re.is_match(diff_content) {
                        matched_rules.push(MatchedRule {
                            rule_id: rule.id.clone(),
                            rule_name: rule.name.clone(),
                            severity: rule.severity,
                            pattern: pattern.clone(),
                            action: rule.action.clone(),
                        });

                        if rule.severity == Severity::Critical || rule.severity == Severity::High {
                            if rule.action == "block" {
                                blocked = true;
                                block_message = rule
                                    .message
                                    .clone()
                                    .unwrap_or_else(|| format!("规则 {} 阻断操作", rule.name));
                            }
                        }
                    }
                }
            }
        }

        if blocked {
            GuardResult::blocked(&block_message)
        } else if !matched_rules.is_empty() {
            let messages: Vec<String> = matched_rules
                .iter()
                .filter(|r| r.action == "warn")
                .map(|r| format!("[{}] {}", format!("{:?}", r.severity).to_uppercase(), r.rule_name))
                .collect();

            if messages.is_empty() {
                GuardResult::allowed()
            } else {
                GuardResult::warning(&matched_rules, &messages.join("; "))
            }
        } else {
            GuardResult::allowed()
        }
    }

    /// 全面评估（commit message + diff + branch）
    pub fn evaluate_full(
        &self,
        commit_msg: &str,
        diff_content: &str,
        branch: &str,
        is_delete: bool,
        deleted_files: &[String],
    ) -> GuardResult {
        // 1. 检查分支保护
        let branch_result = self.evaluate_branch_protection(branch, is_delete);
        if !branch_result.allowed {
            return branch_result;
        }

        // 2. 检查批量删除
        if !deleted_files.is_empty() {
            let batch_result = self.evaluate_batch_delete(deleted_files);
            if !batch_result.allowed {
                return batch_result;
            }
        }

        // 3. 检查提交消息
        let msg_result = self.evaluate_commit_message(commit_msg);
        if !msg_result.allowed {
            return msg_result;
        }

        // 4. 检查 diff
        let diff_result = self.evaluate_diff(diff_content);
        diff_result
    }
}

/// GuardResult 辅助方法
impl GuardResult {
    /// 允许操作
    pub fn allowed() -> Self {
        Self {
            allowed: true,
            matched_rules: Vec::new(),
            message: "Allowed".to_string(),
        }
    }

    /// 阻断操作
    pub fn blocked(reason: &str) -> Self {
        Self {
            allowed: false,
            matched_rules: Vec::new(),
            message: reason.to_string(),
        }
    }

    /// 警告但允许
    pub fn warning(rules: &[MatchedRule], msg: &str) -> Self {
        Self {
            allowed: true,
            matched_rules: rules.to_vec(),
            message: msg.to_string(),
        }
    }
}

/// 配置加载/保存
impl AiGuardConfig {
    /// 从文件加载
    pub fn load_from_file(path: &str) -> std::io::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        toml::from_str(&content).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// 保存到文件
    pub fn save_to_file(&self, path: &str) -> std::io::Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_rm_rf() {
        let audit = AuditLog::new();
        let guard = AiGuard::with_defaults(audit);

        let result = guard.evaluate_commit_message("rm -rf .git");
        assert!(!result.allowed);
        assert!(result.message.contains("rm -rf"));
    }

    #[test]
    fn test_detect_force_push() {
        let audit = AuditLog::new();
        let guard = AiGuard::with_defaults(audit);

        let result = guard.evaluate_commit_message("git push --force origin master");
        assert!(!result.allowed);
    }

    #[test]
    fn test_normal_commit() {
        let audit = AuditLog::new();
        let guard = AiGuard::with_defaults(audit);

        let result = guard.evaluate_commit_message("feat: add new feature");
        assert!(result.allowed);
    }

    #[test]
    fn test_protected_branch_delete() {
        let audit = AuditLog::new();
        let guard = AiGuard::with_defaults(audit);

        let result = guard.evaluate_branch_protection("master", true);
        assert!(!result.allowed);
    }

    #[test]
    fn test_batch_delete() {
        let audit = AuditLog::new();
        let guard = AiGuard::with_defaults(audit);

        let deleted: Vec<String> = (0..15).map(|i| format!("file{}.txt", i)).collect();
        let result = guard.evaluate_batch_delete(&deleted);
        assert!(!result.allowed);
    }
}
