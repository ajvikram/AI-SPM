//! Filesystem Sentinel — Monitors file access by AI coding agents.
//!
//! Classifies file paths by sensitivity and enforces access policies:
//! - Project boundary enforcement
//! - Credential/secret file detection
//! - Configuration file change alerting
//! - System file protection
//! - Bulk operation detection

use ai_spm_core::types::{FileCheckResult, FileOp, FileSensitivity};
use chrono::Utc;
use tracing::warn;

/// Filesystem Sentinel for monitoring and controlling file access.
pub struct FsSentinel {
    /// Project root directory path
    project_root: Option<String>,
    /// Additional protected paths (user-configurable)
    protected_paths: Vec<String>,
    /// Allow access to dotfiles within project
    allow_project_dotfiles: bool,
}

impl FsSentinel {
    pub fn new() -> Self {
        Self {
            project_root: None,
            protected_paths: Vec::new(),
            allow_project_dotfiles: false,
        }
    }

    /// Set the project root directory.
    pub fn set_project_root(&mut self, root: impl Into<String>) {
        self.project_root = Some(root.into());
    }

    /// Add a custom protected path.
    pub fn add_protected_path(&mut self, path: impl Into<String>) {
        self.protected_paths.push(path.into());
    }

    /// Allow access to dotfiles within the project boundary.
    pub fn set_allow_project_dotfiles(&mut self, allow: bool) {
        self.allow_project_dotfiles = allow;
    }

    /// Check a file access operation against security policies.
    pub fn check_access(&self, path: &str, operation: FileOp) -> FileCheckResult {
        let sensitivity = self.classify_path(path);
        let (allowed, reason) = self.evaluate_access(path, operation, sensitivity);

        if !allowed {
            warn!(
                path = %path,
                operation = %operation,
                sensitivity = %sensitivity,
                "Filesystem sentinel BLOCKED file access"
            );
        }

        FileCheckResult {
            path: path.to_string(),
            operation,
            sensitivity,
            allowed,
            reason,
            timestamp: Utc::now(),
        }
    }

    /// Classify a file path by sensitivity level.
    pub fn classify_path(&self, path: &str) -> FileSensitivity {
        let normalized = path.replace('\\', "/");
        let lower = normalized.to_lowercase();

        // System files
        if self.is_system_path(&lower) {
            return FileSensitivity::System;
        }

        // Credential/secret files
        if self.is_credential_path(&lower) {
            return FileSensitivity::Credential;
        }

        // Configuration files
        if self.is_config_path(&lower) {
            return FileSensitivity::Config;
        }

        // Check project boundary
        if let Some(ref root) = self.project_root {
            let root_normalized = root.replace('\\', "/");
            if !normalized.starts_with(&root_normalized) && !normalized.starts_with("./") && !normalized.starts_with("src/") {
                // Could be a relative path within project, check for absolute out-of-bounds      
                if normalized.starts_with('/') || normalized.starts_with("~") {
                    return FileSensitivity::OutOfBounds;
                }
            }
        }

        // Custom protected paths
        for protected in &self.protected_paths {
            let prot_lower = protected.to_lowercase();
            if lower.contains(&prot_lower) {
                return FileSensitivity::Credential;
            }
        }

        FileSensitivity::Normal
    }

    // ── Access evaluation ───────────────────────────────────────────────

    fn evaluate_access(&self, path: &str, operation: FileOp, sensitivity: FileSensitivity) -> (bool, Option<String>) {
        match sensitivity {
            FileSensitivity::Normal => (true, None),

            FileSensitivity::Config => {
                match operation {
                    FileOp::Read => (true, Some("Reading config file — review changes carefully".into())),
                    FileOp::Write => (false, Some(format!(
                        "Writing to configuration file '{}' requires approval — could affect build/deploy pipeline",
                        path
                    ))),
                    FileOp::Delete => (false, Some(format!(
                        "Deleting configuration file '{}' is blocked",
                        path
                    ))),
                    FileOp::Execute => (false, Some("Executing config files is suspicious".into())),
                }
            }

            FileSensitivity::Credential => {
                (false, Some(format!(
                    "Access to credential/secret file '{}' is blocked — {} operation denied",
                    path, operation
                )))
            }

            FileSensitivity::System => {
                (false, Some(format!(
                    "Access to system file '{}' is blocked — agents should not touch system files",
                    path
                )))
            }

            FileSensitivity::OutOfBounds => {
                match operation {
                    FileOp::Read => (false, Some(format!(
                        "Reading file '{}' outside project boundary — out of scope",
                        path
                    ))),
                    _ => (false, Some(format!(
                        "Modifying file '{}' outside project boundary is blocked",
                        path
                    ))),
                }
            }
        }
    }

    // ── Path classification helpers ─────────────────────────────────────

    fn is_system_path(&self, path: &str) -> bool {
        let system_prefixes = [
            "/etc/", "/usr/", "/var/", "/sys/", "/proc/",
            "/boot/", "/sbin/", "/bin/", "/lib/", "/opt/",
            "/root/", "c:\\windows\\", "c:\\program files",
        ];
        for prefix in &system_prefixes {
            if path.starts_with(prefix) {
                return true;
            }
        }
        false
    }

    fn is_credential_path(&self, path: &str) -> bool {
        let credential_patterns = [
            // SSH
            "/.ssh/", "/.ssh/id_", "/.ssh/authorized_keys", "/.ssh/known_hosts",
            "/.ssh/config",
            // AWS
            "/.aws/credentials", "/.aws/config",
            // GCP
            "/.config/gcloud/", "/application_default_credentials",
            // Azure
            "/.azure/",
            // Docker
            "/.docker/config.json",
            // K8s
            "/.kube/config",
            // npm/PyPI
            "/.npmrc", "/.pypirc",
            // GPG
            "/.gnupg/",
            // Git credentials
            "/.git-credentials", "/.gitconfig",
            // Environment files
            ".env", ".env.local", ".env.production", ".env.secret",
            // Key files
            ".pem", ".key", ".p12", ".pfx", ".jks",
            // Token files
            ".token", ".secret",
        ];

        for pattern in &credential_patterns {
            if path.contains(pattern) {
                return true;
            }
        }

        // Files literally named "secrets", "credentials", "password"
        let basename = path.rsplit('/').next().unwrap_or(path);
        let secret_names = ["secrets", "credentials", "password", "passwords", "api_key", "api_keys", "tokens"];
        for name in &secret_names {
            if basename.to_lowercase().contains(name) {
                return true;
            }
        }

        false
    }

    fn is_config_path(&self, path: &str) -> bool {
        let config_files = [
            "dockerfile", "docker-compose", "fly.toml", "vercel.json", "netlify.toml",
            "makefile", "cmakelists.txt", "justfile",
            ".github/workflows/", ".gitlab-ci.yml", "jenkinsfile",
            ".circleci/", "bitbucket-pipelines",
            "package.json", "cargo.toml", "go.mod", "requirements.txt",
            "pyproject.toml", "setup.py", "setup.cfg",
            "tsconfig.json", "webpack.config", "vite.config",
            ".eslintrc", ".prettierrc", "babel.config",
            "nginx.conf", "apache.conf", "httpd.conf",
            "supervisord.conf", "systemd/",
        ];

        let basename = path.rsplit('/').next().unwrap_or(path);
        for cfg in &config_files {
            if basename.to_lowercase().contains(&cfg.to_lowercase())
                || path.to_lowercase().contains(&cfg.to_lowercase())
            {
                return true;
            }
        }

        false
    }
}

impl Default for FsSentinel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sentinel() -> FsSentinel {
        let mut s = FsSentinel::new();
        s.set_project_root("/home/user/project");
        s
    }

    #[test]
    fn test_normal_file_allowed() {
        let s = sentinel();
        let result = s.check_access("src/main.rs", FileOp::Read);
        assert!(result.allowed);
        assert_eq!(result.sensitivity, FileSensitivity::Normal);
    }

    #[test]
    fn test_normal_file_write_allowed() {
        let s = sentinel();
        let result = s.check_access("src/lib.rs", FileOp::Write);
        assert!(result.allowed);
    }

    #[test]
    fn test_ssh_key_blocked() {
        let s = sentinel();
        let result = s.check_access("/home/user/.ssh/id_rsa", FileOp::Read);
        assert!(!result.allowed);
        assert_eq!(result.sensitivity, FileSensitivity::Credential);
    }

    #[test]
    fn test_aws_credentials_blocked() {
        let s = sentinel();
        let result = s.check_access("/home/user/.aws/credentials", FileOp::Read);
        assert!(!result.allowed);
        assert_eq!(result.sensitivity, FileSensitivity::Credential);
    }

    #[test]
    fn test_env_file_blocked() {
        let s = sentinel();
        let result = s.check_access(".env", FileOp::Read);
        assert!(!result.allowed);
        assert_eq!(result.sensitivity, FileSensitivity::Credential);
    }

    #[test]
    fn test_env_production_blocked() {
        let s = sentinel();
        let result = s.check_access(".env.production", FileOp::Read);
        assert!(!result.allowed);
    }

    #[test]
    fn test_system_file_blocked() {
        let s = sentinel();
        let result = s.check_access("/etc/shadow", FileOp::Read);
        assert!(!result.allowed);
        assert_eq!(result.sensitivity, FileSensitivity::System);
    }

    #[test]
    fn test_dockerfile_config_read_allowed() {
        let s = sentinel();
        let result = s.check_access("Dockerfile", FileOp::Read);
        assert!(result.allowed); // Reading config is OK
        assert_eq!(result.sensitivity, FileSensitivity::Config);
    }

    #[test]
    fn test_dockerfile_config_write_blocked() {
        let s = sentinel();
        let result = s.check_access("Dockerfile", FileOp::Write);
        assert!(!result.allowed); // Writing config needs approval
        assert_eq!(result.sensitivity, FileSensitivity::Config);
    }

    #[test]
    fn test_ci_config_blocked() {
        let s = sentinel();
        let result = s.check_access(".github/workflows/deploy.yml", FileOp::Write);
        assert!(!result.allowed);
        assert_eq!(result.sensitivity, FileSensitivity::Config);
    }

    #[test]
    fn test_pem_file_blocked() {
        let s = sentinel();
        let result = s.check_access("server.pem", FileOp::Read);
        assert!(!result.allowed);
        assert_eq!(result.sensitivity, FileSensitivity::Credential);
    }

    #[test]
    fn test_custom_protected_path() {
        let mut s = sentinel();
        s.add_protected_path("internal-api");
        let result = s.check_access("internal-api/keys.json", FileOp::Read);
        assert!(!result.allowed);
    }

    #[test]
    fn test_kube_config_blocked() {
        let s = sentinel();
        let result = s.check_access("/home/user/.kube/config", FileOp::Read);
        assert!(!result.allowed);
        assert_eq!(result.sensitivity, FileSensitivity::Credential);
    }

    #[test]
    fn test_classify_normal_path() {
        let s = sentinel();
        assert_eq!(s.classify_path("src/components/Button.tsx"), FileSensitivity::Normal);
    }

    #[test]
    fn test_classify_credential_path() {
        let s = sentinel();
        assert_eq!(s.classify_path("/home/user/.ssh/id_ed25519"), FileSensitivity::Credential);
    }

    #[test]
    fn test_classify_system_path() {
        let s = sentinel();
        assert_eq!(s.classify_path("/etc/nginx/nginx.conf"), FileSensitivity::System);
    }
}
