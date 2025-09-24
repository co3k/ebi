use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionConfig {
    pub target_command: String,
    pub target_args: Vec<String>,
    pub script_content: String,
    pub working_dir: Option<PathBuf>,
    pub env_vars: HashMap<String, String>,
    pub timeout_seconds: Option<u64>,
    pub sandbox_mode: bool,
}

impl ExecutionConfig {
    pub fn new(target_command: String, target_args: Vec<String>, script_content: String) -> Self {
        Self {
            target_command,
            target_args,
            script_content,
            working_dir: None,
            env_vars: HashMap::new(),
            timeout_seconds: None,
            sandbox_mode: false,
        }
    }

    pub fn with_working_dir(mut self, dir: PathBuf) -> Self {
        self.working_dir = Some(dir);
        self
    }

    pub fn with_env_var(mut self, key: String, value: String) -> Self {
        self.env_vars.insert(key, value);
        self
    }

    pub fn with_timeout(mut self, seconds: u64) -> Self {
        self.timeout_seconds = Some(seconds);
        self
    }

    pub fn with_sandbox(mut self) -> Self {
        self.sandbox_mode = true;
        self
    }

    pub fn get_full_command(&self) -> String {
        let mut cmd = self.target_command.clone();
        for arg in &self.target_args {
            cmd.push(' ');
            if arg.contains(' ') {
                cmd.push_str(&format!("\"{}\"", arg));
            } else {
                cmd.push_str(arg);
            }
        }
        cmd
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.target_command.is_empty() {
            return Err("Target command cannot be empty".to_string());
        }

        if self.script_content.is_empty() {
            return Err("Script content cannot be empty".to_string());
        }

        if let Some(timeout) = self.timeout_seconds {
            if timeout == 0 {
                return Err("Timeout must be greater than 0".to_string());
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub allow_network: bool,
    pub allow_filesystem_read: Vec<PathBuf>,
    pub allow_filesystem_write: Vec<PathBuf>,
    pub max_memory_mb: Option<usize>,
    pub max_cpu_percent: Option<usize>,
    pub allowed_commands: Vec<String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            allow_network: false,
            allow_filesystem_read: vec![PathBuf::from("/tmp")],
            allow_filesystem_write: vec![PathBuf::from("/tmp")],
            max_memory_mb: Some(512),
            max_cpu_percent: Some(50),
            allowed_commands: vec![],
        }
    }
}

impl SandboxConfig {
    pub fn permissive() -> Self {
        Self {
            allow_network: true,
            allow_filesystem_read: vec![],
            allow_filesystem_write: vec![],
            max_memory_mb: None,
            max_cpu_percent: None,
            allowed_commands: vec![],
        }
    }

    pub fn restrictive() -> Self {
        Self {
            allow_network: false,
            allow_filesystem_read: vec![],
            allow_filesystem_write: vec![],
            max_memory_mb: Some(128),
            max_cpu_percent: Some(25),
            allowed_commands: vec![
                "echo".to_string(),
                "cat".to_string(),
                "ls".to_string(),
                "pwd".to_string(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_config() {
        let config = ExecutionConfig::new(
            "bash".to_string(),
            vec!["-c".to_string(), "echo test".to_string()],
            "#!/bin/bash\necho hello".to_string(),
        );

        assert_eq!(config.target_command, "bash");
        assert_eq!(config.target_args, vec!["-c", "echo test"]);
        assert!(!config.sandbox_mode);

        let full_cmd = config.get_full_command();
        assert_eq!(full_cmd, "bash -c \"echo test\"");
    }

    #[test]
    fn test_config_validation() {
        let valid_config =
            ExecutionConfig::new("bash".to_string(), vec![], "echo test".to_string());
        assert!(valid_config.validate().is_ok());

        let invalid_config = ExecutionConfig::new("".to_string(), vec![], "echo test".to_string());
        assert!(invalid_config.validate().is_err());

        let empty_script = ExecutionConfig::new("bash".to_string(), vec![], "".to_string());
        assert!(empty_script.validate().is_err());
    }

    #[test]
    fn test_sandbox_configs() {
        let default_sandbox = SandboxConfig::default();
        assert!(!default_sandbox.allow_network);
        assert_eq!(default_sandbox.max_memory_mb, Some(512));

        let permissive = SandboxConfig::permissive();
        assert!(permissive.allow_network);
        assert!(permissive.max_memory_mb.is_none());

        let restrictive = SandboxConfig::restrictive();
        assert!(!restrictive.allow_network);
        assert_eq!(restrictive.max_memory_mb, Some(128));
        assert_eq!(restrictive.allowed_commands.len(), 4);
    }

    #[test]
    fn test_config_builders() {
        let config =
            ExecutionConfig::new("python".to_string(), vec![], "print('hello')".to_string())
                .with_timeout(30)
                .with_sandbox()
                .with_env_var("PYTHONPATH".to_string(), "/usr/lib".to_string());

        assert_eq!(config.timeout_seconds, Some(30));
        assert!(config.sandbox_mode);
        assert_eq!(
            config.env_vars.get("PYTHONPATH"),
            Some(&"/usr/lib".to_string())
        );
    }
}
