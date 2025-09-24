use crate::error::EbiError;
use crate::executor::ExecutionConfig;
use crate::models::{ExecutionDecision, Script};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

pub struct ScriptRunner {
    config: ExecutionConfig,
    timeout_seconds: Option<u64>,
}

impl ScriptRunner {
    pub fn new(config: ExecutionConfig) -> Self {
        Self {
            config,
            timeout_seconds: None,
        }
    }

    pub fn with_timeout(mut self, seconds: u64) -> Self {
        self.timeout_seconds = Some(seconds);
        self
    }

    pub async fn execute(&self, script: &Script) -> Result<i32, EbiError> {
        // Create command
        let mut command = Command::new(&self.config.target_command);
        command.args(&self.config.target_args);
        command.stdin(Stdio::piped());
        command.stdout(Stdio::inherit());
        command.stderr(Stdio::inherit());

        // Apply environment variables if any
        for (key, value) in &self.config.env_vars {
            command.env(key, value);
        }

        // Set working directory if specified
        if let Some(ref cwd) = self.config.working_dir {
            command.current_dir(cwd);
        }

        // Spawn the command
        let mut child = command.spawn().map_err(|_| EbiError::CommandNotFound {
            command: self.config.target_command.clone(),
        })?;

        // Write script content to stdin
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(script.content.as_bytes())
                .await
                .map_err(|e| {
                    EbiError::ExecutionFailed(format!("Failed to write to stdin: {}", e))
                })?;
            // Close stdin to signal EOF
        }

        // Wait for completion with optional timeout
        let exit_status = if let Some(timeout_secs) = self.timeout_seconds {
            match timeout(Duration::from_secs(timeout_secs), child.wait()).await {
                Ok(Ok(status)) => status,
                Ok(Err(e)) => return Err(EbiError::ExecutionFailed(e.to_string())),
                Err(_) => {
                    // Timeout occurred, try to kill the process
                    if let Err(kill_err) = child.start_kill() {
                        return Err(EbiError::ExecutionFailed(format!(
                            "Script execution timed out after {} seconds and could not be terminated: {}",
                            timeout_secs,
                            kill_err
                        )));
                    }
                    // Await process termination after sending kill signal
                    let _ = child.wait().await;
                    return Err(EbiError::ExecutionFailed(format!(
                        "Script execution timed out after {} seconds",
                        timeout_secs
                    )));
                }
            }
        } else {
            child
                .wait()
                .await
                .map_err(|e| EbiError::ExecutionFailed(e.to_string()))?
        };

        Ok(exit_status.code().unwrap_or(1))
    }

    pub fn validate_decision(&self, decision: &ExecutionDecision) -> Result<(), EbiError> {
        if !decision.proceed {
            return Err(EbiError::ExecutionBlocked);
        }
        Ok(())
    }

    pub fn prepare_sandbox(&self) -> Result<(), EbiError> {
        // Future implementation: Set up sandbox environment
        // For now, just validate that we can execute
        if self.config.target_command.is_empty() {
            return Err(EbiError::InvalidArguments(
                "Target command is empty".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runner_creation() {
        let config = ExecutionConfig::new("bash".to_string(), vec![], "echo test".to_string());
        let runner = ScriptRunner::new(config);
        assert!(runner.timeout_seconds.is_none());

        let runner_with_timeout = runner.with_timeout(60);
        assert_eq!(runner_with_timeout.timeout_seconds, Some(60));
    }

    #[test]
    fn test_validate_decision() {
        let config = ExecutionConfig::new("bash".to_string(), vec![], "echo test".to_string());
        let runner = ScriptRunner::new(config);

        let proceed_decision = ExecutionDecision::proceed();
        assert!(runner.validate_decision(&proceed_decision).is_ok());

        let decline_decision = ExecutionDecision::decline();
        assert!(runner.validate_decision(&decline_decision).is_err());
    }

    #[test]
    fn test_prepare_sandbox() {
        let config = ExecutionConfig::new("bash".to_string(), vec![], "echo test".to_string());
        let runner = ScriptRunner::new(config);
        assert!(runner.prepare_sandbox().is_ok());

        let empty_config = ExecutionConfig::new("".to_string(), vec![], "echo test".to_string());
        let empty_runner = ScriptRunner::new(empty_config);
        assert!(empty_runner.prepare_sandbox().is_err());
    }
}
