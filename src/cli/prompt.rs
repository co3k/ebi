use crate::models::{AnalysisReport, ExecutionDecision, RiskLevel};
use crate::error::EbiError;
use std::io::{self, Write};
use std::time::{Duration, Instant};

pub struct UserPrompter {
    timeout: Option<Duration>,
    use_colors: bool,
}

impl UserPrompter {
    pub fn new(timeout_seconds: Option<u64>, use_colors: bool) -> Self {
        Self {
            timeout: timeout_seconds.map(Duration::from_secs),
            use_colors,
        }
    }

    pub fn prompt_execution_decision(
        &self,
        report: &AnalysisReport,
    ) -> Result<ExecutionDecision, EbiError> {
        // If the report indicates execution should be blocked, don't prompt
        if report.should_block_execution() {
            return Ok(ExecutionDecision::decline());
        }

        // Display the prompt
        self.display_execution_prompt(report)?;

        // Get user input with timeout
        let response = self.get_user_input()?;

        // Parse the response
        self.parse_execution_response(&response)
    }

    fn display_execution_prompt(&self, report: &AnalysisReport) -> Result<(), EbiError> {
        let (color_start, color_end) = if self.use_colors {
            match report.overall_risk {
                RiskLevel::Critical | RiskLevel::High => ("\x1b[1m\x1b[33m", "\x1b[0m"), // Yellow
                RiskLevel::Medium => ("\x1b[1m\x1b[35m", "\x1b[0m"), // Magenta
                _ => ("\x1b[1m\x1b[36m", "\x1b[0m"), // Cyan
            }
        } else {
            ("", "")
        };

        // Display prompt based on risk level
        let prompt_message = match report.overall_risk {
            RiskLevel::Critical => {
                "🚨 CRITICAL RISK DETECTED - Execution automatically blocked for safety."
            }
            RiskLevel::High => {
                "⚠️  HIGH RISK DETECTED\n\
                 This script performs operations that could be dangerous.\n\
                 Please review the analysis carefully before proceeding."
            }
            RiskLevel::Medium => {
                "🔸 MEDIUM RISK DETECTED\n\
                 This script accesses system resources.\n\
                 Please review the analysis before proceeding."
            }
            RiskLevel::Low => {
                "✅ LOW RISK DETECTED\n\
                 This script appears relatively safe."
            }
            RiskLevel::Info => {
                "ℹ️  ANALYSIS COMPLETE\n\
                 No significant security concerns identified."
            }
        };

        print!("\n{}{}{}\n\n", color_start, prompt_message, color_end);

        // For critical risk, don't show the prompt since execution is blocked
        if matches!(report.overall_risk, RiskLevel::Critical) {
            return Err(EbiError::ExecutionBlocked);
        }

        // Show execution recommendation
        println!("{}", report.execution_recommendation);
        println!();

        // Show the actual prompt
        let prompt_text = self.get_prompt_text(&report.overall_risk);
        print!("{}", prompt_text);

        // Flush to ensure prompt is displayed
        io::stdout().flush()
            .map_err(|e| EbiError::UserInputTimeout)?;

        Ok(())
    }

    fn get_prompt_text(&self, risk_level: &RiskLevel) -> String {
        match risk_level {
            RiskLevel::High => {
                "⚠️  Do you want to proceed with execution despite the HIGH RISK? \n\
                 Type 'yes' to execute anyway, 'no' to cancel, or 'review' to see full details: "
            }
            RiskLevel::Medium => {
                "🔸 Do you want to proceed with execution? \n\
                 Type 'yes' to execute, 'no' to cancel, or 'review' to see full details: "
            }
            _ => {
                "Do you want to proceed with script execution? \n\
                 Type 'yes' to execute, 'no' to cancel: "
            }
        }.to_string()
    }

    fn get_user_input(&self) -> Result<String, EbiError> {
        if let Some(timeout_duration) = self.timeout {
            self.get_user_input_with_timeout(timeout_duration)
        } else {
            self.get_user_input_blocking()
        }
    }

    fn get_user_input_blocking(&self) -> Result<String, EbiError> {
        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(0) => {
                // EOF received (Ctrl+D)
                Ok("no".to_string())
            }
            Ok(_) => Ok(input.trim().to_lowercase()),
            Err(_) => Err(EbiError::UserInputTimeout),
        }
    }

    fn get_user_input_with_timeout(&self, timeout: Duration) -> Result<String, EbiError> {
        use std::sync::mpsc;
        use std::thread;

        let (sender, receiver) = mpsc::channel();
        let start_time = Instant::now();

        // Spawn a thread to read from stdin
        thread::spawn(move || {
            let mut input = String::new();
            match io::stdin().read_line(&mut input) {
                Ok(0) => {
                    // EOF
                    let _ = sender.send("no".to_string());
                }
                Ok(_) => {
                    let _ = sender.send(input.trim().to_lowercase());
                }
                Err(_) => {
                    let _ = sender.send("error".to_string());
                }
            }
        });

        // Wait for input or timeout
        loop {
            match receiver.try_recv() {
                Ok(input) => {
                    if input == "error" {
                        return Err(EbiError::UserInputTimeout);
                    }
                    return Ok(input);
                }
                Err(mpsc::TryRecvError::Empty) => {
                    if start_time.elapsed() >= timeout {
                        println!("\n⏰ Input timeout reached. Defaulting to 'no' for safety.");
                        return Ok("no".to_string());
                    }
                    thread::sleep(Duration::from_millis(100));
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Err(EbiError::UserInputTimeout);
                }
            }
        }
    }

    fn parse_execution_response(&self, response: &str) -> Result<ExecutionDecision, EbiError> {
        match response {
            "yes" | "y" | "execute" | "proceed" => {
                Ok(ExecutionDecision::proceed())
            }
            "no" | "n" | "cancel" | "abort" | "stop" => {
                Ok(ExecutionDecision::decline())
            }
            "review" | "details" | "show" | "more" => {
                // For now, treat review as decline - in a full implementation,
                // this would show detailed analysis and prompt again
                println!("💡 Review functionality not yet implemented. Defaulting to decline for safety.");
                Ok(ExecutionDecision::decline())
            }
            "" => {
                // Empty response - default to no for safety
                Ok(ExecutionDecision::decline())
            }
            _ => {
                // Invalid response - ask again (with a retry limit)
                println!("❓ Please enter 'yes' to execute, 'no' to cancel, or 'review' for details.");
                print!("Your choice: ");
                io::stdout().flush().unwrap_or(());

                let retry_response = self.get_user_input()?;
                self.parse_execution_response(&retry_response)
            }
        }
    }

    pub fn prompt_confirmation(&self, message: &str) -> Result<bool, EbiError> {
        print!("{} (y/n): ", message);
        io::stdout().flush()
            .map_err(|_| EbiError::UserInputTimeout)?;

        let response = self.get_user_input()?;
        Ok(matches!(response.as_str(), "yes" | "y"))
    }

    pub fn display_message(&self, message: &str) {
        println!("{}", message);
    }

    pub fn display_progress(&self, message: &str) {
        if self.use_colors {
            print!("\x1b[36m{}\x1b[0m", message);
        } else {
            print!("{}", message);
        }
        io::stdout().flush().unwrap_or(());
    }

    pub fn display_error(&self, error: &EbiError) {
        let (color_start, color_end) = if self.use_colors {
            ("\x1b[1m\x1b[31m", "\x1b[0m")
        } else {
            ("", "")
        };

        eprintln!("{}🚨 Error: {}{}", color_start, error, color_end);
    }

    pub fn clear_line(&self) {
        if self.use_colors {
            print!("\r\x1b[K");
            io::stdout().flush().unwrap_or(());
        }
    }
}

// Convenience functions for common prompting scenarios
impl UserPrompter {
    pub fn for_cli(cli: &crate::cli::args::Cli) -> Self {
        let timeout = if cli.is_debug() {
            None // No timeout in debug mode for easier testing
        } else {
            Some(300) // 5 minute default timeout
        };

        Self::new(timeout, cli.should_use_color())
    }

    pub fn for_testing() -> Self {
        Self::new(Some(1), false) // Very short timeout, no colors for tests
    }

    pub fn without_timeout() -> Self {
        Self::new(None, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ScriptInfo, Language};

    #[test]
    fn test_response_parsing() {
        let prompter = UserPrompter::for_testing();

        // Test yes responses
        assert!(prompter.parse_execution_response("yes").unwrap().proceed);
        assert!(prompter.parse_execution_response("y").unwrap().proceed);
        assert!(prompter.parse_execution_response("execute").unwrap().proceed);

        // Test no responses
        assert!(!prompter.parse_execution_response("no").unwrap().proceed);
        assert!(!prompter.parse_execution_response("n").unwrap().proceed);
        assert!(!prompter.parse_execution_response("cancel").unwrap().proceed);

        // Test empty response (should default to no)
        assert!(!prompter.parse_execution_response("").unwrap().proceed);

        // Test review response (should default to no for now)
        assert!(!prompter.parse_execution_response("review").unwrap().proceed);
    }

    #[test]
    fn test_prompt_text_generation() {
        let prompter = UserPrompter::for_testing();

        let high_risk_prompt = prompter.get_prompt_text(&RiskLevel::High);
        assert!(high_risk_prompt.contains("HIGH RISK"));

        let medium_risk_prompt = prompter.get_prompt_text(&RiskLevel::Medium);
        assert!(medium_risk_prompt.contains("proceed with execution"));

        let low_risk_prompt = prompter.get_prompt_text(&RiskLevel::Low);
        assert!(low_risk_prompt.contains("yes"));
    }

    #[test]
    fn test_critical_risk_handling() {
        let prompter = UserPrompter::for_testing();

        let script_info = ScriptInfo::new(Language::Bash, 100, 5);
        let mut report = AnalysisReport::new(script_info);
        report.overall_risk = RiskLevel::Critical;

        // Critical risk should result in execution blocked error
        let result = prompter.prompt_execution_decision(&report);
        assert!(matches!(result, Err(EbiError::ExecutionBlocked)));
    }

    #[test]
    fn test_prompter_creation() {
        let cli = crate::cli::args::Cli::try_parse_from(vec!["ebi", "--debug", "bash"]).unwrap();
        let prompter = UserPrompter::for_cli(&cli);

        // Debug mode should have no timeout
        assert!(prompter.timeout.is_none());
    }
}