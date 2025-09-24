use crate::error::EbiError;
use crate::localization::locale::LocalizedMessages;
use crate::models::{AnalysisReport, ExecutionDecision, OutputLanguage, RiskLevel};
use std::io::{self, Write};
use std::time::{Duration, Instant};

pub struct UserPrompter {
    timeout: Option<Duration>,
    use_colors: bool,
    output_language: OutputLanguage,
}

impl UserPrompter {
    pub fn new(
        timeout_seconds: Option<u64>,
        use_colors: bool,
        output_language: OutputLanguage,
    ) -> Self {
        Self {
            timeout: timeout_seconds.map(Duration::from_secs),
            use_colors,
            output_language,
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
                RiskLevel::Medium => ("\x1b[1m\x1b[35m", "\x1b[0m"),                     // Magenta
                _ => ("\x1b[1m\x1b[36m", "\x1b[0m"),                                     // Cyan
            }
        } else {
            ("", "")
        };

        // Display prompt based on risk level
        let prompt_message =
            LocalizedMessages::get_prompt_message(&report.overall_risk, &self.output_language);

        print!("\n{}{}{}\n\n", color_start, prompt_message, color_end);

        // Show execution recommendation
        let recommendation_text = report
            .execution_advice
            .as_deref()
            .unwrap_or_else(|| report.execution_recommendation.description());

        println!("{}", recommendation_text);
        println!();

        // For critical risk, show strong warning but still allow user choice
        if matches!(report.overall_risk, RiskLevel::Critical) {
            let critical_warning = LocalizedMessages::get_critical_warning(&self.output_language);
            println!("{}", critical_warning);
            println!();
        }

        // Show the actual prompt
        let prompt_text =
            LocalizedMessages::get_prompt_text(&report.overall_risk, &self.output_language);
        print!("{}", prompt_text);

        // Flush to ensure prompt is displayed
        io::stdout()
            .flush()
            .map_err(|_| EbiError::UserInputTimeout)?;

        Ok(())
    }

    fn get_user_input(&self) -> Result<String, EbiError> {
        if let Some(timeout_duration) = self.timeout {
            self.get_user_input_with_timeout(timeout_duration)
        } else {
            self.get_user_input_blocking()
        }
    }

    fn get_user_input_blocking(&self) -> Result<String, EbiError> {
        use std::fs::File;
        use std::io::Read;

        // Try to open /dev/tty for reading when stdin is piped
        let mut input = String::new();

        // Check if stdin is a terminal
        let is_stdin_terminal = atty::is(atty::Stream::Stdin);

        if !is_stdin_terminal {
            // stdin is piped, try to read from /dev/tty
            match File::open("/dev/tty") {
                Ok(mut tty) => {
                    let mut buf = [0u8; 256];
                    match tty.read(&mut buf) {
                        Ok(0) => Ok("no".to_string()),
                        Ok(n) => {
                            let response = String::from_utf8_lossy(&buf[..n]);
                            Ok(response.trim().to_lowercase())
                        }
                        Err(_) => Err(EbiError::UserInputTimeout),
                    }
                }
                Err(_) => {
                    // Cannot open /dev/tty, default to decline
                    eprintln!("⚠️  Cannot read user input (stdin is piped). Defaulting to decline for safety.");
                    Ok("no".to_string())
                }
            }
        } else {
            // stdin is a terminal, use normal stdin
            match io::stdin().read_line(&mut input) {
                Ok(0) => {
                    // EOF received (Ctrl+D)
                    Ok("no".to_string())
                }
                Ok(_) => Ok(input.trim().to_lowercase()),
                Err(_) => Err(EbiError::UserInputTimeout),
            }
        }
    }

    fn get_user_input_with_timeout(&self, timeout: Duration) -> Result<String, EbiError> {
        use std::fs::File;
        use std::io::Read;
        use std::sync::mpsc;
        use std::thread;

        let (sender, receiver) = mpsc::channel();
        let start_time = Instant::now();

        // Check if stdin is a terminal
        let is_stdin_terminal = atty::is(atty::Stream::Stdin);

        // Spawn a thread to read from stdin or /dev/tty
        thread::spawn(move || {
            if !is_stdin_terminal {
                // stdin is piped, try to read from /dev/tty
                match File::open("/dev/tty") {
                    Ok(mut tty) => {
                        let mut buf = [0u8; 256];
                        match tty.read(&mut buf) {
                            Ok(0) => {
                                let _ = sender.send("no".to_string());
                            }
                            Ok(n) => {
                                let response = String::from_utf8_lossy(&buf[..n]);
                                let _ = sender.send(response.trim().to_lowercase());
                            }
                            Err(_) => {
                                let _ = sender.send("error".to_string());
                            }
                        }
                    }
                    Err(_) => {
                        // Cannot open /dev/tty
                        let _ = sender.send("no".to_string());
                    }
                }
            } else {
                // stdin is a terminal, use normal stdin
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
                        println!("\n⏰ Input timeout reached. Defaulting to decline for safety.");
                        return Err(EbiError::UserInputTimeout);
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
            "yes" | "y" | "execute" | "proceed" => Ok(ExecutionDecision::proceed()),
            "no" | "n" | "cancel" | "abort" | "stop" => Ok(ExecutionDecision::decline()),
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
                println!(
                    "❓ Please enter 'yes' to execute, 'no' to cancel, or 'review' for details."
                );
                print!("Your choice: ");
                io::stdout().flush().unwrap_or(());

                let retry_response = self.get_user_input()?;
                self.parse_execution_response(&retry_response)
            }
        }
    }

    pub fn prompt_confirmation(&self, message: &str) -> Result<bool, EbiError> {
        print!("{} (y/n): ", message);
        io::stdout()
            .flush()
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

    pub fn display_step(&self, step_num: usize, total_steps: usize, message: &str) {
        let (color_start, color_end) = if self.use_colors {
            ("\x1b[1m\x1b[34m", "\x1b[0m")
        } else {
            ("", "")
        };

        eprintln!(
            "{}[{}/{}]{} {}",
            color_start, step_num, total_steps, color_end, message
        );
    }

    pub fn display_spinner_start(&self, message: &str) {
        if self.use_colors {
            eprint!("\x1b[33m⏳ {}\x1b[0m", message);
        } else {
            eprint!("⏳ {}", message);
        }
        io::stderr().flush().unwrap_or(());
    }

    pub fn display_spinner_end(&self, success: bool) {
        if success {
            if self.use_colors {
                eprintln!(" \x1b[32m✓\x1b[0m");
            } else {
                eprintln!(" ✓");
            }
        } else {
            if self.use_colors {
                eprintln!(" \x1b[31m✗\x1b[0m");
            } else {
                eprintln!(" ✗");
            }
        }
    }
}

// Convenience functions for common prompting scenarios
impl UserPrompter {
    pub fn for_cli(cli: &crate::cli::args::Cli) -> Result<Self, EbiError> {
        let output_language = cli.get_output_language()?;

        if cli.is_debug() {
            return Ok(Self::new(None, cli.should_use_color(), output_language));
        }

        let env_timeout = std::env::var("EBI_PROMPT_TIMEOUT")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .map(|value| value.clamp(10, 900));

        let prompt_timeout = env_timeout.unwrap_or_else(|| cli.get_timeout_seconds().min(300));

        Ok(Self::new(
            Some(prompt_timeout),
            cli.should_use_color(),
            output_language,
        ))
    }

    pub fn for_testing() -> Self {
        Self::new(Some(1), false, OutputLanguage::English) // Very short timeout, no colors for tests
    }

    pub fn without_timeout() -> Self {
        Self::new(None, true, OutputLanguage::English)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Language, ScriptInfo};
    use clap::Parser;

    #[test]
    fn test_response_parsing() {
        let prompter = UserPrompter::for_testing();

        // Test yes responses
        assert!(prompter.parse_execution_response("yes").unwrap().proceed);
        assert!(prompter.parse_execution_response("y").unwrap().proceed);
        assert!(
            prompter
                .parse_execution_response("execute")
                .unwrap()
                .proceed
        );

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
        let high_risk_prompt =
            LocalizedMessages::get_prompt_text(&RiskLevel::High, &OutputLanguage::English);
        assert!(high_risk_prompt.contains("HIGH RISK"));

        let medium_risk_prompt =
            LocalizedMessages::get_prompt_text(&RiskLevel::Medium, &OutputLanguage::English);
        assert!(medium_risk_prompt.contains("proceed with execution"));

        let low_risk_prompt =
            LocalizedMessages::get_prompt_text(&RiskLevel::Low, &OutputLanguage::English);
        assert!(low_risk_prompt.contains("yes"));
    }

    #[test]
    fn test_critical_risk_handling() {
        let prompter = UserPrompter::for_testing();

        let script_info = ScriptInfo::new(Language::Bash, 100, 5);
        let mut report = AnalysisReport::new(script_info);
        report.overall_risk = RiskLevel::Critical;

        // Critical risk should now prompt the user (but will timeout in test with 'no' default)
        let result = prompter.prompt_execution_decision(&report);
        assert!(matches!(result, Err(EbiError::UserInputTimeout)));
    }

    #[test]
    fn test_prompter_creation() {
        let cli = crate::cli::args::Cli::try_parse_from(vec!["ebi", "--debug", "bash"]).unwrap();
        let prompter = UserPrompter::for_cli(&cli).unwrap();

        // Debug mode should have no timeout
        assert!(prompter.timeout.is_none());
    }
}
