use clap::Parser;
use crate::error::EbiError;

#[derive(Parser, Debug)]
#[command(name = "ebi")]
#[command(about = "Evaluate Before Invocation - Script analysis tool using LLMs")]
#[command(long_about = None)]
#[command(version)]
pub struct Cli {
    /// Override automatic language detection
    #[arg(short = 'l', long)]
    pub lang: Option<String>,

    /// LLM model to use for analysis
    #[arg(short = 'm', long, default_value = "gpt-5-mini")]
    pub model: String,

    /// Maximum time for LLM analysis in seconds (10-300)
    #[arg(short = 't', long, default_value = "60", value_parser = validate_timeout)]
    pub timeout: u64,

    /// Enable verbose output to stderr
    #[arg(short = 'v', long)]
    pub verbose: bool,

    /// Enable debug output including LLM communications
    #[arg(short = 'd', long)]
    pub debug: bool,

    /// Target command and its arguments
    #[arg(trailing_var_arg = true, required = true)]
    pub command_and_args: Vec<String>,
}

impl Cli {
    pub fn parse_args() -> Result<Self, EbiError> {
        let cli = Self::try_parse()
            .map_err(|e| EbiError::InvalidArguments(e.to_string()))?;

        // Additional validation
        cli.validate()?;

        Ok(cli)
    }

    pub fn validate(&self) -> Result<(), EbiError> {
        // Validate timeout range
        if !(10..=300).contains(&self.timeout) {
            return Err(EbiError::InvalidArguments(
                "Timeout must be between 10 and 300 seconds".to_string(),
            ));
        }

        // Ensure we have at least a command
        if self.command_and_args.is_empty() {
            return Err(EbiError::InvalidArguments(
                "Target command is required".to_string(),
            ));
        }

        // Validate language if provided
        if let Some(ref lang) = self.lang {
            crate::models::Language::from_str(lang)?;
        }

        Ok(())
    }

    pub fn get_target_command(&self) -> &str {
        &self.command_and_args[0]
    }

    pub fn get_target_args(&self) -> &[String] {
        if self.command_and_args.len() > 1 {
            &self.command_and_args[1..]
        } else {
            &[]
        }
    }

    pub fn get_llm_model(&self) -> &str {
        // Check environment variable override
        if let Ok(_model) = std::env::var("EBI_DEFAULT_MODEL") {
            // We can't return a borrowed string from env var, so for now return the CLI value
            // In a real implementation, we'd want to handle this differently
        }
        &self.model
    }

    pub fn get_timeout_seconds(&self) -> u64 {
        // Check environment variable override
        if let Ok(timeout_str) = std::env::var("EBI_DEFAULT_TIMEOUT") {
            if let Ok(timeout) = timeout_str.parse::<u64>() {
                if (10..=300).contains(&timeout) {
                    return timeout;
                }
            }
        }
        self.timeout
    }

    pub fn is_verbose(&self) -> bool {
        self.verbose || self.debug
    }

    pub fn is_debug(&self) -> bool {
        self.debug
    }

    pub fn should_use_color(&self) -> bool {
        // Disable color if NO_COLOR environment variable is set
        std::env::var("NO_COLOR").is_err()
    }
}

fn validate_timeout(s: &str) -> Result<u64, String> {
    let timeout: u64 = s.parse()
        .map_err(|_| "Timeout must be a number")?;

    if (10..=300).contains(&timeout) {
        Ok(timeout)
    } else {
        Err("Timeout must be between 10 and 300 seconds".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_cli_parsing() {
        let args = vec!["ebi", "bash"];
        let cli = Cli::try_parse_from(args).unwrap();

        assert_eq!(cli.command_and_args, vec!["bash"]);
        assert_eq!(cli.model, "gpt-5-mini");
        assert_eq!(cli.timeout, 60);
        assert!(cli.lang.is_none());
        assert!(!cli.verbose);
        assert!(!cli.debug);
    }

    #[test]
    fn test_cli_with_all_options() {
        let args = vec![
            "ebi",
            "--lang", "python",
            "--model", "gemini-1.5-flash",
            "--timeout", "120",
            "--verbose",
            "python",
            "-",
            "--some-arg"
        ];

        let cli = Cli::try_parse_from(args).unwrap();

        assert_eq!(cli.lang, Some("python".to_string()));
        assert_eq!(cli.model, "gemini-1.5-flash");
        assert_eq!(cli.timeout, 120);
        assert!(cli.verbose);
        assert!(!cli.debug);
        assert_eq!(cli.command_and_args, vec!["python", "-", "--some-arg"]);
    }

    #[test]
    fn test_cli_short_flags() {
        let args = vec!["ebi", "-l", "bash", "-m", "claude-sonnet-4", "-t", "30", "-v", "sh", "-c", "echo test"];

        let cli = Cli::try_parse_from(args).unwrap();

        assert_eq!(cli.lang, Some("bash".to_string()));
        assert_eq!(cli.model, "claude-sonnet-4");
        assert_eq!(cli.timeout, 30);
        assert!(cli.verbose);
        assert_eq!(cli.command_and_args, vec!["sh", "-c", "echo test"]);
    }

    #[test]
    fn test_debug_flag() {
        let args = vec!["ebi", "--debug", "bash"];
        let cli = Cli::try_parse_from(args).unwrap();

        assert!(cli.debug);
        assert!(cli.is_debug());
        assert!(cli.is_verbose()); // Debug implies verbose
    }

    #[test]
    fn test_timeout_validation() {
        // Test timeout below minimum
        let args = vec!["ebi", "--timeout", "5", "bash"];
        assert!(Cli::try_parse_from(args).is_err());

        // Test timeout above maximum
        let args = vec!["ebi", "--timeout", "400", "bash"];
        assert!(Cli::try_parse_from(args).is_err());

        // Test valid timeout
        let args = vec!["ebi", "--timeout", "120", "bash"];
        assert!(Cli::try_parse_from(args).is_ok());
    }

    #[test]
    fn test_no_command_error() {
        // Test that providing no command fails
        let args = vec!["ebi", "--verbose"];
        assert!(Cli::try_parse_from(args).is_err());
    }

    #[test]
    fn test_target_command_extraction() {
        let args = vec!["ebi", "python", "script.py", "--arg"];
        let cli = Cli::try_parse_from(args).unwrap();

        assert_eq!(cli.get_target_command(), "python");
        assert_eq!(cli.get_target_args(), &["script.py", "--arg"]);
    }

    #[test]
    fn test_validation() {
        let mut cli = Cli::try_parse_from(vec!["ebi", "bash"]).unwrap();

        // Valid CLI should pass validation
        assert!(cli.validate().is_ok());

        // Invalid language should fail
        cli.lang = Some("invalid-language".to_string());
        assert!(cli.validate().is_err());

        // Fix language, break timeout
        cli.lang = Some("python".to_string());
        cli.timeout = 5; // Too low
        assert!(cli.validate().is_err());
    }
}
