use clap::Parser;
use crate::error::EbiError;
use crate::models::OutputLanguage;
use crate::localization::LocaleDetector;

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

    /// Output language for analysis reports (english, japanese)
    /// If not specified, automatically detects from system locale
    #[arg(long, default_value = "english")]
    pub output_lang: String,

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

        // Validate output language
        self.get_output_language()?;

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

    pub fn get_output_language(&self) -> Result<OutputLanguage, EbiError> {
        // Priority 1: Environment variable override
        if let Ok(env_lang) = std::env::var("EBI_OUTPUT_LANGUAGE") {
            return OutputLanguage::from_str(&env_lang);
        }
        
        // Priority 2: CLI option (if not default)
        if self.output_lang != "english" {
            return OutputLanguage::from_str(&self.output_lang);
        }
        
        // Priority 3: System locale detection
        let detected_locale = LocaleDetector::detect_system_locale();
        
        // Priority 4: Fall back to CLI default (english)
        Ok(detected_locale)
    }

    /// Get debug information about language detection
    pub fn get_language_debug_info(&self) -> String {
        let mut info = Vec::new();
        
        // Show environment variable status
        match std::env::var("EBI_OUTPUT_LANGUAGE") {
            Ok(value) => info.push(format!("EBI_OUTPUT_LANGUAGE={}", value)),
            Err(_) => info.push("EBI_OUTPUT_LANGUAGE=(not set)".to_string()),
        }
        
        // Show CLI option
        info.push(format!("CLI --output-lang={}", self.output_lang));
        
        // Show system locale info
        info.push(format!("System locale: {}", LocaleDetector::get_system_locale_info()));
        
        // Show detected language
        match self.get_output_language() {
            Ok(lang) => info.push(format!("Detected language: {}", lang.as_str())),
            Err(e) => info.push(format!("Language detection error: {}", e)),
        }
        
        info.join("\n")
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
        assert_eq!(cli.output_lang, "english");
    }

    #[test]
    fn test_cli_with_all_options() {
        let args = vec![
            "ebi",
            "--lang", "python",
            "--model", "gemini-2.5-flash",
            "--timeout", "120",
            "--verbose",
            "python",
            "-",
            "--some-arg"
        ];

        let cli = Cli::try_parse_from(args).unwrap();

        assert_eq!(cli.lang, Some("python".to_string()));
        assert_eq!(cli.model, "gemini-2.5-flash");
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

    #[test]
    fn test_output_language_parsing() {
        let args = vec!["ebi", "--output-lang", "japanese", "bash"];
        let cli = Cli::try_parse_from(args).unwrap();
        
        assert_eq!(cli.output_lang, "japanese");
        assert!(cli.get_output_language().is_ok());
        assert_eq!(cli.get_output_language().unwrap(), OutputLanguage::Japanese);
    }

    #[test]
    fn test_output_language_validation() {
        let args = vec!["ebi", "--output-lang", "invalid", "bash"];
        let cli = Cli::try_parse_from(args).unwrap();
        
        assert!(cli.get_output_language().is_err());
    }

    #[test]
    fn test_environment_variable_override() {
        // Test that environment variable overrides CLI option
        std::env::set_var("EBI_OUTPUT_LANGUAGE", "japanese");
        
        let args = vec!["ebi", "--output-lang", "english", "bash"];
        let cli = Cli::try_parse_from(args).unwrap();
        
        assert_eq!(cli.get_output_language().unwrap(), OutputLanguage::Japanese);
        
        // Clean up
        std::env::remove_var("EBI_OUTPUT_LANGUAGE");
    }

    #[test]
    fn test_environment_variable_invalid() {
        std::env::set_var("EBI_OUTPUT_LANGUAGE", "invalid");
        
        let args = vec!["ebi", "bash"];
        let cli = Cli::try_parse_from(args).unwrap();
        
        assert!(cli.get_output_language().is_err());
        
        // Clean up
        std::env::remove_var("EBI_OUTPUT_LANGUAGE");
    }

    #[test]
    fn test_locale_detection_priority() {
        // Test that locale detection works when no explicit language is set
        std::env::set_var("LANG", "ja_JP.UTF-8");
        
        let args = vec!["ebi", "bash"]; // No --output-lang specified
        let cli = Cli::try_parse_from(args).unwrap();
        
        assert_eq!(cli.get_output_language().unwrap(), OutputLanguage::Japanese);
        
        // Clean up
        std::env::remove_var("LANG");
    }

    #[test]
    fn test_locale_detection_with_explicit_option() {
        // Test that explicit CLI option overrides locale detection
        std::env::set_var("LANG", "ja_JP.UTF-8");
        
        let args = vec!["ebi", "--output-lang", "english", "bash"];
        let cli = Cli::try_parse_from(args).unwrap();
        
        assert_eq!(cli.get_output_language().unwrap(), OutputLanguage::English);
        
        // Clean up
        std::env::remove_var("LANG");
    }

    #[test]
    fn test_language_debug_info() {
        let args = vec!["ebi", "bash"];
        let cli = Cli::try_parse_from(args).unwrap();
        
        let debug_info = cli.get_language_debug_info();
        assert!(debug_info.contains("EBI_OUTPUT_LANGUAGE="));
        assert!(debug_info.contains("CLI --output-lang="));
        assert!(debug_info.contains("System locale:"));
        assert!(debug_info.contains("Detected language:"));
    }
}
