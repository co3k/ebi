use thiserror::Error;

#[derive(Error, Debug)]
pub enum EbiError {
    #[error("Parse error: Cannot determine script language")]
    UnknownLanguage,

    #[error("Parse error: Failed to parse script: {0}")]
    ParseError(String),

    #[error("No input provided - empty stdin")]
    NoInput,

    #[error("LLM analysis failed: {0}")]
    AnalysisUnavailable(String),

    #[error("LLM analysis timeout after {timeout} seconds")]
    AnalysisTimeout { timeout: u64 },

    #[error("Invalid LLM response: {0}")]
    InvalidResponse(String),

    #[error("Script too large for analysis - token limit exceeded")]
    TokenLimitExceeded,

    #[error("Script execution blocked due to critical security risk")]
    ExecutionBlocked,

    #[error("Target command not found: {command}")]
    CommandNotFound { command: String },

    #[error("Target command execution failed: {0}")]
    ExecutionFailed(String),

    #[error("LLM client error: {0}")]
    LlmClientError(String),

    #[error("Invalid command line arguments: {0}")]
    InvalidArguments(String),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Network error: {0}")]
    NetworkError(#[from] reqwest::Error),

    #[error("JSON serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Timeout waiting for user input")]
    UserInputTimeout,

    #[error("Configuration error: {0}")]
    ConfigError(String),
}
