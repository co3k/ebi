pub mod error;
pub mod models;
pub mod cli;
pub mod parser;
pub mod analyzer;
pub mod executor;
pub mod localization;

pub use error::EbiError;

// Re-export commonly used types
pub use models::{
    Script, Language, ScriptSource, ScriptComponents, AnalysisRequest,
    AnalysisResult, AnalysisReport, RiskLevel, ExecutionDecision
};

pub use executor::ExecutionConfig;

pub use cli::CliHandler;