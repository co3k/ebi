pub mod analyzer;
pub mod cli;
pub mod error;
pub mod executor;
pub mod localization;
pub mod models;
pub mod parser;

pub use error::EbiError;

// Re-export commonly used types
pub use models::{
    AnalysisReport, AnalysisRequest, AnalysisResult, ExecutionDecision, Language, RiskLevel,
    Script, ScriptComponents, ScriptSource,
};

pub use executor::ExecutionConfig;

pub use cli::CliHandler;
