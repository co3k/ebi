pub mod error;
pub mod models;
pub mod cli;
pub mod parser;
pub mod analyzer;
pub mod executor;

pub use error::EbiError;

// Re-export commonly used types
pub use models::{
    Script, Language, ScriptSource, ScriptComponents, AnalysisRequest,
    AnalysisResult, AnalysisReport, RiskLevel
};

pub use cli::CliHandler;