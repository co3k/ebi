pub mod script;
pub mod components;
pub mod analysis;
pub mod report;

pub use script::{Script, Language, ScriptSource, OutputLanguage};
pub use components::{ScriptComponents, ParseMetadata, NodeInfo, SecurityRelevance};
pub use analysis::{AnalysisRequest, AnalysisResult, AnalysisType, AnalysisContext, RiskLevel, Finding};
pub use report::{AnalysisReport, ScriptInfo, ExecutionRecommendation, ExecutionDecision};