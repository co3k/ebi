pub mod analysis;
pub mod components;
pub mod report;
pub mod script;

pub use analysis::{
    AnalysisContext, AnalysisRequest, AnalysisResult, AnalysisType, Finding, RiskLevel,
};
pub use components::{NodeInfo, ParseMetadata, ScriptComponents, SecurityRelevance};
pub use report::{AnalysisReport, ExecutionDecision, ExecutionRecommendation, ScriptInfo};
pub use script::{Language, OutputLanguage, Script, ScriptSource};
