// Analyzer module - handles LLM integration and analysis orchestration

pub mod aggregator;
pub mod llm_client;
pub mod orchestrator;
pub mod prompts;

pub use aggregator::AnalysisAggregator;
pub use llm_client::{create_llm_client, LlmConfig, LlmProvider};
pub use orchestrator::AnalysisOrchestrator;
pub use prompts::PromptTemplate;
