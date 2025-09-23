// Analyzer module - handles LLM integration and analysis orchestration

pub mod llm_client;
pub mod prompts;
pub mod orchestrator;
pub mod aggregator;

pub use llm_client::{LlmProvider, LlmConfig, OpenAiCompatibleClient, create_llm_client};
pub use prompts::PromptTemplate;
pub use orchestrator::AnalysisOrchestrator;
pub use aggregator::AnalysisAggregator;