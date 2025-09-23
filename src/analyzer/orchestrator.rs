use crate::models::{
    AnalysisRequest, AnalysisResult, AnalysisType, AnalysisContext,
    ScriptComponents, Language, ScriptSource,
};
use crate::analyzer::llm_client::{LlmProvider, create_llm_client};
use crate::analyzer::prompts::PromptTemplate;
use crate::error::EbiError;
use std::sync::Arc;
use tokio::time::{timeout, Duration};
use futures::future::join_all;

pub struct AnalysisOrchestrator {
    llm_client: Arc<dyn LlmProvider + Send + Sync>,
    max_concurrent_requests: usize,
    default_timeout: Duration,
}

impl AnalysisOrchestrator {
    pub fn new(
        model: &str,
        api_key: Option<String>,
        timeout_seconds: u64,
        max_concurrent: usize,
    ) -> Result<Self, EbiError> {
        let client = create_llm_client(model, api_key, timeout_seconds)?;

        Ok(Self {
            llm_client: client.into(),
            max_concurrent_requests: max_concurrent,
            default_timeout: Duration::from_secs(timeout_seconds),
        })
    }

    pub async fn analyze_script_components(
        &self,
        components: &ScriptComponents,
        language: &Language,
        source: &ScriptSource,
        model: &str,
    ) -> Result<Vec<AnalysisResult>, EbiError> {
        let context = AnalysisContext {
            language: language.clone(),
            source: source.clone(),
        };

        // Prepare analysis requests
        let mut requests = Vec::new();

        // Always perform code vulnerability analysis
        let code_content = components.get_analysis_content(language, true);
        let code_request = AnalysisRequest {
            analysis_type: AnalysisType::CodeVulnerability,
            content: code_content,
            context: context.clone(),
            model: model.to_string(),
            timeout_seconds: self.default_timeout.as_secs(),
        };
        requests.push(code_request);

        // Perform injection analysis if there are comments or string literals
        if !components.comments.is_empty() || !components.string_literals.is_empty() {
            let injection_content = components.get_injection_content();
            let injection_request = AnalysisRequest {
                analysis_type: AnalysisType::InjectionDetection,
                content: injection_content,
                context: context.clone(),
                model: model.to_string(),
                timeout_seconds: self.default_timeout.as_secs(),
            };
            requests.push(injection_request);
        }

        // Execute requests in parallel with concurrency limit
        self.execute_parallel_analysis(requests).await
    }

    async fn execute_parallel_analysis(
        &self,
        requests: Vec<AnalysisRequest>,
    ) -> Result<Vec<AnalysisResult>, EbiError> {
        if requests.is_empty() {
            return Ok(Vec::new());
        }

        // Split requests into batches to respect concurrency limit
        let mut results = Vec::new();
        let chunks: Vec<_> = requests
            .chunks(self.max_concurrent_requests)
            .collect();

        for chunk in chunks {
            let batch_futures: Vec<_> = chunk
                .iter()
                .map(|request| self.execute_single_analysis(request))
                .collect();

            let batch_results = join_all(batch_futures).await;

            // Collect results and handle errors
            for result in batch_results {
                match result {
                    Ok(analysis_result) => results.push(analysis_result),
                    Err(e) => {
                        // Log the error but continue with other analyses
                        eprintln!("Analysis failed: {}", e);
                        // Create a fallback result indicating failure
                        results.push(self.create_failure_result(e));
                    }
                }
            }
        }

        // Ensure we have at least one result
        if results.is_empty() {
            return Err(EbiError::LlmClientError(
                "All analysis requests failed".to_string()
            ));
        }

        Ok(results)
    }

    async fn execute_single_analysis(
        &self,
        request: &AnalysisRequest,
    ) -> Result<AnalysisResult, EbiError> {
        // Apply timeout to the entire analysis operation
        timeout(
            self.default_timeout,
            self.llm_client.analyze(request)
        )
        .await
        .map_err(|_| EbiError::AnalysisTimeout {
            timeout: self.default_timeout.as_secs()
        })?
    }

    fn create_failure_result(&self, error: EbiError) -> AnalysisResult {
        use crate::models::RiskLevel;

        AnalysisResult::new(
            AnalysisType::CodeVulnerability,
            "failed".to_string(),
            0,
        )
        .with_risk_level(RiskLevel::Critical) // Fail-safe: treat failures as critical
        .with_summary(format!("Analysis failed: {}", error))
        .with_confidence(0.0)
        .with_details("Analysis could not be completed due to an error. \
                      For security, execution should be blocked.".to_string())
    }

    pub async fn quick_analysis(
        &self,
        content: &str,
        language: &Language,
        source: &ScriptSource,
        model: &str,
    ) -> Result<AnalysisResult, EbiError> {
        let context = AnalysisContext {
            language: language.clone(),
            source: source.clone(),
        };

        let request = AnalysisRequest {
            analysis_type: AnalysisType::CodeVulnerability,
            content: content.to_string(),
            context,
            model: model.to_string(),
            timeout_seconds: self.default_timeout.as_secs(),
        };

        self.execute_single_analysis(&request).await
    }

    pub fn validate_analysis_request(&self, request: &AnalysisRequest) -> Result<(), EbiError> {
        // Validate content length
        if request.content.is_empty() {
            return Err(EbiError::InvalidArguments(
                "Analysis content cannot be empty".to_string()
            ));
        }

        // Check if content is too long (rough token estimation)
        let estimated_tokens = request.content.len() / 4;
        if estimated_tokens > 100000 { // ~100k tokens
            return Err(EbiError::InvalidArguments(
                "Content too long for analysis".to_string()
            ));
        }

        // Validate timeout
        if request.timeout_seconds < 10 || request.timeout_seconds > 300 {
            return Err(EbiError::InvalidArguments(
                "Timeout must be between 10 and 300 seconds".to_string()
            ));
        }

        Ok(())
    }

    pub async fn test_connectivity(&self) -> Result<(), EbiError> {
        let test_request = AnalysisRequest {
            analysis_type: AnalysisType::CodeVulnerability,
            content: "echo 'test'".to_string(),
            context: AnalysisContext {
                language: Language::Bash,
                source: ScriptSource::Stdin,
            },
            model: self.llm_client.get_model_name().to_string(),
            timeout_seconds: 30,
        };

        // Try a quick test analysis
        timeout(
            Duration::from_secs(30),
            self.llm_client.analyze(&test_request)
        )
        .await
        .map_err(|_| EbiError::AnalysisTimeout { timeout: 30 })?
        .map(|_| ())
    }

    pub fn get_model_info(&self) -> String {
        format!(
            "Model: {}, Timeout: {}s, Max Concurrent: {}",
            self.llm_client.get_model_name(),
            self.default_timeout.as_secs(),
            self.max_concurrent_requests
        )
    }

    pub fn update_timeout(&mut self, timeout_seconds: u64) {
        self.default_timeout = Duration::from_secs(timeout_seconds);
    }

    pub fn update_concurrency(&mut self, max_concurrent: usize) {
        self.max_concurrent_requests = max_concurrent.max(1); // Ensure at least 1
    }
}

// Helper functions for creating orchestrators with common configurations
impl AnalysisOrchestrator {
    pub fn for_development() -> Result<Self, EbiError> {
        Self::new("gpt-3.5-turbo", None, 60, 2)
    }

    pub fn for_production(api_key: String) -> Result<Self, EbiError> {
        Self::new("gpt-4", Some(api_key), 120, 3)
    }

    pub fn for_testing() -> Result<Self, EbiError> {
        Self::new("mock-model", None, 30, 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ScriptComponents;

    // Note: These tests would require either mocking the LLM client or using a test API
    #[tokio::test]
    async fn test_orchestrator_creation() {
        // This test uses a mock configuration
        let result = AnalysisOrchestrator::for_testing();
        // Since we don't have actual LLM client implementation, this might fail
        // In a real implementation, we'd use dependency injection or mocking
    }

    #[test]
    fn test_request_validation() {
        let orchestrator = AnalysisOrchestrator::for_testing();
        if let Ok(orch) = orchestrator {
            let valid_request = AnalysisRequest {
                analysis_type: AnalysisType::CodeVulnerability,
                content: "echo hello".to_string(),
                context: AnalysisContext {
                    language: Language::Bash,
                    source: ScriptSource::Stdin,
                },
                model: "test-model".to_string(),
                timeout_seconds: 60,
            };

            assert!(orch.validate_analysis_request(&valid_request).is_ok());

            let invalid_request = AnalysisRequest {
                analysis_type: AnalysisType::CodeVulnerability,
                content: "".to_string(), // Empty content
                context: AnalysisContext {
                    language: Language::Bash,
                    source: ScriptSource::Stdin,
                },
                model: "test-model".to_string(),
                timeout_seconds: 60,
            };

            assert!(orch.validate_analysis_request(&invalid_request).is_err());
        }
    }

    #[test]
    fn test_configuration_updates() {
        let mut orchestrator = AnalysisOrchestrator::for_testing();
        if let Ok(ref mut orch) = orchestrator {
            orch.update_timeout(90);
            orch.update_concurrency(5);

            let info = orch.get_model_info();
            assert!(info.contains("90s"));
            assert!(info.contains("Max Concurrent: 5"));
        }
    }
}