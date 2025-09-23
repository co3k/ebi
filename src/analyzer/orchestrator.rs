use crate::models::{
    AnalysisRequest, AnalysisResult, AnalysisType, AnalysisContext,
    ScriptComponents, Language, ScriptSource, OutputLanguage,
};
use crate::analyzer::llm_client::{LlmProvider, create_llm_client};
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
        output_language: &OutputLanguage,
    ) -> Result<Vec<AnalysisResult>, EbiError> {
        let context = AnalysisContext {
            language: language.clone(),
            source: source.clone(),
            script_type: None,
            truncated: false,
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
            output_language: output_language.clone(),
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
                output_language: output_language.clone(),
            };
            requests.push(injection_request);
        }

        // Execute initial requests in parallel with concurrency limit
        let initial_results = self.execute_parallel_analysis(requests).await?;

        // Check if we need detailed analysis for high-risk findings
        let needs_detailed_analysis = self.should_perform_detailed_analysis(&initial_results, components);

        if needs_detailed_analysis {
            let detailed_results = self.perform_detailed_analysis(
                &initial_results,
                components,
                language,
                source,
                model,
                output_language
            ).await?;

            // Combine initial and detailed results
            let mut combined_results = initial_results;
            combined_results.extend(detailed_results);
            Ok(combined_results)
        } else {
            Ok(initial_results)
        }
    }

    fn should_perform_detailed_analysis(
        &self,
        results: &[AnalysisResult],
        components: &ScriptComponents,
    ) -> bool {
        // Perform detailed analysis if:
        // 1. Any result shows HIGH or CRITICAL risk
        // 2. There are multiple medium-risk findings
        // 3. There are many critical or high-risk nodes in static analysis

        let has_high_risk = results.iter().any(|r|
            matches!(r.risk_level, crate::models::RiskLevel::High | crate::models::RiskLevel::Critical)
        );

        let medium_risk_count = results.iter()
            .filter(|r| matches!(r.risk_level, crate::models::RiskLevel::Medium))
            .count();

        let critical_nodes = components.get_critical_nodes().len();
        let high_risk_nodes = components.get_high_risk_nodes().len();

        has_high_risk ||
        medium_risk_count >= 2 ||
        critical_nodes >= 3 ||
        high_risk_nodes >= 5
    }

    async fn perform_detailed_analysis(
        &self,
        initial_results: &[AnalysisResult],
        components: &ScriptComponents,
        language: &Language,
        source: &ScriptSource,
        model: &str,
        output_language: &OutputLanguage,
    ) -> Result<Vec<AnalysisResult>, EbiError> {
        let context = AnalysisContext {
            language: language.clone(),
            source: source.clone(),
            script_type: None,
            truncated: false,
        };

        let mut detailed_requests = Vec::new();

        // Extract initial findings for context
        let _initial_findings: Vec<String> = initial_results.iter()
            .map(|r| format!("{:?}: {}", r.analysis_type, r.summary))
            .collect();

        // Detailed risk analysis
        let detailed_risk_request = AnalysisRequest {
            analysis_type: AnalysisType::DetailedRiskAnalysis,
            content: components.get_analysis_content(language, true),
            context: context.clone(),
            model: model.to_string(),
            timeout_seconds: self.default_timeout.as_secs(),
            output_language: output_language.clone(),
        };
        detailed_requests.push(detailed_risk_request);

        // Specific threat analysis focusing on high-risk lines
        let high_risk_lines = self.extract_high_risk_lines(components);
        if !high_risk_lines.is_empty() {
            let threat_analysis_request = AnalysisRequest {
                analysis_type: AnalysisType::SpecificThreatAnalysis,
                content: components.get_analysis_content(language, true),
                context: context.clone(),
                model: model.to_string(),
                timeout_seconds: self.default_timeout.as_secs(),
                output_language: output_language.clone(),
            };
            detailed_requests.push(threat_analysis_request);
        }

        self.execute_parallel_analysis(detailed_requests).await
    }

    fn extract_high_risk_lines(&self, components: &ScriptComponents) -> Vec<usize> {
        let mut high_risk_lines = Vec::new();

        // Extract line numbers from critical and high-risk nodes
        for node in &components.metadata.priority_nodes {
            if matches!(node.security_relevance, crate::models::SecurityRelevance::Critical | crate::models::SecurityRelevance::High) {
                high_risk_lines.push(node.line_start);
            }
        }

        // Sort and deduplicate
        high_risk_lines.sort_unstable();
        high_risk_lines.dedup();
        high_risk_lines
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
                        // Return error immediately instead of creating fallback
                        return Err(e);
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
            Duration::from_secs(request.timeout_seconds)
                .min(self.default_timeout),
            self.llm_client.analyze(request)
        )
        .await
        .map_err(|_| EbiError::AnalysisTimeout {
            timeout: request.timeout_seconds
        })?
    }


    pub async fn quick_analysis(
        &self,
        content: &str,
        language: &Language,
        source: &ScriptSource,
        model: &str,
        output_language: &OutputLanguage,
    ) -> Result<AnalysisResult, EbiError> {
        let context = AnalysisContext {
            language: language.clone(),
            source: source.clone(),
            script_type: None,
            truncated: false,
        };

        let request = AnalysisRequest {
            analysis_type: AnalysisType::CodeVulnerability,
            content: content.to_string(),
            context,
            model: model.to_string(),
            timeout_seconds: self.default_timeout.as_secs(),
            output_language: output_language.clone(),
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
                script_type: None,
                truncated: false,
            },
            model: self.llm_client.get_model_name().to_string(),
            timeout_seconds: 30,
            output_language: OutputLanguage::English,
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
        Self::new("gpt-5-mini", None, 60, 2)
    }

    pub fn for_production(api_key: String) -> Result<Self, EbiError> {
        Self::new("gpt-5-mini", Some(api_key), 120, 3)
    }

    pub fn for_testing() -> Result<Self, EbiError> {
        Self::new("mock-model", None, 30, 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::llm_client::LlmProvider;
    use crate::models::{AnalysisContext, AnalysisRequest, AnalysisResult, AnalysisType, ScriptSource, Language};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;

    struct MockLlmClient;

    impl LlmProvider for MockLlmClient {
        fn analyze<'a>(
            &'a self,
            request: &'a AnalysisRequest,
        ) -> Pin<Box<dyn Future<Output = Result<AnalysisResult, EbiError>> + Send + 'a>> {
            let response = AnalysisResult::new(
                request.analysis_type.clone(),
                "mock-model".to_string(),
                5,
            )
            .with_summary("Mock analysis".to_string())
            .with_confidence(0.9);

            Box::pin(async move { Ok(response) })
        }

        fn get_model_name(&self) -> &str {
            "mock-model"
        }

        fn get_timeout(&self) -> Duration {
            Duration::from_secs(30)
        }
    }

    fn mock_orchestrator() -> AnalysisOrchestrator {
        AnalysisOrchestrator {
            llm_client: Arc::new(MockLlmClient),
            max_concurrent_requests: 2,
            default_timeout: Duration::from_secs(60),
        }
    }

    #[tokio::test]
    async fn test_orchestrator_creation() {
        let orchestrator = mock_orchestrator();
        assert_eq!(orchestrator.max_concurrent_requests, 2);
        assert_eq!(orchestrator.llm_client.get_timeout(), Duration::from_secs(30));
    }

    #[test]
    fn test_request_validation() {
        let orchestrator = mock_orchestrator();

        let valid_request = AnalysisRequest {
            analysis_type: AnalysisType::CodeVulnerability,
            content: "echo hello".to_string(),
            context: AnalysisContext {
                language: Language::Bash,
                source: ScriptSource::Stdin,
                script_type: None,
                truncated: false,
            },
            model: "test-model".to_string(),
            timeout_seconds: 60,
            output_language: OutputLanguage::English,
        };

        assert!(orchestrator.validate_analysis_request(&valid_request).is_ok());

        let invalid_request = AnalysisRequest {
            analysis_type: AnalysisType::CodeVulnerability,
            content: "".to_string(),
            context: AnalysisContext {
                language: Language::Bash,
                source: ScriptSource::Stdin,
                script_type: None,
                truncated: false,
            },
            model: "test-model".to_string(),
            timeout_seconds: 60,
            output_language: OutputLanguage::English,
        };

        assert!(orchestrator.validate_analysis_request(&invalid_request).is_err());
    }

    #[test]
    fn test_configuration_updates() {
        let mut orchestrator = mock_orchestrator();
        orchestrator.update_timeout(90);
        orchestrator.update_concurrency(5);

        let info = orchestrator.get_model_info();
        assert!(info.contains("90s"));
        assert!(info.contains("Max Concurrent: 5"));
    }
}
