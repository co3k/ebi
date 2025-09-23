use crate::error::EbiError;
use crate::models::{AnalysisRequest, AnalysisResult, AnalysisType};
use reqwest;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub struct LlmConfig {
    pub model_name: String,
    pub api_endpoint: String,
    pub api_key: Option<String>,
    pub timeout_seconds: u64,
    pub max_retries: u32,
}

#[derive(Debug, Serialize)]
struct LlmApiRequest {
    model: String,
    messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_completion_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
}

#[derive(Debug, Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct LlmApiResponse {
    choices: Vec<Choice>,
    usage: Option<Usage>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: ResponseMessage,
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ResponseMessage {
    content: String,
}

#[derive(Debug, Deserialize)]
struct Usage {
    total_tokens: u32,
    prompt_tokens: u32,
    completion_tokens: u32,
}

pub trait LlmProvider: Send + Sync {
    fn analyze<'a>(
        &'a self,
        request: &'a AnalysisRequest,
    ) -> Pin<Box<dyn Future<Output = Result<AnalysisResult, EbiError>> + Send + 'a>>;
    fn get_model_name(&self) -> &str;
    fn get_timeout(&self) -> Duration;
}

pub struct OpenAiCompatibleClient {
    config: LlmConfig,
    client: reqwest::Client,
}

impl OpenAiCompatibleClient {
    pub fn new(config: LlmConfig) -> Result<Self, EbiError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_seconds))
            .build()
            .map_err(|e| {
                EbiError::LlmClientError(format!("Failed to create HTTP client: {}", e))
            })?;

        Ok(Self { config, client })
    }

    async fn make_api_request(&self, request: &AnalysisRequest) -> Result<String, EbiError> {
        let prompt = self.build_prompt(request);
        let api_request = self.build_api_request(prompt);

        let mut retries = 0;
        loop {
            let timeout_secs = request.timeout_seconds.min(self.config.timeout_seconds);
            let timeout_duration = Duration::from_secs(timeout_secs);

            let mut http_request = self
                .client
                .post(&self.config.api_endpoint)
                .header("Content-Type", "application/json")
                .json(&api_request);

            if let Some(ref api_key) = self.config.api_key {
                if !api_key.is_empty() {
                    http_request =
                        http_request.header("Authorization", format!("Bearer {}", api_key));
                }
            }

            let response = timeout(timeout_duration, http_request.send()).await;

            match response {
                Ok(Ok(resp)) => {
                    if resp.status().is_success() {
                        let api_response: LlmApiResponse = resp.json().await.map_err(|e| {
                            EbiError::LlmClientError(format!("Failed to parse response: {}", e))
                        })?;

                        if let Some(choice) = api_response.choices.first() {
                            return Ok(choice.message.content.clone());
                        } else {
                            return Err(EbiError::LlmClientError(
                                "No response choices received".to_string(),
                            ));
                        }
                    } else {
                        let status = resp.status();
                        let error_text = resp
                            .text()
                            .await
                            .unwrap_or_else(|_| "Unknown error".to_string());

                        if retries < self.config.max_retries
                            && (status.is_server_error() || status == 429)
                        {
                            retries += 1;
                            tokio::time::sleep(Duration::from_millis(1000 * retries as u64)).await;
                            continue;
                        }

                        return Err(EbiError::LlmClientError(format!(
                            "API request failed with status {}: {}",
                            status, error_text
                        )));
                    }
                }
                Ok(Err(e)) => {
                    if retries < self.config.max_retries {
                        retries += 1;
                        tokio::time::sleep(Duration::from_millis(1000 * retries as u64)).await;
                        continue;
                    }
                    return Err(EbiError::LlmClientError(format!("Network error: {}", e)));
                }
                Err(_) => {
                    return Err(EbiError::AnalysisTimeout {
                        timeout: timeout_secs,
                    });
                }
            }
        }
    }

    fn build_prompt(&self, request: &AnalysisRequest) -> String {
        use crate::analyzer::prompts::PromptTemplate;
        
        match request.analysis_type {
            AnalysisType::CodeVulnerability => {
                PromptTemplate::build_vulnerability_analysis_prompt(
                    &request.content,
                    &request.context.language,
                    &request.context.source,
                    &request.output_language,
                )
            }
            AnalysisType::InjectionDetection => {
                PromptTemplate::build_injection_analysis_prompt(
                    &request.content,
                    &request.context.language,
                    &request.context.source,
                    &request.output_language,
                )
            }
        }
    }

    fn build_api_request(&self, prompt: String) -> LlmApiRequest {
        build_llm_api_request(&self.config.model_name, prompt)
    }
}

impl LlmProvider for OpenAiCompatibleClient {
    fn analyze<'a>(
        &'a self,
        request: &'a AnalysisRequest,
    ) -> Pin<Box<dyn Future<Output = Result<AnalysisResult, EbiError>> + Send + 'a>> {
        Box::pin(async move {
            let start_time = std::time::Instant::now();

            let response_content = self.make_api_request(request).await?;

            let duration_ms = start_time.elapsed().as_millis() as u64;

            // Parse the response to extract risk level and summary
            let (risk_level, summary, confidence) =
                Self::parse_analysis_response(&response_content);

            let result = AnalysisResult::new(
                request.analysis_type.clone(),
                self.config.model_name.clone(),
                duration_ms,
            )
            .with_risk_level(risk_level)
            .with_summary(summary)
            .with_confidence(confidence)
            .with_details(response_content);

            Ok(result)
        })
    }

    fn get_model_name(&self) -> &str {
        &self.config.model_name
    }

    fn get_timeout(&self) -> Duration {
        Duration::from_secs(self.config.timeout_seconds)
    }
}

impl OpenAiCompatibleClient {
    fn parse_analysis_response(response: &str) -> (crate::models::RiskLevel, String, f32) {
        use crate::models::RiskLevel;

        let response_lower = response.to_lowercase();

        // Extract risk level
        let risk_level = if response_lower.contains("critical") {
            RiskLevel::Critical
        } else if response_lower.contains("high") {
            RiskLevel::High
        } else if response_lower.contains("medium") {
            RiskLevel::Medium
        } else if response_lower.contains("low") {
            RiskLevel::Low
        } else {
            RiskLevel::Info // Default if unclear
        };

        // Extract summary (first few sentences)
        let summary = response
            .lines()
            .take(3)
            .collect::<Vec<_>>()
            .join(" ")
            .chars()
            .take(200)
            .collect::<String>();

        // Calculate confidence based on response quality
        let confidence = if response.len() > 100
            && (response_lower.contains("vulnerability")
                || response_lower.contains("risk")
                || response_lower.contains("security"))
        {
            0.85
        } else if response.len() > 50 {
            0.70
        } else {
            0.50
        };

        (risk_level, summary, confidence)
    }
}

// Factory function to create LLM clients
pub fn create_llm_client(
    model: &str,
    api_key: Option<String>,
    timeout_seconds: u64,
) -> Result<Box<dyn LlmProvider + Send + Sync>, EbiError> {
    // Determine API endpoint based on model
    let endpoint_override = std::env::var("EBI_LLM_API_ENDPOINT").ok();
    let trimmed_model = model.trim();

    let (api_endpoint, actual_model) = if let Some(endpoint) = endpoint_override {
        (endpoint, trimmed_model.to_string())
    } else if is_openai_model(trimmed_model) {
        (
            "https://api.openai.com/v1/chat/completions".to_string(),
            trimmed_model.to_string(),
        )
    } else if trimmed_model.starts_with("claude-") {
        // For Claude, we'd need to use Anthropic's API format (not OpenAI compatible)
        return Err(EbiError::LlmClientError(
            "Claude models not yet supported - use OpenAI-compatible models".to_string(),
        ));
    } else if trimmed_model.starts_with("gemini-") {
        // For Gemini, we'd need to use Google's API format
        return Err(EbiError::LlmClientError(
            "Gemini models not yet supported - use OpenAI-compatible models".to_string(),
        ));
    } else {
        return Err(EbiError::LlmClientError(format!(
            "Unsupported model '{trimmed_model}'. Specify a supported model or set EBI_LLM_API_ENDPOINT for custom integrations",
        )));
    };

    let config = LlmConfig {
        model_name: actual_model,
        api_endpoint,
        api_key,
        timeout_seconds,
        max_retries: 3,
    };

    let client = OpenAiCompatibleClient::new(config)?;
    Ok(Box::new(client))
}

fn build_llm_api_request(model_name: &str, prompt: String) -> LlmApiRequest {
    let uses_reasoning = uses_reasoning_parameters(model_name);

    let mut api_request = LlmApiRequest {
        model: model_name.to_string(),
        messages: vec![
            ChatMessage {
                role: "system".to_string(),
                content: "You are a security analysis assistant. Analyze the provided script code for security vulnerabilities and provide a detailed assessment.".to_string(),
            },
            ChatMessage {
                role: "user".to_string(),
                content: prompt,
            },
        ],
        max_tokens: None,
        max_completion_tokens: None,
        temperature: if uses_reasoning { None } else { Some(0.3) },
    };

    if uses_reasoning {
        api_request.max_completion_tokens = Some(1000);
    } else {
        api_request.max_tokens = Some(1000);
    }

    api_request
}

fn is_openai_model(model: &str) -> bool {
    let candidate = model.strip_prefix("openai/").unwrap_or(model);
    let candidate = candidate.strip_prefix("ft:").unwrap_or(candidate);

    candidate.starts_with("gpt-")
        || candidate.starts_with("chatgpt-")
        || candidate.starts_with("o1")
        || candidate.starts_with("o3")
        || candidate.starts_with("o4")
}

fn uses_reasoning_parameters(model: &str) -> bool {
    let candidate = model.strip_prefix("openai/").unwrap_or(model);
    let candidate = candidate.strip_prefix("ft:").unwrap_or(candidate);

    candidate.starts_with("o1")
        || candidate.starts_with("o3")
        || candidate.starts_with("o4")
        || candidate.starts_with("gpt-5")
        || candidate.starts_with("gpt-4.1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Language, ScriptSource};

    #[test]
    fn test_prompt_building() {
        let prompt = crate::analyzer::prompts::PromptTemplate::build_vulnerability_analysis_prompt(
            "echo hello",
            &Language::Bash,
            &ScriptSource::Stdin,
            &crate::models::OutputLanguage::English,
        );
        assert!(prompt.contains("bash"));
        assert!(prompt.contains("echo hello"));
        assert!(prompt.contains("vulnerabilities"));
    }

    #[test]
    fn test_response_parsing() {
        let response = "Risk Level: HIGH\nThis script contains potential vulnerabilities including command injection.";
        let (risk_level, summary, confidence) =
            OpenAiCompatibleClient::parse_analysis_response(response);

        assert_eq!(risk_level, crate::models::RiskLevel::High);
        assert!(summary.contains("vulnerabilities"));
        assert!(confidence > 0.5);
    }

    #[test]
    fn test_client_creation_rejects_unknown_model() {
        let err = match create_llm_client("unsupported-model", Some("test-key".to_string()), 60) {
            Ok(_) => panic!("unexpected success for unsupported model"),
            Err(err) => err,
        };

        match err {
            EbiError::LlmClientError(message) => {
                assert!(message.contains("unsupported-model"));
            }
            other => panic!("unexpected error type: {:?}", other),
        }
    }

    #[test]
    fn test_o_series_models_supported_by_detection() {
        assert!(super::is_openai_model("o1-mini"));
        assert!(super::is_openai_model("o3-preview"));
        assert!(super::is_openai_model("o4-mini"));
        assert!(super::is_openai_model("gpt-5-mini"));

        assert!(super::uses_reasoning_parameters("o1-mini"));
        assert!(super::uses_reasoning_parameters("o3-preview"));
        assert!(super::uses_reasoning_parameters("o4-mini"));
        assert!(super::uses_reasoning_parameters("gpt-5-mini"));
        assert!(super::uses_reasoning_parameters("gpt-4.1"));

        assert!(!super::uses_reasoning_parameters("gpt-4o"));
        assert!(!super::uses_reasoning_parameters("gpt-4o-mini"));
        assert!(!super::uses_reasoning_parameters("gpt-3.5-turbo"));
    }

    #[test]
    fn test_build_api_request_switches_token_parameters() {
        let request = super::build_llm_api_request("gpt-5-mini", "prompt".to_string());
        assert!(request.max_tokens.is_none());
        assert_eq!(request.max_completion_tokens, Some(1000));
        assert!(request.temperature.is_none());

        let classic_request = super::build_llm_api_request("gpt-4o", "prompt".to_string());
        assert_eq!(classic_request.max_tokens, Some(1000));
        assert!(classic_request.max_completion_tokens.is_none());
        assert_eq!(classic_request.temperature, Some(0.3));
    }
}
