use crate::models::{AnalysisRequest, AnalysisResult, AnalysisType};
use crate::error::EbiError;
use reqwest;
use serde::{Deserialize, Serialize};
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
    max_tokens: Option<u32>,
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

pub trait LlmProvider {
    async fn analyze(&self, request: &AnalysisRequest) -> Result<AnalysisResult, EbiError>;
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
            .map_err(|e| EbiError::LlmClientError(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self { config, client })
    }

    async fn make_api_request(&self, request: &AnalysisRequest) -> Result<String, EbiError> {
        let prompt = self.build_prompt(request);

        let api_request = LlmApiRequest {
            model: self.config.model_name.clone(),
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
            max_tokens: Some(1000),
            temperature: Some(0.3), // Lower temperature for more consistent security analysis
        };

        let mut retries = 0;
        loop {
            let response = timeout(
                Duration::from_secs(self.config.timeout_seconds),
                self.client
                    .post(&self.config.api_endpoint)
                    .header("Content-Type", "application/json")
                    .header("Authorization", format!("Bearer {}",
                        self.config.api_key.as_ref().unwrap_or(&"".to_string())))
                    .json(&api_request)
                    .send()
            ).await;

            match response {
                Ok(Ok(resp)) => {
                    if resp.status().is_success() {
                        let api_response: LlmApiResponse = resp.json().await
                            .map_err(|e| EbiError::LlmClientError(format!("Failed to parse response: {}", e)))?;

                        if let Some(choice) = api_response.choices.first() {
                            return Ok(choice.message.content.clone());
                        } else {
                            return Err(EbiError::LlmClientError("No response choices received".to_string()));
                        }
                    } else {
                        let status = resp.status();
                        let error_text = resp.text().await.unwrap_or_else(|_| "Unknown error".to_string());

                        if retries < self.config.max_retries && (status.is_server_error() || status == 429) {
                            retries += 1;
                            tokio::time::sleep(Duration::from_millis(1000 * retries as u64)).await;
                            continue;
                        }

                        return Err(EbiError::LlmClientError(
                            format!("API request failed with status {}: {}", status, error_text)
                        ));
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
                        timeout: self.config.timeout_seconds
                    });
                }
            }
        }
    }

    fn build_prompt(&self, request: &AnalysisRequest) -> String {
        match request.analysis_type {
            AnalysisType::CodeVulnerability => {
                format!(
                    r#"Please analyze the following {} script for security vulnerabilities:

SCRIPT CONTENT:
{}

CONTEXT:
- Script length: {} characters
- Language: {}
- Source: {}

Please provide:
1. Overall risk level (Critical/High/Medium/Low)
2. Specific vulnerabilities found
3. Potential impact of each vulnerability
4. Recommended mitigations

Focus on:
- Command injection vulnerabilities
- Privilege escalation risks
- Network security issues
- File system access patterns
- Code execution risks

Respond in a structured format with clear risk assessment."#,
                    request.context.language.as_str(),
                    request.content,
                    request.content.len(),
                    request.context.language.as_str(),
                    request.context.source.as_str()
                )
            }
            AnalysisType::InjectionDetection => {
                format!(
                    r#"Please analyze the following content extracted from a {} script for potential injection attacks:

CONTENT TO ANALYZE:
{}

This content includes comments and string literals from the script. Please check for:
1. Suspicious patterns that might indicate injection attacks
2. Obfuscated or encoded content
3. Unusual character sequences
4. Potential social engineering attempts
5. Hidden or misleading information

CONTEXT:
- Script language: {}
- Content source: {}

Provide a risk assessment and explain any suspicious patterns found."#,
                    request.context.language.as_str(),
                    request.content,
                    request.context.language.as_str(),
                    request.context.source.as_str()
                )
            }
        }
    }
}

impl LlmProvider for OpenAiCompatibleClient {
    async fn analyze(&self, request: &AnalysisRequest) -> Result<AnalysisResult, EbiError> {
        let start_time = std::time::Instant::now();

        let response_content = self.make_api_request(request).await?;

        let duration_ms = start_time.elapsed().as_millis() as u64;

        // Parse the response to extract risk level and summary
        let (risk_level, summary, confidence) = self.parse_analysis_response(&response_content);

        let mut result = AnalysisResult::new(
            request.analysis_type.clone(),
            self.config.model_name.clone(),
            duration_ms,
        )
        .with_risk_level(risk_level)
        .with_summary(summary)
        .with_confidence(confidence);

        // Store the full response as details
        result = result.with_details(response_content);

        Ok(result)
    }

    fn get_model_name(&self) -> &str {
        &self.config.model_name
    }

    fn get_timeout(&self) -> Duration {
        Duration::from_secs(self.config.timeout_seconds)
    }
}

impl OpenAiCompatibleClient {
    fn parse_analysis_response(&self, response: &str) -> (crate::models::RiskLevel, String, f64) {
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
        let confidence = if response.len() > 100 &&
                          (response_lower.contains("vulnerability") ||
                           response_lower.contains("risk") ||
                           response_lower.contains("security")) {
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
pub fn create_llm_client(model: &str, api_key: Option<String>, timeout_seconds: u64) -> Result<Box<dyn LlmProvider + Send + Sync>, EbiError> {
    // Determine API endpoint based on model
    let (api_endpoint, actual_model) = if model.starts_with("gpt-") {
        ("https://api.openai.com/v1/chat/completions".to_string(), model.to_string())
    } else if model.starts_with("claude-") {
        // For Claude, we'd need to use Anthropic's API format (not OpenAI compatible)
        return Err(EbiError::LlmClientError("Claude models not yet supported - use OpenAI-compatible models".to_string()));
    } else if model.starts_with("gemini-") {
        // For Gemini, we'd need to use Google's API format
        return Err(EbiError::LlmClientError("Gemini models not yet supported - use OpenAI-compatible models".to_string()));
    } else {
        // Default to OpenAI-compatible endpoint (for local models, etc.)
        ("http://localhost:11434/v1/chat/completions".to_string(), model.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AnalysisContext, Language, ScriptSource};

    #[test]
    fn test_prompt_building() {
        let config = LlmConfig {
            model_name: "gpt-4".to_string(),
            api_endpoint: "https://api.openai.com/v1/chat/completions".to_string(),
            api_key: Some("test-key".to_string()),
            timeout_seconds: 60,
            max_retries: 3,
        };

        let client = OpenAiCompatibleClient::new(config).unwrap();

        let request = AnalysisRequest {
            analysis_type: AnalysisType::CodeVulnerability,
            content: "echo hello".to_string(),
            context: AnalysisContext {
                language: Language::Bash,
                source: ScriptSource::Stdin,
            },
            model: "gpt-4".to_string(),
            timeout_seconds: 60,
        };

        let prompt = client.build_prompt(&request);
        assert!(prompt.contains("bash"));
        assert!(prompt.contains("echo hello"));
        assert!(prompt.contains("vulnerabilities"));
    }

    #[test]
    fn test_response_parsing() {
        let config = LlmConfig {
            model_name: "gpt-4".to_string(),
            api_endpoint: "https://api.openai.com/v1/chat/completions".to_string(),
            api_key: Some("test-key".to_string()),
            timeout_seconds: 60,
            max_retries: 3,
        };

        let client = OpenAiCompatibleClient::new(config).unwrap();

        let response = "Risk Level: HIGH\nThis script contains potential vulnerabilities including command injection.";
        let (risk_level, summary, confidence) = client.parse_analysis_response(response);

        assert_eq!(risk_level, crate::models::RiskLevel::High);
        assert!(summary.contains("vulnerabilities"));
        assert!(confidence > 0.5);
    }

    #[test]
    fn test_client_creation() {
        // Test OpenAI model
        let client = create_llm_client("gpt-4", Some("test-key".to_string()), 60);
        assert!(client.is_ok());

        // Test unsupported model
        let client = create_llm_client("claude-3", Some("test-key".to_string()), 60);
        assert!(client.is_err());
    }
}