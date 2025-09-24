use crate::error::EbiError;
use crate::models::{AnalysisRequest, AnalysisResult, AnalysisType, OutputLanguage};
use reqwest;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;
use tokio::time::timeout;

// Constants for Claude API configuration
const CLAUDE_DEFAULT_MAX_TOKENS: u32 = 1000;
const CLAUDE_DEFAULT_TEMPERATURE: f32 = 0.3;

#[derive(Debug, Clone)]
pub struct LlmConfig {
    pub model_name: String,
    pub api_endpoint: String,
    pub api_key: Option<String>,
    pub timeout_seconds: u64,
    pub max_retries: u32,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f32>,
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

fn extract_summary_from_response(response: &str) -> String {
    let lines: Vec<&str> = response.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        let line_lower = line.to_lowercase();
        if line_lower.contains("summary:") || line_lower.contains("概要:") {
            let summary_lines: Vec<&str> = lines
                .iter()
                .skip(i + 1)
                .take_while(|l| {
                    let trimmed = l.trim();
                    if trimmed.is_empty() {
                        return false;
                    }

                    let lower = trimmed.to_lowercase();
                    !lower.contains("analysis:") && !lower.contains("分析:")
                })
                .copied()
                .collect();

            if !summary_lines.is_empty() {
                return summary_lines.join("\n").trim().to_string();
            }
        }
    }

    let meaningful_lines: Vec<&str> = lines
        .iter()
        .filter(|line| {
            let line_clean = line.trim();
            !line_clean.is_empty()
                && line_clean.len() > 20
                && !line_clean.starts_with('#')
                && !line_clean.starts_with("RISK LEVEL:")
                && !line_clean.starts_with("CONFIDENCE:")
        })
        .take(5)
        .copied()
        .collect();

    if meaningful_lines.is_empty() {
        response
            .lines()
            .take(3)
            .collect::<Vec<_>>()
            .join(" ")
            .chars()
            .take(300)
            .collect()
    } else {
        meaningful_lines.join(" ").chars().take(500).collect()
    }
}

fn determine_risk_level(response_lower: &str) -> crate::models::RiskLevel {
    if response_lower.contains("risk level: critical")
        || response_lower.contains("リスクレベル: クリティカル")
        || response_lower.contains("critical risk")
    {
        crate::models::RiskLevel::Critical
    } else if response_lower.contains("risk level: high")
        || response_lower.contains("リスクレベル: 高")
        || response_lower.contains("high risk")
    {
        crate::models::RiskLevel::High
    } else if response_lower.contains("risk level: medium")
        || response_lower.contains("リスクレベル: 中")
        || response_lower.contains("medium risk")
    {
        crate::models::RiskLevel::Medium
    } else if response_lower.contains("risk level: low")
        || response_lower.contains("リスクレベル: 低")
        || response_lower.contains("low risk")
    {
        crate::models::RiskLevel::Low
    } else if response_lower.contains("risk level: info")
        || response_lower.contains("risk level: none")
        || response_lower.contains("リスクレベル: 情報")
    {
        crate::models::RiskLevel::Info
    } else if response_lower.contains("critical") || response_lower.contains("クリティカル") {
        crate::models::RiskLevel::Critical
    } else if response_lower.contains("high") || response_lower.contains("高リスク") {
        crate::models::RiskLevel::High
    } else if response_lower.contains("medium") || response_lower.contains("中リスク") {
        crate::models::RiskLevel::Medium
    } else if response_lower.contains("low") || response_lower.contains("低リスク") {
        crate::models::RiskLevel::Low
    } else {
        crate::models::RiskLevel::Info
    }
}

fn calculate_confidence(response: &str, response_lower: &str) -> f32 {
    if response.len() > 100
        && (response_lower.contains("vulnerability")
            || response_lower.contains("risk")
            || response_lower.contains("security")
            || response_lower.contains("脆弱性")
            || response_lower.contains("リスク")
            || response_lower.contains("セキュリティ"))
    {
        0.85
    } else if response.len() > 50 {
        0.70
    } else {
        0.50
    }
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
        let api_request =
            self.build_api_request(prompt, &request.analysis_type, &request.output_language);

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
            AnalysisType::CodeVulnerability => PromptTemplate::build_vulnerability_analysis_prompt(
                &request.content,
                &request.context.language,
                &request.context.source,
                &request.output_language,
            ),
            AnalysisType::InjectionDetection => PromptTemplate::build_injection_analysis_prompt(
                &request.content,
                &request.context.language,
                &request.context.source,
                &request.output_language,
            ),
            AnalysisType::DetailedRiskAnalysis => {
                // For now, pass empty initial findings - this could be enhanced later
                PromptTemplate::build_detailed_risk_analysis_prompt(
                    &request.content,
                    &request.context.language,
                    &request.context.source,
                    &request.output_language,
                    &[], // initial_findings - could be enhanced to pass actual findings
                )
            }
            AnalysisType::SpecificThreatAnalysis => {
                // For now, pass empty focus lines - this could be enhanced later
                PromptTemplate::build_specific_threat_analysis_prompt(
                    &request.content,
                    &request.context.language,
                    &request.context.source,
                    &request.output_language,
                    &[], // focus_lines - could be enhanced to pass specific line numbers
                )
            }
        }
    }

    fn build_api_request(
        &self,
        prompt: String,
        analysis_type: &AnalysisType,
        output_language: &OutputLanguage,
    ) -> LlmApiRequest {
        build_llm_api_request(
            &self.config.model_name,
            prompt,
            analysis_type,
            output_language,
        )
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
        let response_lower = response.to_lowercase();

        let risk_level = determine_risk_level(&response_lower);
        let summary = extract_summary_from_response(response);
        let confidence = calculate_confidence(response, &response_lower);

        (risk_level, summary, confidence)
    }
}

// Anthropic Claude API structures
#[derive(Debug, Serialize)]
struct ClaudeApiRequest {
    model: String,
    max_tokens: u32,
    messages: Vec<ClaudeMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
}

#[derive(Debug, Serialize)]
struct ClaudeMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ClaudeApiResponse {
    content: Vec<ClaudeContent>,
    usage: Option<ClaudeUsage>,
    #[serde(rename = "stop_reason")]
    stop_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ClaudeContent {
    text: String,
    #[serde(rename = "type")]
    content_type: String,
}

#[derive(Debug, Deserialize)]
struct ClaudeUsage {
    #[serde(rename = "input_tokens")]
    input_tokens: u32,
    #[serde(rename = "output_tokens")]
    output_tokens: u32,
}

pub struct ClaudeClient {
    config: LlmConfig,
    client: reqwest::Client,
}

impl ClaudeClient {
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
        let api_request =
            self.build_api_request(prompt, &request.analysis_type, &request.output_language);

        let mut retries = 0;
        loop {
            let timeout_secs = request.timeout_seconds.min(self.config.timeout_seconds);
            let timeout_duration = Duration::from_secs(timeout_secs);

            let http_request = self
                .client
                .post(&self.config.api_endpoint)
                .header("Content-Type", "application/json")
                .header(
                    "x-api-key",
                    self.config.api_key.as_ref().unwrap_or(&"".to_string()),
                )
                .header("anthropic-version", "2023-06-01")
                .json(&api_request);

            let response = timeout(timeout_duration, http_request.send()).await;

            match response {
                Ok(Ok(resp)) => {
                    if resp.status().is_success() {
                        let api_response: ClaudeApiResponse = resp.json().await.map_err(|e| {
                            EbiError::LlmClientError(format!("Failed to parse response: {}", e))
                        })?;

                        if let Some(content) = api_response.content.first() {
                            return Ok(content.text.clone());
                        } else {
                            return Err(EbiError::LlmClientError(
                                "No response content received".to_string(),
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
            AnalysisType::CodeVulnerability => PromptTemplate::build_vulnerability_analysis_prompt(
                &request.content,
                &request.context.language,
                &request.context.source,
                &request.output_language,
            ),
            AnalysisType::InjectionDetection => PromptTemplate::build_injection_analysis_prompt(
                &request.content,
                &request.context.language,
                &request.context.source,
                &request.output_language,
            ),
            AnalysisType::DetailedRiskAnalysis => {
                PromptTemplate::build_detailed_risk_analysis_prompt(
                    &request.content,
                    &request.context.language,
                    &request.context.source,
                    &request.output_language,
                    &[], // No initial findings in base LLM call
                )
            }
            AnalysisType::SpecificThreatAnalysis => {
                PromptTemplate::build_specific_threat_analysis_prompt(
                    &request.content,
                    &request.context.language,
                    &request.context.source,
                    &request.output_language,
                    &[], // No focus lines in base LLM call
                )
            }
        }
    }

    fn build_api_request(
        &self,
        prompt: String,
        analysis_type: &AnalysisType,
        output_language: &OutputLanguage,
    ) -> ClaudeApiRequest {
        use crate::analyzer::prompts::PromptTemplate;
        let system_prompt = PromptTemplate::build_system_prompt(analysis_type, output_language);

        ClaudeApiRequest {
            model: self.config.model_name.clone(),
            max_tokens: self.config.max_tokens.unwrap_or(CLAUDE_DEFAULT_MAX_TOKENS),
            messages: vec![ClaudeMessage {
                role: "user".to_string(),
                content: prompt,
            }],
            temperature: self.config.temperature.or(Some(CLAUDE_DEFAULT_TEMPERATURE)),
            system: Some(system_prompt),
        }
    }
}

impl LlmProvider for ClaudeClient {
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

impl ClaudeClient {
    fn parse_analysis_response(response: &str) -> (crate::models::RiskLevel, String, f32) {
        let response_lower = response.to_lowercase();

        let risk_level = determine_risk_level(&response_lower);
        let summary = extract_summary_from_response(response);
        let confidence = calculate_confidence(response, &response_lower);

        (risk_level, summary, confidence)
    }
}

// Gemini API structures
#[derive(Debug, Serialize)]
struct GeminiApiRequest {
    contents: Vec<GeminiContent>,
    generation_config: Option<GeminiGenerationConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
struct GeminiContent {
    parts: Vec<GeminiPart>,
}

#[derive(Debug, Serialize, Deserialize)]
struct GeminiPart {
    text: String,
}

#[derive(Debug, Serialize)]
struct GeminiGenerationConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    max_output_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
}

#[derive(Debug, Deserialize)]
struct GeminiApiResponse {
    candidates: Vec<GeminiCandidate>,
    usage_metadata: Option<GeminiUsageMetadata>,
}

#[derive(Debug, Deserialize)]
struct GeminiCandidate {
    content: GeminiContent,
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GeminiUsageMetadata {
    prompt_token_count: u32,
    candidates_token_count: u32,
    total_token_count: u32,
}

pub struct GeminiClient {
    config: LlmConfig,
    client: reqwest::Client,
}

impl GeminiClient {
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
        let api_request =
            self.build_api_request(prompt, &request.analysis_type, &request.output_language);

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
                    http_request = http_request.query(&[("key", api_key)]);
                }
            }

            let response = timeout(timeout_duration, http_request.send()).await;

            match response {
                Ok(Ok(resp)) => {
                    if resp.status().is_success() {
                        let api_response: GeminiApiResponse = resp.json().await.map_err(|e| {
                            EbiError::LlmClientError(format!("Failed to parse response: {}", e))
                        })?;

                        if let Some(candidate) = api_response.candidates.first() {
                            if let Some(part) = candidate.content.parts.first() {
                                return Ok(part.text.clone());
                            }
                        }
                        return Err(EbiError::LlmClientError(
                            "No response content received".to_string(),
                        ));
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
            AnalysisType::CodeVulnerability => PromptTemplate::build_vulnerability_analysis_prompt(
                &request.content,
                &request.context.language,
                &request.context.source,
                &request.output_language,
            ),
            AnalysisType::InjectionDetection => PromptTemplate::build_injection_analysis_prompt(
                &request.content,
                &request.context.language,
                &request.context.source,
                &request.output_language,
            ),
            AnalysisType::DetailedRiskAnalysis => {
                PromptTemplate::build_detailed_risk_analysis_prompt(
                    &request.content,
                    &request.context.language,
                    &request.context.source,
                    &request.output_language,
                    &[], // No initial findings in base LLM call
                )
            }
            AnalysisType::SpecificThreatAnalysis => {
                PromptTemplate::build_specific_threat_analysis_prompt(
                    &request.content,
                    &request.context.language,
                    &request.context.source,
                    &request.output_language,
                    &[], // No focus lines in base LLM call
                )
            }
        }
    }

    fn build_api_request(
        &self,
        prompt: String,
        analysis_type: &AnalysisType,
        output_language: &OutputLanguage,
    ) -> GeminiApiRequest {
        use crate::analyzer::prompts::PromptTemplate;
        let system_prompt = PromptTemplate::build_system_prompt(analysis_type, output_language);
        let full_prompt = format!("{}\n\n{}", system_prompt, prompt);

        GeminiApiRequest {
            contents: vec![GeminiContent {
                parts: vec![GeminiPart { text: full_prompt }],
            }],
            generation_config: Some(GeminiGenerationConfig {
                max_output_tokens: self.config.max_tokens,
                temperature: self.config.temperature,
            }),
        }
    }
}

impl LlmProvider for GeminiClient {
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

impl GeminiClient {
    fn parse_analysis_response(response: &str) -> (crate::models::RiskLevel, String, f32) {
        let response_lower = response.to_lowercase();

        let risk_level = determine_risk_level(&response_lower);
        let summary = extract_summary_from_response(response);
        let confidence = calculate_confidence(response, &response_lower);

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
    } else if is_claude_model(trimmed_model) {
        (
            "https://api.anthropic.com/v1/messages".to_string(),
            trimmed_model.to_string(),
        )
    } else if is_gemini_model(trimmed_model) {
        (
            format!(
                "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent",
                trimmed_model
            ),
            trimmed_model.to_string(),
        )
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
        max_tokens: None,
        temperature: None,
    };

    let client: Box<dyn LlmProvider + Send + Sync> = if is_claude_model(&config.model_name) {
        Box::new(ClaudeClient::new(config)?)
    } else if is_gemini_model(&config.model_name) {
        Box::new(GeminiClient::new(config)?)
    } else {
        Box::new(OpenAiCompatibleClient::new(config)?)
    };
    Ok(client)
}

fn build_llm_api_request(
    model_name: &str,
    prompt: String,
    analysis_type: &AnalysisType,
    output_language: &OutputLanguage,
) -> LlmApiRequest {
    use crate::analyzer::prompts::PromptTemplate;

    let uses_reasoning = uses_reasoning_parameters(model_name);
    let system_prompt = PromptTemplate::build_system_prompt(analysis_type, output_language);

    let mut api_request = LlmApiRequest {
        model: model_name.to_string(),
        messages: vec![
            ChatMessage {
                role: "system".to_string(),
                content: system_prompt,
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

fn is_claude_model(model: &str) -> bool {
    let candidate = model.strip_prefix("anthropic/").unwrap_or(model);
    candidate.starts_with("claude-")
}

fn is_gemini_model(model: &str) -> bool {
    let candidate = model.strip_prefix("gemini/").unwrap_or(model);

    candidate.starts_with("gemini-")
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
        use crate::models::{AnalysisType, OutputLanguage};
        let request = super::build_llm_api_request(
            "gpt-5-mini",
            "prompt".to_string(),
            &AnalysisType::CodeVulnerability,
            &OutputLanguage::English,
        );
        assert!(request.max_tokens.is_none());
        assert_eq!(request.max_completion_tokens, Some(1000));
        assert!(request.temperature.is_none());

        let classic_request = super::build_llm_api_request(
            "gpt-4o",
            "prompt".to_string(),
            &AnalysisType::CodeVulnerability,
            &OutputLanguage::English,
        );
        assert_eq!(classic_request.max_tokens, Some(1000));
        assert!(classic_request.max_completion_tokens.is_none());
        assert_eq!(classic_request.temperature, Some(0.3));
    }

    #[test]
    fn test_claude_model_detection() {
        assert!(super::is_claude_model("claude-3.5-sonnet"));
        assert!(super::is_claude_model("claude-3.5-haiku"));
        assert!(super::is_claude_model("claude-3-opus"));
        assert!(super::is_claude_model("claude-3-sonnet"));
        assert!(super::is_claude_model("claude-3-haiku"));
        assert!(super::is_claude_model("claude-2"));
        assert!(super::is_claude_model("claude-instant"));
        assert!(super::is_claude_model("anthropic/claude-3.5-sonnet"));

        assert!(!super::is_claude_model("gpt-4"));
        assert!(!super::is_claude_model("gemini-pro"));
        assert!(!super::is_claude_model("unknown-model"));
    }

    #[test]
    fn test_claude_client_creation() {
        let client =
            super::create_llm_client("claude-3.5-sonnet", Some("test-key".to_string()), 60);
        assert!(client.is_ok());

        let client = client.unwrap();
        assert_eq!(client.get_model_name(), "claude-3.5-sonnet");
    }

    #[test]
    fn test_claude_response_parsing() {
        let response = "Risk Level: HIGH\nThis script contains potential vulnerabilities including command injection.";
        let (risk_level, summary, confidence) =
            super::ClaudeClient::parse_analysis_response(response);

        assert_eq!(risk_level, crate::models::RiskLevel::High);
        assert!(summary.contains("vulnerabilities"));
        assert!(confidence > 0.5);
    }

    #[test]
    fn test_gemini_model_detection() {
        assert!(super::is_gemini_model("gemini-pro"));
        assert!(super::is_gemini_model("gemini-1.5-pro"));
        assert!(super::is_gemini_model("gemini-1.5-flash"));
        assert!(super::is_gemini_model("gemini-2.0-flash-exp"));
        assert!(super::is_gemini_model("gemini-2.5-flash"));
        assert!(super::is_gemini_model("gemini/gemini-1.5-pro"));

        assert!(!super::is_gemini_model("gpt-4"));
        assert!(!super::is_gemini_model("claude-3.5-sonnet"));
        assert!(!super::is_gemini_model("unknown-model"));
    }

    #[test]
    fn test_gemini_client_creation() {
        let client = super::create_llm_client("gemini-2.5-flash", Some("test-key".to_string()), 60);
        assert!(client.is_ok());

        let client = client.unwrap();
        assert_eq!(client.get_model_name(), "gemini-2.5-flash");
    }

    #[test]
    fn test_gemini_response_parsing() {
        let response = "Risk Level: HIGH\nThis script contains potential vulnerabilities including command injection.";
        let (risk_level, summary, confidence) = GeminiClient::parse_analysis_response(response);

        assert_eq!(risk_level, crate::models::RiskLevel::High);
        assert!(summary.contains("vulnerabilities"));
        assert!(confidence > 0.5);
    }
}
