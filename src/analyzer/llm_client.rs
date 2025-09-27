use crate::error::EbiError;
use crate::models::{AnalysisRequest, AnalysisResult, AnalysisType, OutputLanguage};
use rig::completion::{CompletionModel, AssistantContent};
use rig::providers::{anthropic, gemini, openai};
use rig::client::CompletionClient;
use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct LlmConfig {
    pub model_name: String,
    pub api_key: Option<String>,
    pub timeout_seconds: u64,
    pub max_retries: u32,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f32>,
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
            if line_clean.is_empty() {
                return false;
            }

            if line_clean.starts_with('#') {
                return false;
            }

            let uppercase = line_clean.to_uppercase();
            if uppercase.starts_with("RISK LEVEL:") || uppercase.starts_with("CONFIDENCE:") {
                return false;
            }

            true
        })
        .take(6)
        .copied()
        .collect();

    let raw_summary = if meaningful_lines.is_empty() {
        response
            .lines()
            .take(3)
            .collect::<Vec<_>>()
            .join("\n")
            .chars()
            .take(600)
            .collect()
    } else {
        meaningful_lines.join("\n").chars().take(1200).collect()
    };

    let mut summary = clean_summary_text(raw_summary);

    if summary.trim().len() < 5 {
        summary = response
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                !trimmed.is_empty()
                    && !trimmed.to_uppercase().starts_with("RISK LEVEL:")
                    && !trimmed.to_uppercase().starts_with("CONFIDENCE:")
            })
            .take(6)
            .map(|line| line.replace('|', " "))
            .collect::<Vec<_>>()
            .join("\n");

        if summary.trim().is_empty() {
            summary = "Summary not provided by model.".to_string();
        }
    }

    summary
}

fn parse_explicit_risk_level(line: &str) -> Option<crate::models::RiskLevel> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    let lower = trimmed.to_lowercase();

    if let Some(value) = extract_risk_token(&lower, trimmed, "risk level") {
        return Some(value);
    }

    if line.contains("リスクレベル") {
        return extract_risk_token(&lower, trimmed, "リスクレベル");
    }

    None
}

fn extract_risk_token(
    lower_line: &str,
    original_line: &str,
    marker: &str,
) -> Option<crate::models::RiskLevel> {
    let marker_lower = marker.to_lowercase();
    let marker_pos = lower_line.find(&marker_lower)?;
    let after_marker = &original_line[marker_pos + marker.len()..];

    let token_section = after_marker
        .split(|c| c == ':' || c == '：')
        .nth(1)
        .unwrap_or(after_marker)
        .trim();

    if token_section.is_empty() {
        return None;
    }

    for segment in token_section.split(|c: char| {
        c.is_whitespace() || matches!(c, '-' | '–' | '|' | '*' | '•' | '.' | ',' | ';') || c == '・'
    }) {
        let candidate = segment
            .trim()
            .trim_matches(|c: char| !c.is_alphanumeric() && c != '.' && c != '・');

        if candidate.is_empty() {
            continue;
        }

        if let Some(mapped) = map_risk_token(candidate) {
            return Some(mapped);
        }
    }

    None
}

fn map_risk_token(token: &str) -> Option<crate::models::RiskLevel> {
    let lower = token.to_lowercase();

    if lower.starts_with("critical") || token.contains("クリティカル") {
        Some(crate::models::RiskLevel::Critical)
    } else if lower.starts_with("high") || token.contains("高") {
        Some(crate::models::RiskLevel::High)
    } else if lower.starts_with("medium") || token.contains("中") {
        Some(crate::models::RiskLevel::Medium)
    } else if lower.starts_with("low") || token.contains("低") {
        Some(crate::models::RiskLevel::Low)
    } else if lower.starts_with("info") || lower.starts_with("none") || token.contains("情報") {
        Some(crate::models::RiskLevel::Info)
    } else {
        None
    }
}

fn determine_risk_level(response: &str, response_lower: &str) -> crate::models::RiskLevel {
    let mut explicit_risks = Vec::new();

    for line in response.lines() {
        if let Some(risk) = parse_explicit_risk_level(line) {
            explicit_risks.push(risk);
        }
    }

    if let Some(override_risk) = detect_safe_risk_override(response_lower, &explicit_risks) {
        return override_risk;
    }

    if let Some(last_explicit) = explicit_risks.last() {
        return last_explicit.clone();
    }

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

fn extract_legitimacy_line(response: &str) -> Option<String> {
    for line in response.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let lower = trimmed.to_lowercase();
        if lower.starts_with("legitimacy assessment") {
            return Some(trimmed.to_string());
        }

        if trimmed.starts_with("正当性評価") || trimmed.starts_with("正当性判定") {
            return Some(trimmed.to_string());
        }
    }

    None
}

fn detect_safe_risk_override(
    response_lower: &str,
    explicit_risks: &[crate::models::RiskLevel],
) -> Option<crate::models::RiskLevel> {
    const SAFE_PHRASES_INFO: &[&str] = &[
        "no injection or social-engineering risks identified",
        "no injection or social engineering risks identified",
        "no injection risks identified",
        "no social-engineering risks identified",
        "no social engineering risks identified",
        "no significant security concerns identified",
        "no significant security issues identified",
        "no security concerns identified",
        "no vulnerabilities identified",
        "no vulnerabilities were identified",
        "no malicious behavior detected",
        "no malicious behaviour detected",
        "no suspicious behavior detected",
        "no suspicious behaviour detected",
        "no suspicious patterns found",
        "no suspicious patterns identified",
        "no signs of compromise",
        "no evidence of tampering",
        "no evidence of malicious intent",
    ];

    const SAFE_PHRASES_INFO_JP: &[&str] = &[
        "リスクは確認されません",
        "リスクは見られません",
        "懸念は確認されません",
        "懸念は見られません",
        "懸念は特定されません",
        "悪意のある挙動は確認されません",
        "悪意のある動作は確認されません",
        "注入やソーシャルエンジニアリングのリスクは確認されません",
        "注入リスクは確認されません",
        "ソーシャルエンジニアリングのリスクは確認されません",
        "脆弱性は確認されません",
        "脆弱性は特定されません",
        "悪意のある操作は確認されません",
        "悪意のある操作は特定されません",
    ];

    if SAFE_PHRASES_INFO
        .iter()
        .any(|phrase| response_lower.contains(phrase))
        || SAFE_PHRASES_INFO_JP
            .iter()
            .any(|phrase| response_lower.contains(&phrase.to_lowercase()))
    {
        let max_explicit = explicit_risks.iter().max().cloned();
        return match max_explicit {
            Some(level) if level >= crate::models::RiskLevel::High => {
                Some(crate::models::RiskLevel::Medium)
            }
            _ => Some(crate::models::RiskLevel::Info),
        };
    }

    None
}

fn clean_summary_text(summary: String) -> String {
    let mut seen = HashSet::new();
    let mut cleaned = Vec::new();
    let mut consecutive_blank = false;

    for line in summary.lines() {
        let trimmed = line.trim_end();
        if trimmed.trim().is_empty() {
            if !consecutive_blank && !cleaned.is_empty() {
                cleaned.push(String::new());
            }
            consecutive_blank = true;
            continue;
        }

        let sanitized = trimmed
            .replace("**", "")
            .replace('`', "")
            .replace('|', " ")
            .trim()
            .to_string();

        if sanitized.is_empty() {
            continue;
        }

        if sanitized.starts_with('|') {
            continue;
        }

        let lowercase = sanitized.to_lowercase();

        const FILLER_PHRASES: &[&str] = &[
            "サイバーセキュリティアナリストとして",
            "cybersecurity analyst",
            "as a cybersecurity analyst",
            "this analysis",
            "i will",
            "i'll help",
        ];

        if FILLER_PHRASES
            .iter()
            .any(|phrase| lowercase.contains(phrase))
        {
            continue;
        }

        if seen.insert(lowercase) {
            cleaned.push(sanitized);
            consecutive_blank = false;
        }

        if cleaned.len() >= 12 {
            break;
        }
    }

    if cleaned.is_empty() {
        let fallback = summary
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.replace("**", "").replace('`', ""))
                }
            })
            .take(5)
            .collect::<Vec<_>>()
            .join("\n");

        if fallback.is_empty() {
            return summary.chars().take(400).collect();
        }

        return fallback.chars().take(800).collect();
    }

    while cleaned.last().map(|s| s.is_empty()).unwrap_or(false) {
        cleaned.pop();
    }

    let combined = cleaned.join("\n");
    if combined.trim().is_empty() {
        "Summary not provided by model.".to_string()
    } else {
        combined.chars().take(1000).collect()
    }
}

pub struct RigLlmClient {
    config: LlmConfig,
    provider: RigProvider,
}

enum RigProvider {
    OpenAI(openai::Client),
    OpenAIResponses(openai::Client),
    Anthropic(anthropic::Client),
    Gemini(gemini::Client),
}

impl RigLlmClient {
    pub fn new(config: LlmConfig) -> Result<Self, EbiError> {
        let provider = create_provider(&config)?;
        Ok(Self { config, provider })
    }

    async fn make_api_request(&self, request: &AnalysisRequest) -> Result<String, EbiError> {
        let prompt = self.build_prompt(request);
        let system_prompt = self.build_system_prompt(&request.analysis_type, &request.output_language);

        match &self.provider {
            RigProvider::OpenAI(client) | RigProvider::OpenAIResponses(client) => {
                let model = client.completion_model(&self.config.model_name);
                self.send_completion_request(model, &prompt, system_prompt).await
            }
            RigProvider::Anthropic(client) => {
                let model = client.completion_model(&self.config.model_name);
                self.send_completion_request(model, &prompt, system_prompt).await
            }
            RigProvider::Gemini(client) => {
                let model = client.completion_model(&self.config.model_name);
                self.send_completion_request(model, &prompt, system_prompt).await
            }
        }
    }

    async fn send_completion_request<M: CompletionModel>(
        &self,
        model: M,
        prompt: &str,
        system_prompt: String,
    ) -> Result<String, EbiError> {
        let mut builder = model
            .completion_request(prompt)
            .preamble(system_prompt);

        // Skip temperature for models that don't support it (like GPT-5 series and o1 series)
        if let Some(temp) = self.config.temperature {
            if !self.config.model_name.starts_with("gpt-5") && !self.config.model_name.starts_with("o1") {
                builder = builder.temperature(temp as f64);
            }
        }

        if let Some(max_tokens) = self.config.max_tokens {
            builder = builder.max_tokens(max_tokens as u64);
        }

        let response = builder
            .send()
            .await
            .map_err(|e| EbiError::LlmClientError(format!("Request failed: {}", e)))?;

        // Extract the text content from the response
        let mut extracted_text = String::new();
        for content in response.choice.iter() {
            if let AssistantContent::Text(text_content) = content {
                extracted_text.push_str(&text_content.text);
            }
        }

        Ok(extracted_text)
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
                    &[],
                )
            }
            AnalysisType::SpecificThreatAnalysis => {
                PromptTemplate::build_specific_threat_analysis_prompt(
                    &request.content,
                    &request.context.language,
                    &request.context.source,
                    &request.output_language,
                    &[],
                )
            }
        }
    }

    fn build_system_prompt(&self, analysis_type: &AnalysisType, output_language: &OutputLanguage) -> String {
        use crate::analyzer::prompts::PromptTemplate;
        PromptTemplate::build_system_prompt(analysis_type, output_language)
    }

    fn parse_analysis_response(response: &str) -> (crate::models::RiskLevel, String, f32) {
        let response_lower = response.to_lowercase();

        let risk_level = determine_risk_level(response, &response_lower);
        let mut summary = extract_summary_from_response(response);
        if let Some(legitimacy_line) = extract_legitimacy_line(response) {
            let summary_lower = summary.to_lowercase();
            if summary.is_empty()
                || (!summary_lower.contains("legitimacy assessment")
                    && !summary.contains("正当性評価")
                    && !summary.contains("正当"))
            {
                summary = if summary.is_empty() {
                    legitimacy_line
                } else {
                    format!("{}\n{}", legitimacy_line, summary)
                };
            }
        }
        let confidence = calculate_confidence(response, &response_lower);

        (risk_level, summary, confidence)
    }
}

impl LlmProvider for RigLlmClient {
    fn analyze<'a>(
        &'a self,
        request: &'a AnalysisRequest,
    ) -> Pin<Box<dyn Future<Output = Result<AnalysisResult, EbiError>> + Send + 'a>> {
        Box::pin(async move {
            let start_time = std::time::Instant::now();

            let response_content = self.make_api_request(request).await?;

            let duration_ms = start_time.elapsed().as_millis() as u64;

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

fn create_provider(config: &LlmConfig) -> Result<RigProvider, EbiError> {
    let model_name = config.model_name.trim();

    if is_openai_model(model_name) {
        let api_key = config.api_key.clone()
            .or_else(|| std::env::var("OPENAI_API_KEY").ok())
            .ok_or_else(|| EbiError::LlmClientError("OpenAI API key not found".to_string()))?;

        let client = openai::Client::new(&api_key);

        // Use ResponsesCompletionModel for newer models
        if model_name.starts_with("gpt-5") || model_name.starts_with("o") {
            Ok(RigProvider::OpenAIResponses(client))
        } else {
            Ok(RigProvider::OpenAI(client))
        }
    } else if is_claude_model(model_name) {
        let api_key = config.api_key.clone()
            .or_else(|| std::env::var("ANTHROPIC_API_KEY").ok())
            .ok_or_else(|| EbiError::LlmClientError("Anthropic API key not found".to_string()))?;

        let client = anthropic::Client::new(&api_key);
        Ok(RigProvider::Anthropic(client))
    } else if is_gemini_model(model_name) {
        let api_key = config.api_key.clone()
            .or_else(|| std::env::var("GEMINI_API_KEY").ok())
            .ok_or_else(|| EbiError::LlmClientError("Gemini API key not found".to_string()))?;

        let client = gemini::Client::new(&api_key);
        Ok(RigProvider::Gemini(client))
    } else {
        Err(EbiError::LlmClientError(format!(
            "Unsupported model '{}'. Use OpenAI (gpt-*), Anthropic (claude-*), or Gemini (gemini-*) models",
            model_name
        )))
    }
}

pub fn create_llm_client(
    model: &str,
    api_key: Option<String>,
    timeout_seconds: u64,
) -> Result<Box<dyn LlmProvider + Send + Sync>, EbiError> {
    let config = LlmConfig {
        model_name: model.to_string(),
        api_key,
        timeout_seconds,
        max_retries: 3,
        max_tokens: Some(1000),
        temperature: Some(0.3),
    };

    let client = RigLlmClient::new(config)?;
    Ok(Box::new(client))
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
        assert!(prompt.contains("SECURITY VULNERABILITY ANALYSIS"));
        assert!(prompt.contains("LEGITIMACY ASSESSMENT"));
    }

    #[test]
    fn test_response_parsing() {
        let response = "Risk Level: HIGH\nThis script contains potential vulnerabilities including command injection.";
        let (risk_level, summary, confidence) =
            RigLlmClient::parse_analysis_response(response);

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
    fn test_model_detection() {
        assert!(is_openai_model("gpt-4"));
        assert!(is_openai_model("gpt-4o"));
        assert!(is_openai_model("o1-mini"));
        assert!(is_openai_model("o3-preview"));

        assert!(is_claude_model("claude-3.5-sonnet"));
        assert!(is_claude_model("claude-3-opus"));
        assert!(is_claude_model("anthropic/claude-3.5-sonnet"));

        assert!(is_gemini_model("gemini-pro"));
        assert!(is_gemini_model("gemini-1.5-pro"));
        assert!(is_gemini_model("gemini/gemini-2.5-flash"));
    }

    #[test]
    fn test_claude_response_parsing() {
        let response = "Risk Level: HIGH\nThis script contains potential vulnerabilities including command injection.";
        let (risk_level, summary, confidence) =
            RigLlmClient::parse_analysis_response(response);

        assert_eq!(risk_level, crate::models::RiskLevel::High);
        assert!(summary.contains("vulnerabilities"));
        assert!(confidence > 0.5);
    }

    #[test]
    fn test_gemini_response_parsing() {
        let response = "Risk Level: HIGH\nThis script contains potential vulnerabilities including command injection.";
        let (risk_level, summary, confidence) = RigLlmClient::parse_analysis_response(response);

        assert_eq!(risk_level, crate::models::RiskLevel::High);
        assert!(summary.contains("vulnerabilities"));
        assert!(confidence > 0.5);
    }
}