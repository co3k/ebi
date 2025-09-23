use serde::{Deserialize, Serialize};
use crate::models::{Language, OutputLanguage};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalysisRequest {
    pub analysis_type: AnalysisType,
    pub content: String,
    pub context: AnalysisContext,
    pub model: String,
    pub timeout_seconds: u64,
    pub output_language: OutputLanguage,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AnalysisType {
    InjectionDetection,  // For comments/strings
    CodeVulnerability,   // For code body
    DetailedRiskAnalysis, // Comprehensive risk breakdown for high-risk scripts
    SpecificThreatAnalysis, // Line-by-line threat analysis
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalysisContext {
    pub language: Language,
    pub source: crate::models::ScriptSource,
    pub script_type: Option<String>, // e.g., "installer", "config"
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub analysis_type: AnalysisType,
    pub risk_level: RiskLevel,
    pub summary: String,
    pub details: Option<String>,
    pub findings: Vec<Finding>,
    pub confidence: f32,
    pub model_used: String,
    pub analysis_duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    None,
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub description: String,
    pub severity: RiskLevel,
    pub location: Option<String>, // Line numbers or code snippet
    pub recommendation: Option<String>,
}

impl AnalysisRequest {
    pub fn new_code_analysis(
        content: String,
        language: Language,
        model: String,
        timeout_seconds: u64,
    ) -> Self {
        Self {
            analysis_type: AnalysisType::CodeVulnerability,
            content,
            context: AnalysisContext {
                language,
                source: crate::models::ScriptSource::Stdin,
                script_type: None,
                truncated: false,
            },
            model,
            timeout_seconds,
            output_language: OutputLanguage::English,
        }
    }

    pub fn new_injection_analysis(
        content: String,
        language: Language,
        model: String,
        timeout_seconds: u64,
    ) -> Self {
        Self {
            analysis_type: AnalysisType::InjectionDetection,
            content,
            context: AnalysisContext {
                language,
                source: crate::models::ScriptSource::Stdin,
                script_type: None,
                truncated: false,
            },
            model,
            timeout_seconds,
            output_language: OutputLanguage::English,
        }
    }

    pub fn with_script_type(mut self, script_type: String) -> Self {
        self.context.script_type = Some(script_type);
        self
    }

    pub fn mark_truncated(mut self) -> Self {
        self.context.truncated = true;
        self
    }

    pub fn is_empty(&self) -> bool {
        self.content.trim().is_empty()
    }

    pub fn content_size(&self) -> usize {
        self.content.len()
    }
}

impl AnalysisResult {
    pub fn new(
        analysis_type: AnalysisType,
        model_used: String,
        analysis_duration_ms: u64,
    ) -> Self {
        Self {
            analysis_type,
            risk_level: RiskLevel::None,
            summary: String::new(),
            details: None,
            findings: Vec::new(),
            confidence: 0.0,
            model_used,
            analysis_duration_ms,
        }
    }

    pub fn with_risk_level(mut self, risk_level: RiskLevel) -> Self {
        self.risk_level = risk_level;
        self
    }

    pub fn with_summary(mut self, summary: String) -> Self {
        self.summary = summary;
        self
    }

    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    pub fn with_details<S: Into<String>>(mut self, details: S) -> Self {
        self.details = Some(details.into());
        self
    }

    pub fn add_finding(&mut self, finding: Finding) {
        // Update overall risk level if this finding is more severe
        if finding.severity > self.risk_level {
            self.risk_level = finding.severity.clone();
        }
        self.findings.push(finding);
    }

    pub fn has_high_risk_findings(&self) -> bool {
        self.findings.iter().any(|f| matches!(
            f.severity,
            RiskLevel::High | RiskLevel::Critical
        ))
    }

    pub fn is_valid(&self) -> bool {
        !self.summary.is_empty() && self.confidence > 0.0
    }
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::None => "NONE",
            RiskLevel::Info => "INFO",
            RiskLevel::Low => "LOW",
            RiskLevel::Medium => "MEDIUM",
            RiskLevel::High => "HIGH",
            RiskLevel::Critical => "CRITICAL",
        }
    }

    pub fn as_emoji(&self) -> &'static str {
        match self {
            RiskLevel::None => "✅",
            RiskLevel::Info => "ℹ️",
            RiskLevel::Low => "⚠️",
            RiskLevel::Medium => "🔶",
            RiskLevel::High => "⚠️",
            RiskLevel::Critical => "🚨",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "none" => Some(RiskLevel::None),
            "info" => Some(RiskLevel::Info),
            "low" => Some(RiskLevel::Low),
            "medium" => Some(RiskLevel::Medium),
            "high" => Some(RiskLevel::High),
            "critical" => Some(RiskLevel::Critical),
            _ => None,
        }
    }

    pub fn numeric_value(&self) -> u8 {
        match self {
            RiskLevel::None => 0,
            RiskLevel::Info => 1,
            RiskLevel::Low => 2,
            RiskLevel::Medium => 3,
            RiskLevel::High => 4,
            RiskLevel::Critical => 5,
        }
    }
}

impl PartialOrd for RiskLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.numeric_value().cmp(&other.numeric_value()))
    }
}

impl Ord for RiskLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.numeric_value().cmp(&other.numeric_value())
    }
}

impl AnalysisType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AnalysisType::InjectionDetection => "injection_detection",
            AnalysisType::CodeVulnerability => "code_vulnerability",
            AnalysisType::DetailedRiskAnalysis => "detailed_risk_analysis",
            AnalysisType::SpecificThreatAnalysis => "specific_threat_analysis",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            AnalysisType::InjectionDetection => "Prompt injection and hidden instruction analysis",
            AnalysisType::CodeVulnerability => "Code vulnerability and security analysis",
            AnalysisType::DetailedRiskAnalysis => "Comprehensive risk breakdown for high-risk scripts",
            AnalysisType::SpecificThreatAnalysis => "Line-by-line threat analysis",
        }
    }
}

impl Finding {
    pub fn new(description: String, severity: RiskLevel) -> Self {
        Self {
            description,
            severity,
            location: None,
            recommendation: None,
        }
    }

    pub fn with_location(mut self, location: String) -> Self {
        self.location = Some(location);
        self
    }

    pub fn with_recommendation(mut self, recommendation: String) -> Self {
        self.recommendation = Some(recommendation);
        self
    }

    pub fn is_actionable(&self) -> bool {
        self.recommendation.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_request_creation() {
        let request = AnalysisRequest::new_code_analysis(
            "echo test".to_string(),
            Language::Bash,
            "gpt-4".to_string(),
            60,
        );

        assert_eq!(request.analysis_type, AnalysisType::CodeVulnerability);
        assert_eq!(request.content, "echo test");
        assert!(!request.is_empty());
    }

    #[test]
    fn test_analysis_result_risk_level_update() {
        let mut result = AnalysisResult::new(
            AnalysisType::CodeVulnerability,
            "gpt-4".to_string(),
            1000,
        );

        // Start with no risk
        assert_eq!(result.risk_level, RiskLevel::None);

        // Add a medium risk finding
        result.add_finding(Finding::new(
            "Potential issue".to_string(),
            RiskLevel::Medium,
        ));
        assert_eq!(result.risk_level, RiskLevel::Medium);

        // Add a high risk finding - should update overall risk
        result.add_finding(Finding::new(
            "Serious issue".to_string(),
            RiskLevel::High,
        ));
        assert_eq!(result.risk_level, RiskLevel::High);

        assert!(result.has_high_risk_findings());
    }

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Critical > RiskLevel::High);
        assert!(RiskLevel::High > RiskLevel::Medium);
        assert!(RiskLevel::Medium > RiskLevel::Low);
        assert!(RiskLevel::Low > RiskLevel::Info);
        assert!(RiskLevel::Info > RiskLevel::None);
    }

    #[test]
    fn test_risk_level_str_conversion() {
        assert_eq!(RiskLevel::Critical.as_str(), "CRITICAL");
        assert_eq!(RiskLevel::from_str("high"), Some(RiskLevel::High));
        assert_eq!(RiskLevel::from_str("unknown"), None);
    }

    #[test]
    fn test_finding_creation() {
        let finding = Finding::new("Test issue".to_string(), RiskLevel::Medium)
            .with_location("line 42".to_string())
            .with_recommendation("Fix this".to_string());

        assert_eq!(finding.description, "Test issue");
        assert_eq!(finding.severity, RiskLevel::Medium);
        assert!(finding.is_actionable());
    }
}
