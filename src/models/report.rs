use crate::models::analysis::{AnalysisResult, RiskLevel};
use crate::models::script::Language;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub script_info: ScriptInfo,
    pub overall_risk: RiskLevel,
    pub injection_analysis: Option<AnalysisResult>,
    pub code_analysis: Option<AnalysisResult>,
    pub execution_recommendation: ExecutionRecommendation,
    pub execution_advice: Option<String>,
    pub warnings: Vec<String>,
    pub risk_explanation: Option<String>,
    pub mitigation_suggestions: Vec<String>,
    pub analysis_summary: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScriptInfo {
    pub language: Language,
    pub size_bytes: usize,
    pub line_count: usize,
    pub detected_type: String, // e.g., "Installation Script"
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ExecutionRecommendation {
    Safe,      // Low risk, likely safe
    Caution,   // Medium risk, review carefully
    Dangerous, // High risk, not recommended
    Blocked,   // Critical risk or analysis failure
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecutionDecision {
    pub proceed: bool,
    pub timestamp: SystemTime,
    pub analysis_report_hash: String, // For audit trail
}

impl AnalysisReport {
    pub fn new(script_info: ScriptInfo) -> Self {
        Self {
            script_info,
            overall_risk: RiskLevel::None,
            injection_analysis: None,
            code_analysis: None,
            execution_recommendation: ExecutionRecommendation::Safe,
            execution_advice: None,
            warnings: Vec::new(),
            risk_explanation: None,
            mitigation_suggestions: Vec::new(),
            analysis_summary: String::new(),
        }
    }

    pub fn with_injection_analysis(mut self, analysis: AnalysisResult) -> Self {
        self.injection_analysis = Some(analysis);
        self.update_overall_assessment();
        self
    }

    pub fn with_code_analysis(mut self, analysis: AnalysisResult) -> Self {
        self.code_analysis = Some(analysis);
        self.update_overall_assessment();
        self
    }

    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }

    pub fn update_overall_assessment(&mut self) {
        // Calculate overall risk from both analyses
        let mut max_risk = RiskLevel::None;

        if let Some(ref injection) = self.injection_analysis {
            if injection.risk_level > max_risk {
                max_risk = injection.risk_level.clone();
            }
        }

        if let Some(ref code) = self.code_analysis {
            if code.risk_level > max_risk {
                max_risk = code.risk_level.clone();
            }
        }

        self.overall_risk = max_risk.clone();

        // Set execution recommendation based on overall risk
        self.execution_recommendation = match max_risk {
            RiskLevel::None | RiskLevel::Info => ExecutionRecommendation::Safe,
            RiskLevel::Low => ExecutionRecommendation::Safe,
            RiskLevel::Medium => ExecutionRecommendation::Caution,
            RiskLevel::High => ExecutionRecommendation::Dangerous,
            RiskLevel::Critical => ExecutionRecommendation::Blocked,
        };
    }

    pub fn should_block_execution(&self) -> bool {
        matches!(
            self.execution_recommendation,
            ExecutionRecommendation::Blocked
        )
    }

    pub fn has_analysis_results(&self) -> bool {
        self.injection_analysis.is_some() || self.code_analysis.is_some()
    }

    pub fn get_all_findings(&self) -> Vec<&crate::models::analysis::Finding> {
        let mut findings = Vec::new();

        if let Some(ref injection) = self.injection_analysis {
            findings.extend(&injection.findings);
        }

        if let Some(ref code) = self.code_analysis {
            findings.extend(&code.findings);
        }

        findings
    }

    pub fn generate_summary(&self) -> String {
        let mut summary = String::new();

        // Basic script info
        summary.push_str(&format!(
            "Script Type: {} Script\n",
            match self.script_info.language {
                Language::Bash => "Bash",
                Language::Python => "Python",
                Language::Unknown => "Unknown",
            }
        ));

        summary.push_str(&format!(
            "Size: {} bytes, {} lines\n",
            self.script_info.size_bytes, self.script_info.line_count
        ));

        summary.push_str(&format!("Risk Level: {}\n", self.overall_risk.as_str()));

        // Analysis summaries
        if let Some(ref code) = self.code_analysis {
            summary.push_str(&format!("\n▶ CODE ANALYSIS\n{}\n", code.summary));
        }

        if let Some(ref injection) = self.injection_analysis {
            summary.push_str(&format!("\n▶ INJECTION ANALYSIS\n{}\n", injection.summary));
        }

        // Warnings
        if !self.warnings.is_empty() {
            summary.push_str("\n⚠️ WARNINGS:\n");
            for warning in &self.warnings {
                summary.push_str(&format!("- {}\n", warning));
            }
        }

        summary
    }
}

impl ScriptInfo {
    pub fn new(language: Language, size_bytes: usize, line_count: usize) -> Self {
        let detected_type = Self::detect_script_type(size_bytes, line_count);

        Self {
            language,
            size_bytes,
            line_count,
            detected_type,
        }
    }

    fn detect_script_type(size_bytes: usize, line_count: usize) -> String {
        if size_bytes > 10_000 || line_count > 500 {
            "Large Script".to_string()
        } else if line_count < 10 {
            "Simple Script".to_string()
        } else {
            "Regular Script".to_string()
        }
    }

    pub fn with_detected_type(mut self, script_type: String) -> Self {
        self.detected_type = script_type;
        self
    }
}

impl ExecutionRecommendation {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExecutionRecommendation::Safe => "SAFE",
            ExecutionRecommendation::Caution => "CAUTION",
            ExecutionRecommendation::Dangerous => "DANGEROUS",
            ExecutionRecommendation::Blocked => "BLOCKED",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            ExecutionRecommendation::Safe => "Low risk, likely safe to execute",
            ExecutionRecommendation::Caution => "Medium risk, review carefully before executing",
            ExecutionRecommendation::Dangerous => "High risk, execution not recommended",
            ExecutionRecommendation::Blocked => {
                "Critical risk or analysis failure, execution blocked"
            }
        }
    }

    pub fn should_prompt_user(&self) -> bool {
        !matches!(self, ExecutionRecommendation::Blocked)
    }
}

impl fmt::Display for ExecutionRecommendation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.description())
    }
}

impl ExecutionDecision {
    pub fn new(proceed: bool, analysis_report: &AnalysisReport) -> Self {
        // Create a simple hash of the report for audit trail
        let mut hasher = DefaultHasher::new();
        analysis_report.overall_risk.as_str().hash(&mut hasher);
        analysis_report
            .script_info
            .language
            .as_str()
            .hash(&mut hasher);
        analysis_report.script_info.size_bytes.hash(&mut hasher);
        analysis_report.script_info.line_count.hash(&mut hasher);
        if !analysis_report.analysis_summary.is_empty() {
            analysis_report.analysis_summary.hash(&mut hasher);
        }

        let report_hash = format!("{:016x}", hasher.finish());

        Self {
            proceed,
            timestamp: SystemTime::now(),
            analysis_report_hash: report_hash,
        }
    }

    pub fn proceed() -> Self {
        Self {
            proceed: true,
            timestamp: SystemTime::now(),
            analysis_report_hash: "manual-proceed".to_string(),
        }
    }

    pub fn decline() -> Self {
        Self {
            proceed: false,
            timestamp: SystemTime::now(),
            analysis_report_hash: "manual-decline".to_string(),
        }
    }
}

impl std::fmt::Display for AnalysisReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "═══════════════════════════════════════════════════════════\n"
        )?;
        write!(f, "🦐 EBI SECURITY ANALYSIS REPORT 🍤\n")?;
        write!(
            f,
            "═══════════════════════════════════════════════════════════\n\n"
        )?;

        write!(f, "{}", self.generate_summary())?;

        write!(
            f,
            "\n═══════════════════════════════════════════════════════════\n"
        )?;

        if self.should_block_execution() {
            write!(f, "❌ EXECUTION BLOCKED DUE TO SECURITY CONCERNS\n")?;
        } else {
            write!(f, "Execute this script? (yes/no): ")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::analysis::{AnalysisResult, AnalysisType};
    use crate::ExecutionConfig;

    #[test]
    fn test_analysis_report_creation() {
        let script_info = ScriptInfo::new(Language::Bash, 100, 5);
        let report = AnalysisReport::new(script_info);

        assert_eq!(report.overall_risk, RiskLevel::None);
        assert_eq!(
            report.execution_recommendation,
            ExecutionRecommendation::Safe
        );
        assert!(!report.has_analysis_results());
    }

    #[test]
    fn test_analysis_report_risk_calculation() {
        let script_info = ScriptInfo::new(Language::Bash, 100, 5);
        let mut report = AnalysisReport::new(script_info);

        // Add medium risk code analysis
        let code_analysis =
            AnalysisResult::new(AnalysisType::CodeVulnerability, "gpt-4".to_string(), 1000)
                .with_risk_level(RiskLevel::Medium);

        report = report.with_code_analysis(code_analysis);

        assert_eq!(report.overall_risk, RiskLevel::Medium);
        assert_eq!(
            report.execution_recommendation,
            ExecutionRecommendation::Caution
        );

        // Add high risk injection analysis - should override
        let injection_analysis =
            AnalysisResult::new(AnalysisType::InjectionDetection, "gpt-4".to_string(), 800)
                .with_risk_level(RiskLevel::High);

        report = report.with_injection_analysis(injection_analysis);

        assert_eq!(report.overall_risk, RiskLevel::High);
        assert_eq!(
            report.execution_recommendation,
            ExecutionRecommendation::Dangerous
        );
    }

    #[test]
    fn test_execution_decision() {
        let script_info = ScriptInfo::new(Language::Python, 50, 3);
        let report = AnalysisReport::new(script_info);

        let decision = ExecutionDecision::new(true, &report);
        assert!(decision.proceed);
        assert!(!decision.analysis_report_hash.is_empty());
    }

    #[test]
    fn test_execution_config() {
        let config = ExecutionConfig::new(
            "python".to_string(),
            vec!["-c".to_string()],
            "print('hello')".to_string(),
        );

        let command = config.get_full_command();
        assert_eq!(command, "python -c");
    }

    #[test]
    fn test_script_info_type_detection() {
        let small_script = ScriptInfo::new(Language::Bash, 50, 3);
        assert_eq!(small_script.detected_type, "Simple Script");

        let large_script = ScriptInfo::new(Language::Bash, 20000, 1000);
        assert_eq!(large_script.detected_type, "Large Script");

        let regular_script = ScriptInfo::new(Language::Bash, 500, 50);
        assert_eq!(regular_script.detected_type, "Regular Script");
    }
}
