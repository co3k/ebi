use crate::error::EbiError;
use crate::localization::locale::LocalizedMessages;
use crate::models::{
    AnalysisReport, AnalysisResult, AnalysisType, OutputLanguage, RiskLevel, ScriptComponents,
    ScriptInfo, SecurityRelevance,
};
use crate::parser::SecurityClassifier;

#[derive(Clone, Copy, PartialEq, Eq)]
enum LegitimacyHint {
    Legitimate,
    Suspicious,
    Unknown,
}

pub struct AnalysisAggregator {
    classifier: SecurityClassifier,
}

impl AnalysisAggregator {
    pub fn new() -> Self {
        Self {
            classifier: SecurityClassifier::new(),
        }
    }

    pub fn aggregate_analysis_results(
        &self,
        results: Vec<AnalysisResult>,
        script_info: ScriptInfo,
        components: &ScriptComponents,
        output_language: &OutputLanguage,
    ) -> Result<AnalysisReport, EbiError> {
        if results.is_empty() {
            return Err(EbiError::LlmClientError(
                "No analysis results to aggregate".to_string(),
            ));
        }

        // Create the base report
        let mut report = AnalysisReport::new(script_info);

        // Separate results by analysis type
        let (code_results, injection_results): (Vec<_>, Vec<_>) = results
            .into_iter()
            .partition(|r| matches!(r.analysis_type, AnalysisType::CodeVulnerability));

        // Aggregate code vulnerability analysis
        if let Some(code_result) = self.aggregate_code_analysis(code_results)? {
            report = report.with_code_analysis(code_result);
        }

        // Aggregate injection detection analysis
        if let Some(injection_result) = self.aggregate_injection_analysis(injection_results)? {
            report = report.with_injection_analysis(injection_result);
        }

        // Calculate overall risk level
        let overall_risk = self.calculate_overall_risk(&report, components);
        report.overall_risk = overall_risk;

        // Add risk explanations and recommendations
        report = self.enrich_report_with_insights(report, components, output_language);

        Ok(report)
    }

    fn aggregate_code_analysis(
        &self,
        results: Vec<AnalysisResult>,
    ) -> Result<Option<AnalysisResult>, EbiError> {
        if results.is_empty() {
            return Ok(None);
        }

        if results.len() == 1 {
            return Ok(Some(results.into_iter().next().unwrap()));
        }

        // Aggregate multiple code analysis results
        let highest_risk = results
            .iter()
            .map(|r| &r.risk_level)
            .max()
            .unwrap_or(&RiskLevel::Info);

        let total_duration: u64 = results.iter().map(|r| r.analysis_duration_ms).sum();

        let average_confidence =
            results.iter().map(|r| r.confidence).sum::<f32>() / results.len() as f32;

        // Combine summaries
        let combined_summary = results
            .iter()
            .map(|r| r.summary.clone())
            .collect::<Vec<_>>()
            .join(" | ");

        // Combine details
        let combined_details = results
            .iter()
            .enumerate()
            .map(|(i, r)| {
                format!(
                    "Analysis {}: {}",
                    i + 1,
                    r.details.as_deref().unwrap_or("No details available")
                )
            })
            .collect::<Vec<_>>()
            .join("\n\n");

        let aggregated = AnalysisResult::new(
            AnalysisType::CodeVulnerability,
            results[0].model_used.clone(),
            total_duration,
        )
        .with_risk_level(highest_risk.clone())
        .with_summary(combined_summary)
        .with_confidence(average_confidence)
        .with_details(combined_details);

        Ok(Some(aggregated))
    }

    fn aggregate_injection_analysis(
        &self,
        results: Vec<AnalysisResult>,
    ) -> Result<Option<AnalysisResult>, EbiError> {
        if results.is_empty() {
            return Ok(None);
        }

        if results.len() == 1 {
            return Ok(Some(results.into_iter().next().unwrap()));
        }

        // Similar aggregation logic as code analysis
        let highest_risk = results
            .iter()
            .map(|r| &r.risk_level)
            .max()
            .unwrap_or(&RiskLevel::Info);

        let total_duration: u64 = results.iter().map(|r| r.analysis_duration_ms).sum();

        let average_confidence =
            results.iter().map(|r| r.confidence).sum::<f32>() / results.len() as f32;

        let combined_summary = results
            .iter()
            .map(|r| r.summary.clone())
            .collect::<Vec<_>>()
            .join(" | ");

        let combined_details = results
            .iter()
            .enumerate()
            .map(|(i, r)| {
                format!(
                    "Injection Analysis {}: {}",
                    i + 1,
                    r.details.as_deref().unwrap_or("No details available")
                )
            })
            .collect::<Vec<_>>()
            .join("\n\n");

        let aggregated = AnalysisResult::new(
            AnalysisType::InjectionDetection,
            results[0].model_used.clone(),
            total_duration,
        )
        .with_risk_level(highest_risk.clone())
        .with_summary(combined_summary)
        .with_confidence(average_confidence)
        .with_details(combined_details);

        Ok(Some(aggregated))
    }

    fn calculate_overall_risk(
        &self,
        report: &AnalysisReport,
        components: &ScriptComponents,
    ) -> RiskLevel {
        let mut llm_risks = Vec::new();
        let mut legitimacy_hints = Vec::new();

        if let Some(ref code_analysis) = report.code_analysis {
            llm_risks.push(code_analysis.risk_level.clone());
            if let Some(hint) =
                detect_legitimacy_hint(&code_analysis.summary, code_analysis.details.as_ref())
            {
                legitimacy_hints.push(hint);
            }
        }

        if let Some(ref injection_analysis) = report.injection_analysis {
            llm_risks.push(injection_analysis.risk_level.clone());
            if let Some(hint) = detect_legitimacy_hint(
                &injection_analysis.summary,
                injection_analysis.details.as_ref(),
            ) {
                legitimacy_hints.push(hint);
            }
        }

        let llm_risk = llm_risks.into_iter().max().unwrap_or(RiskLevel::Info);

        let combined_legitimacy = combine_legitimacy_hints(&legitimacy_hints);

        let static_relevance = self
            .classifier
            .classify_script_overall_risk(&components.metadata.priority_nodes);
        let static_risk = self.map_security_to_risk(static_relevance);

        let adjusted_static_risk =
            if matches!(combined_legitimacy, Some(LegitimacyHint::Legitimate)) {
                std::cmp::min(static_risk, RiskLevel::Low)
            } else {
                static_risk
            };

        let mut overall = std::cmp::max(llm_risk.clone(), adjusted_static_risk);

        if matches!(combined_legitimacy, Some(LegitimacyHint::Legitimate)) {
            overall = std::cmp::min(overall, RiskLevel::Medium);
        }

        if llm_risk <= RiskLevel::Low {
            overall = std::cmp::min(overall, RiskLevel::Medium);
        }

        overall
    }

    fn enrich_report_with_insights(
        &self,
        mut report: AnalysisReport,
        components: &ScriptComponents,
        output_language: &OutputLanguage,
    ) -> AnalysisReport {
        // Add execution recommendation
        let (recommendation, advice) =
            LocalizedMessages::get_execution_guidance(&report.overall_risk, output_language);
        report.execution_recommendation = recommendation;
        report.execution_advice = Some(advice);

        // Add risk explanation
        let relevance = self.map_risk_to_relevance(&report.overall_risk);
        let risk_explanation = LocalizedMessages::get_risk_explanation(&relevance, output_language);
        report.risk_explanation = Some(risk_explanation.to_string());

        // Add mitigation suggestions
        let suggestions = self
            .classifier
            .get_risk_mitigation_suggestions(&components.metadata.priority_nodes);
        report.mitigation_suggestions = suggestions;

        // Add summary statistics
        report.analysis_summary =
            self.generate_analysis_summary(&report, components, output_language);

        report
    }

    fn map_security_to_risk(&self, relevance: SecurityRelevance) -> RiskLevel {
        match relevance {
            SecurityRelevance::Critical => RiskLevel::Critical,
            SecurityRelevance::High => RiskLevel::High,
            SecurityRelevance::Medium => RiskLevel::Medium,
            SecurityRelevance::Low => RiskLevel::Low,
        }
    }

    fn map_risk_to_relevance(&self, risk: &RiskLevel) -> SecurityRelevance {
        match risk {
            RiskLevel::Critical => SecurityRelevance::Critical,
            RiskLevel::High => SecurityRelevance::High,
            RiskLevel::Medium => SecurityRelevance::Medium,
            RiskLevel::Low | RiskLevel::Info | RiskLevel::None => SecurityRelevance::Low,
        }
    }

    fn generate_analysis_summary(
        &self,
        report: &AnalysisReport,
        components: &ScriptComponents,
        output_language: &OutputLanguage,
    ) -> String {
        let mut summary_parts = Vec::new();

        // Script overview
        summary_parts.push(LocalizedMessages::format_analysis_summary(
            report.script_info.language.as_str(),
            report.script_info.line_count,
            report.script_info.size_bytes,
            output_language,
        ));

        // Static analysis summary
        let critical_nodes = components.get_critical_nodes().len();
        let high_risk_nodes = components.get_high_risk_nodes().len();

        if let Some(static_summary) = LocalizedMessages::format_static_analysis_summary(
            critical_nodes,
            high_risk_nodes,
            output_language,
        ) {
            summary_parts.push(static_summary);
        }

        // LLM analysis summary
        let mut llm_analyses = Vec::new();
        if let Some(ref code_analysis) = report.code_analysis {
            llm_analyses.push(LocalizedMessages::format_code_vulnerability_analysis(
                code_analysis.risk_level.as_str(),
                code_analysis.confidence,
                output_language,
            ));
        }

        if let Some(ref injection_analysis) = report.injection_analysis {
            llm_analyses.push(LocalizedMessages::format_injection_detection(
                injection_analysis.risk_level.as_str(),
                injection_analysis.confidence,
                output_language,
            ));
        }

        if !llm_analyses.is_empty() {
            summary_parts.push(llm_analyses.join(", "));
        }

        // Overall assessment
        summary_parts.push(LocalizedMessages::format_overall_risk_assessment(
            report.overall_risk.as_str(),
            output_language,
        ));

        summary_parts.join("\n")
    }

    pub fn validate_analysis_quality(&self, results: &[AnalysisResult]) -> Vec<String> {
        let mut warnings = Vec::new();

        for (i, result) in results.iter().enumerate() {
            // Check confidence levels
            if result.confidence < 0.5 {
                warnings.push(format!(
                    "Analysis {}: Low confidence ({:.1}%) - results may be unreliable",
                    i + 1,
                    result.confidence * 100.0
                ));
            }

            // Check for very short summaries
            if result.summary.len() < 20 {
                warnings.push(format!(
                    "Analysis {}: Summary appears too brief - may indicate analysis issues",
                    i + 1
                ));
            }

            // Check for analysis timeouts or errors in details
            if let Some(ref details) = result.details {
                if details.to_lowercase().contains("timeout")
                    || details.to_lowercase().contains("error")
                {
                    warnings.push(format!(
                        "Analysis {}: May have encountered issues during processing",
                        i + 1
                    ));
                }
            }
        }

        warnings
    }
}

fn combine_legitimacy_hints(hints: &[LegitimacyHint]) -> Option<LegitimacyHint> {
    if hints.is_empty() {
        return None;
    }

    if hints.contains(&LegitimacyHint::Suspicious) {
        Some(LegitimacyHint::Suspicious)
    } else if hints.contains(&LegitimacyHint::Legitimate) {
        Some(LegitimacyHint::Legitimate)
    } else if hints.contains(&LegitimacyHint::Unknown) {
        Some(LegitimacyHint::Unknown)
    } else {
        None
    }
}

fn detect_legitimacy_hint(summary: &str, details: Option<&String>) -> Option<LegitimacyHint> {
    if let Some(hint) = parse_legitimacy_from_text(summary) {
        return Some(hint);
    }

    if let Some(details_text) = details {
        if let Some(hint) = parse_legitimacy_from_text(details_text) {
            return Some(hint);
        }
    }

    None
}

fn parse_legitimacy_from_text(text: &str) -> Option<LegitimacyHint> {
    for line in text.lines() {
        if let Some(hint) = parse_legitimacy_from_line(line) {
            return Some(hint);
        }
    }

    // Fallback to whole-text search in case formatting removes line breaks
    let lower = text.to_lowercase();
    if lower.contains("legitimacy assessment") {
        if lower.contains("suspicious") {
            return Some(LegitimacyHint::Suspicious);
        }
        if lower.contains("legitimate") {
            return Some(LegitimacyHint::Legitimate);
        }
        if lower.contains("unknown") {
            return Some(LegitimacyHint::Unknown);
        }
    }

    if text.contains("正当性評価") || text.contains("正当性判定") {
        if text.contains("不審") || text.contains("疑わしい") {
            return Some(LegitimacyHint::Suspicious);
        }
        if text.contains("正当") {
            return Some(LegitimacyHint::Legitimate);
        }
        if text.contains("不明") {
            return Some(LegitimacyHint::Unknown);
        }
    }

    if text.contains("正当") && !text.contains("不正") {
        return Some(LegitimacyHint::Legitimate);
    }

    None
}

fn parse_legitimacy_from_line(line: &str) -> Option<LegitimacyHint> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    let lower = trimmed.to_lowercase();
    if lower.starts_with("legitimacy assessment") {
        if lower.contains("suspicious") {
            Some(LegitimacyHint::Suspicious)
        } else if lower.contains("legitimate") {
            Some(LegitimacyHint::Legitimate)
        } else if lower.contains("unknown") {
            Some(LegitimacyHint::Unknown)
        } else {
            None
        }
    } else if trimmed.starts_with("正当性評価") || trimmed.starts_with("正当性判定") {
        if trimmed.contains("不審") || trimmed.contains("疑わしい") {
            Some(LegitimacyHint::Suspicious)
        } else if trimmed.contains("正当") {
            Some(LegitimacyHint::Legitimate)
        } else if trimmed.contains("不明") {
            Some(LegitimacyHint::Unknown)
        } else {
            None
        }
    } else if lower.contains("legitimate") && !lower.contains("suspicious") {
        Some(LegitimacyHint::Legitimate)
    } else if lower.contains("suspicious") {
        Some(LegitimacyHint::Suspicious)
    } else if trimmed.contains("正当") && !trimmed.contains("疑わしい") {
        Some(LegitimacyHint::Legitimate)
    } else if trimmed.contains("疑わしい") || trimmed.contains("不審") {
        Some(LegitimacyHint::Suspicious)
    } else {
        None
    }
}

impl Default for AnalysisAggregator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::components::{NodeInfo, SecurityRelevance};
    use crate::models::{
        AnalysisResult, AnalysisType, ExecutionRecommendation, Language, RiskLevel,
        ScriptComponents, ScriptInfo,
    };

    #[test]
    fn test_risk_calculation() {
        let aggregator = AnalysisAggregator::new();

        let script_info = ScriptInfo::new(Language::Bash, 100, 5);
        let components = ScriptComponents::new();

        let report = AnalysisReport::new(script_info);
        let risk = aggregator.calculate_overall_risk(&report, &components);

        // Empty analysis should result in low risk
        assert_eq!(risk, RiskLevel::Low);
    }

    #[test]
    fn test_execution_recommendation() {
        let aggregator = AnalysisAggregator::new();
        let script_info = ScriptInfo::new(Language::Bash, 100, 5);
        let components = ScriptComponents::new();

        let mut report = AnalysisReport::new(script_info);
        report.overall_risk = RiskLevel::Critical;

        use crate::localization::locale::LocalizedMessages;
        let (recommendation, advice) = LocalizedMessages::get_execution_guidance(
            &report.overall_risk,
            &OutputLanguage::English,
        );
        assert_eq!(recommendation, ExecutionRecommendation::Blocked);
        assert!(advice.contains("BLOCK EXECUTION"));
    }

    #[test]
    fn test_analysis_quality_validation() {
        let aggregator = AnalysisAggregator::new();

        let low_confidence_result = AnalysisResult::new(
            AnalysisType::CodeVulnerability,
            "test-model".to_string(),
            1000,
        )
        .with_confidence(0.3) // Low confidence
        .with_summary("Bad".to_string()); // Short summary

        let warnings = aggregator.validate_analysis_quality(&[low_confidence_result]);

        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.contains("Low confidence")));
        assert!(warnings.iter().any(|w| w.contains("too brief")));
    }

    #[test]
    fn test_low_llm_risk_limits_static_risk() {
        let aggregator = AnalysisAggregator::new();

        let script_info = ScriptInfo::new(Language::Bash, 100, 40);
        let mut components = ScriptComponents::new();
        components.metadata.priority_nodes.push(NodeInfo {
            node_type: "command_substitution".to_string(),
            line_start: 12,
            line_end: 12,
            security_relevance: SecurityRelevance::Critical,
        });

        let code_result = AnalysisResult::new(
            AnalysisType::CodeVulnerability,
            "test-model".to_string(),
            100,
        )
        .with_risk_level(RiskLevel::Info)
        .with_summary("No significant security concerns identified.".to_string())
        .with_confidence(0.6);

        let injection_result = AnalysisResult::new(
            AnalysisType::InjectionDetection,
            "test-model".to_string(),
            120,
        )
        .with_risk_level(RiskLevel::Info)
        .with_summary("No injection or social-engineering risks identified.".to_string())
        .with_confidence(0.6);

        let report = AnalysisReport::new(script_info)
            .with_code_analysis(code_result)
            .with_injection_analysis(injection_result);

        let overall = aggregator.calculate_overall_risk(&report, &components);

        assert!(overall <= RiskLevel::Medium);
    }
}
