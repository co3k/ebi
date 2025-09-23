use crate::models::{
    AnalysisResult, AnalysisReport, RiskLevel, AnalysisType,
    ScriptInfo, ScriptComponents, ExecutionRecommendation, SecurityRelevance,
};
use crate::parser::SecurityClassifier;
use crate::error::EbiError;

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
    ) -> Result<AnalysisReport, EbiError> {
        if results.is_empty() {
            return Err(EbiError::LlmClientError(
                "No analysis results to aggregate".to_string()
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
        report = self.enrich_report_with_insights(report, components);

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
        let highest_risk = results.iter()
            .map(|r| &r.risk_level)
            .max()
            .unwrap_or(&RiskLevel::Info);

        let total_duration: u64 = results.iter()
            .map(|r| r.analysis_duration_ms)
            .sum();

        let average_confidence = results.iter()
            .map(|r| r.confidence)
            .sum::<f32>() / results.len() as f32;

        // Combine summaries
        let combined_summary = results.iter()
            .map(|r| r.summary.clone())
            .collect::<Vec<_>>()
            .join(" | ");

        // Combine details
        let combined_details = results.iter()
            .enumerate()
            .map(|(i, r)| format!(
                "Analysis {}: {}",
                i + 1,
                r.details.as_deref().unwrap_or("No details available")
            ))
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
        let highest_risk = results.iter()
            .map(|r| &r.risk_level)
            .max()
            .unwrap_or(&RiskLevel::Info);

        let total_duration: u64 = results.iter()
            .map(|r| r.analysis_duration_ms)
            .sum();

        let average_confidence = results.iter()
            .map(|r| r.confidence)
            .sum::<f32>() / results.len() as f32;

        let combined_summary = results.iter()
            .map(|r| r.summary.clone())
            .collect::<Vec<_>>()
            .join(" | ");

        let combined_details = results.iter()
            .enumerate()
            .map(|(i, r)| format!(
                "Injection Analysis {}: {}",
                i + 1,
                r.details.as_deref().unwrap_or("No details available")
            ))
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
        let mut risk_factors = Vec::new();

        // Factor in LLM analysis results
        if let Some(ref code_analysis) = report.code_analysis {
            risk_factors.push(code_analysis.risk_level.clone());
        }

        if let Some(ref injection_analysis) = report.injection_analysis {
            risk_factors.push(injection_analysis.risk_level.clone());
        }

        // Factor in static analysis from components
        let static_relevance = self.classifier.classify_script_overall_risk(&components.metadata.priority_nodes);
        risk_factors.push(self.map_security_to_risk(static_relevance));

        // Return the highest risk level found
        risk_factors.iter()
            .max()
            .unwrap_or(&RiskLevel::Low)
            .clone()
    }

    fn enrich_report_with_insights(
        &self,
        mut report: AnalysisReport,
        components: &ScriptComponents,
    ) -> AnalysisReport {
        // Add execution recommendation
        let (recommendation, advice) = self.generate_execution_guidance(&report, components);
        report.execution_recommendation = recommendation;
        report.execution_advice = Some(advice);

        // Add risk explanation
        let relevance = self.map_risk_to_relevance(&report.overall_risk);
        let risk_explanation = self.classifier.get_risk_explanation(&relevance);
        report.risk_explanation = Some(risk_explanation.to_string());

        // Add mitigation suggestions
        let suggestions = self.classifier.get_risk_mitigation_suggestions(&components.metadata.priority_nodes);
        report.mitigation_suggestions = suggestions;

        // Add summary statistics
        report.analysis_summary = self.generate_analysis_summary(&report, components);

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

    fn generate_execution_guidance(
        &self,
        report: &AnalysisReport,
        _components: &ScriptComponents,
    ) -> (ExecutionRecommendation, String) {
        match report.overall_risk {
            RiskLevel::Critical => (
                ExecutionRecommendation::Blocked,
                "BLOCK EXECUTION: This script contains critical security risks that could \
                 cause immediate system damage or compromise. Manual review required before execution.".to_string(),
            ),
            RiskLevel::High => (
                ExecutionRecommendation::Dangerous,
                "CAUTION REQUIRED: This script contains high-risk operations. \
                 Carefully review the identified issues and consider safer alternatives. \
                 Execute only if you trust the source and understand the implications.".to_string(),
            ),
            RiskLevel::Medium => (
                ExecutionRecommendation::Caution,
                "REVIEW RECOMMENDED: This script performs operations that access system resources. \
                 Review the analysis results and ensure you understand what the script will do.".to_string(),
            ),
            RiskLevel::Low => (
                ExecutionRecommendation::Safe,
                "LOW RISK: This script appears to perform standard operations with minimal security impact. \
                 Standard precautions apply.".to_string(),
            ),
            RiskLevel::Info | RiskLevel::None => (
                ExecutionRecommendation::Safe,
                "MINIMAL RISK: No significant security concerns identified. \
                 This script appears safe to execute.".to_string(),
            ),
        }
    }

    fn generate_analysis_summary(
        &self,
        report: &AnalysisReport,
        components: &ScriptComponents,
    ) -> String {
        let mut summary_parts = Vec::new();

        // Script overview
        summary_parts.push(format!(
            "Analyzed {} script ({} lines, {} bytes)",
            report.script_info.language.as_str(),
            report.script_info.line_count,
            report.script_info.size_bytes
        ));

        // Static analysis summary
        let critical_nodes = components.get_critical_nodes().len();
        let high_risk_nodes = components.get_high_risk_nodes().len();

        if critical_nodes > 0 || high_risk_nodes > 0 {
            summary_parts.push(format!(
                "Static analysis found {} critical and {} high-risk operations",
                critical_nodes,
                high_risk_nodes
            ));
        }

        // LLM analysis summary
        let mut llm_analyses = Vec::new();
        if let Some(ref code_analysis) = report.code_analysis {
            llm_analyses.push(format!(
                "Code vulnerability analysis: {} risk (confidence: {:.0}%)",
                code_analysis.risk_level.as_str(),
                code_analysis.confidence * 100.0
            ));
        }

        if let Some(ref injection_analysis) = report.injection_analysis {
            llm_analyses.push(format!(
                "Injection detection: {} risk (confidence: {:.0}%)",
                injection_analysis.risk_level.as_str(),
                injection_analysis.confidence * 100.0
            ));
        }

        if !llm_analyses.is_empty() {
            summary_parts.push(llm_analyses.join(", "));
        }

        // Overall assessment
        summary_parts.push(format!(
            "Overall risk assessment: {}",
            report.overall_risk.as_str()
        ));

        summary_parts.join(". ")
    }


    pub fn validate_analysis_quality(&self, results: &[AnalysisResult]) -> Vec<String> {
        let mut warnings = Vec::new();

        for (i, result) in results.iter().enumerate() {
            // Check confidence levels
            if result.confidence < 0.5 {
                warnings.push(format!(
                    "Analysis {}: Low confidence ({:.1}%) - results may be unreliable",
                    i + 1, result.confidence * 100.0
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
                if details.to_lowercase().contains("timeout") ||
                   details.to_lowercase().contains("error") {
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

impl Default for AnalysisAggregator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ScriptComponents, ExecutionRecommendation, Language};

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

        let (recommendation, advice) = aggregator.generate_execution_guidance(&report, &components);
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
}
