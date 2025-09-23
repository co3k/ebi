use ebi::analyzer::AnalysisAggregator;
use ebi::models::{
    AnalysisResult, AnalysisType, RiskLevel, ScriptInfo, Language,
    ScriptComponents, ExecutionRecommendation
};

#[test]
fn aggregator_combines_results_and_sets_overall_risk() {
    let aggregator = AnalysisAggregator::new();
    let script_info = ScriptInfo::new(Language::Bash, 128, 12);
    let components = ScriptComponents::new();

    let code_result = AnalysisResult::new(AnalysisType::CodeVulnerability, "model".into(), 120)
        .with_risk_level(RiskLevel::High)
        .with_summary("High risk code".into())
        .with_confidence(0.9)
        .with_details("detail".into());

    let injection_result = AnalysisResult::new(AnalysisType::InjectionDetection, "model".into(), 80)
        .with_risk_level(RiskLevel::Medium)
        .with_summary("Medium injection risk".into())
        .with_confidence(0.8)
        .with_details("injection detail".into());

    let report = aggregator
        .aggregate_analysis_results(vec![code_result, injection_result], script_info, &components)
        .expect("aggregation should succeed");

    assert_eq!(report.overall_risk, RiskLevel::High);
    assert_eq!(report.execution_recommendation, ExecutionRecommendation::Dangerous);
    assert!(report.execution_advice.is_some());
    assert!(report.analysis_summary.contains("Overall risk assessment"));
}

#[test]
fn aggregator_quality_validation_flags_warnings() {
    let aggregator = AnalysisAggregator::new();

    let low_confidence = AnalysisResult::new(AnalysisType::CodeVulnerability, "model".into(), 50)
        .with_summary("Too short".into())
        .with_confidence(0.2);

    let warnings = aggregator.validate_analysis_quality(&[low_confidence]);

    assert!(!warnings.is_empty());
    assert!(warnings.iter().any(|w| w.contains("Low confidence")));
}

#[test]
fn fallback_report_blocks_execution_and_sets_critical_risk() {
    let aggregator = AnalysisAggregator::new();
    let script_info = ScriptInfo::new(Language::Python, 200, 20);
    let error = ebi::error::EbiError::AnalysisTimeout { timeout: 30 };

    let report = aggregator.create_fallback_report(script_info, &error);

    assert_eq!(report.overall_risk, RiskLevel::Critical);
    assert_eq!(report.execution_recommendation, ExecutionRecommendation::Blocked);
    assert!(report.execution_advice.as_ref().unwrap().contains("BLOCK EXECUTION"));
}
