use std::collections::HashMap;

lazy_static::lazy_static! {
    pub static ref ENGLISH_STRINGS: HashMap<&'static str, &'static str> = {
        let mut m = HashMap::new();

        // Risk levels
        m.insert("risk_level_critical", "CRITICAL");
        m.insert("risk_level_high", "HIGH");
        m.insert("risk_level_medium", "MEDIUM");
        m.insert("risk_level_low", "LOW");
        m.insert("risk_level_info", "INFO");
        m.insert("risk_level_none", "NONE");

        // Execution recommendations
        m.insert("execution_safe", "SAFE");
        m.insert("execution_caution", "CAUTION");
        m.insert("execution_dangerous", "DANGEROUS");
        m.insert("execution_blocked", "BLOCKED");

        // Section headers
        m.insert("section_analysis_summary", "ANALYSIS SUMMARY");
        m.insert("section_code_vulnerability_analysis", "CODE VULNERABILITY ANALYSIS");
        m.insert("section_injection_detection_analysis", "INJECTION DETECTION ANALYSIS");
        m.insert("section_risk_explanation", "RISK EXPLANATION");
        m.insert("section_recommended_mitigations", "RECOMMENDED MITIGATIONS");
        m.insert("section_execution_recommendation", "EXECUTION RECOMMENDATION");

        // Messages
        m.insert("message_analysis_error", "ANALYSIS ERROR");
        m.insert("message_execution_blocked", "EXECUTION BLOCKED DUE TO SECURITY CONCERNS");
        m.insert("message_review_required", "REVIEW REQUIRED");
        m.insert("message_blocked", "BLOCKED");
        m.insert("message_script_type_bash", "Bash");
        m.insert("message_script_type_python", "Python");
        m.insert("message_script_type_unknown", "Unknown");
        m.insert("message_script_type_large", "Large Script");
        m.insert("message_script_type_simple", "Simple Script");
        m.insert("message_script_type_regular", "Regular Script");

        // Descriptions
        m.insert("desc_safe_execution", "Low risk, likely safe to execute");
        m.insert("desc_caution_execution", "Medium risk, review carefully before executing");
        m.insert("desc_dangerous_execution", "High risk, execution not recommended");
        m.insert("desc_blocked_execution", "Critical risk or analysis failure, execution blocked");
        m.insert("desc_analysis_failure", "For security, script execution is blocked when analysis fails.");

        // Report header
        m.insert("report_header", "EBI SECURITY ANALYSIS REPORT");
        m.insert("report_script_info", "Script");
        m.insert("report_overall_risk", "OVERALL RISK LEVEL");

        m
    };

    pub static ref JAPANESE_STRINGS: HashMap<&'static str, &'static str> = {
        let mut m = HashMap::new();

        // Risk levels
        m.insert("risk_level_critical", "クリティカル");
        m.insert("risk_level_high", "高");
        m.insert("risk_level_medium", "中");
        m.insert("risk_level_low", "低");
        m.insert("risk_level_info", "情報");
        m.insert("risk_level_none", "なし");

        // Execution recommendations
        m.insert("execution_safe", "安全");
        m.insert("execution_caution", "注意");
        m.insert("execution_dangerous", "危険");
        m.insert("execution_blocked", "ブロック");

        // Section headers
        m.insert("section_analysis_summary", "分析サマリー");
        m.insert("section_code_vulnerability_analysis", "コード脆弱性分析");
        m.insert("section_injection_detection_analysis", "インジェクション検出分析");
        m.insert("section_risk_explanation", "リスク説明");
        m.insert("section_recommended_mitigations", "推奨緩和策");
        m.insert("section_execution_recommendation", "実行推奨");

        // Messages
        m.insert("message_analysis_error", "分析エラー");
        m.insert("message_execution_blocked", "セキュリティ上の懸念により実行がブロックされました");
        m.insert("message_review_required", "レビューが必要");
        m.insert("message_blocked", "ブロック");
        m.insert("message_script_type_bash", "Bash");
        m.insert("message_script_type_python", "Python");
        m.insert("message_script_type_unknown", "不明");
        m.insert("message_script_type_large", "大型スクリプト");
        m.insert("message_script_type_simple", "シンプルスクリプト");
        m.insert("message_script_type_regular", "通常スクリプト");

        // Descriptions
        m.insert("desc_safe_execution", "低リスク、実行しても安全とみなされます");
        m.insert("desc_caution_execution", "中リスク、実行前に慎重に確認してください");
        m.insert("desc_dangerous_execution", "高リスク、実行は推奨されません");
        m.insert("desc_blocked_execution", "クリティカルリスクまたは分析失敗、実行がブロックされました");
        m.insert("desc_analysis_failure", "セキュリティのため、分析に失敗した場合はスクリプトの実行がブロックされます。");

        // Report header
        m.insert("report_header", "EBI セキュリティ分析レポート");
        m.insert("report_script_info", "スクリプト");
        m.insert("report_overall_risk", "総合リスクレベル");

        m
    };
}
