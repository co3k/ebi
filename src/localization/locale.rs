use crate::models::{OutputLanguage, SecurityRelevance, RiskLevel, ExecutionRecommendation};
use std::env;

pub struct LocaleDetector;

pub struct LocalizedMessages;

impl LocalizedMessages {
    pub fn get_risk_explanation(relevance: &SecurityRelevance, language: &OutputLanguage) -> &'static str {
        match (relevance, language) {
            (SecurityRelevance::Critical, OutputLanguage::Japanese) => {
                "システムに深刻な損害を与える可能性、任意コードの実行、またはシステムセキュリティの侵害を引き起こす可能性のある操作を含みます"
            }
            (SecurityRelevance::High, OutputLanguage::Japanese) => {
                "昇格した権限を必要とする操作、ネットワーク通信、またはシステム状態の変更を含みます"
            }
            (SecurityRelevance::Medium, OutputLanguage::Japanese) => {
                "システムリソース、環境変数、またはファイルI/Oにアクセスする操作を含みます"
            }
            (SecurityRelevance::Low, OutputLanguage::Japanese) => {
                "セキュリティへの影響が最小限の標準的な操作のみを含みます"
            }
            (SecurityRelevance::Critical, OutputLanguage::English) => {
                "Contains operations that could cause immediate system damage, execute arbitrary code, or compromise system security"
            }
            (SecurityRelevance::High, OutputLanguage::English) => {
                "Contains operations that require elevated privileges, perform network communication, or modify system state"
            }
            (SecurityRelevance::Medium, OutputLanguage::English) => {
                "Contains operations that access system resources, environment variables, or perform file I/O"
            }
            (SecurityRelevance::Low, OutputLanguage::English) => {
                "Contains only standard operations with minimal security impact"
            }
        }
    }

    pub fn get_execution_guidance(risk: &RiskLevel, language: &OutputLanguage) -> (ExecutionRecommendation, String) {
        match (risk, language) {
            (RiskLevel::Critical, OutputLanguage::Japanese) => (
                ExecutionRecommendation::Blocked,
                "実行をブロック: このスクリプトには、システムに深刻な損害や侵害を引き起こす可能性のある重大なセキュリティリスクが含まれています。実行前に手動でのレビューが必要です。".to_string(),
            ),
            (RiskLevel::High, OutputLanguage::Japanese) => (
                ExecutionRecommendation::Dangerous,
                "注意が必要: このスクリプトには高リスクの操作が含まれています。特定された問題を慎重に確認し、より安全な代替手段を検討してください。ソースを信頼し、影響を理解している場合のみ実行してください。".to_string(),
            ),
            (RiskLevel::Medium, OutputLanguage::Japanese) => (
                ExecutionRecommendation::Caution,
                "レビュー推奨: このスクリプトはシステムリソースにアクセスする操作を実行します。分析結果を確認し、スクリプトが何を行うかを理解してください。".to_string(),
            ),
            (RiskLevel::Low, OutputLanguage::Japanese) => (
                ExecutionRecommendation::Safe,
                "低リスク: このスクリプトはセキュリティへの影響が最小限の標準的な操作を実行するようです。標準的な予防措置を適用してください。".to_string(),
            ),
            (RiskLevel::Info | RiskLevel::None, OutputLanguage::Japanese) => (
                ExecutionRecommendation::Safe,
                "最小リスク: 重大なセキュリティ上の問題は特定されませんでした。このスクリプトは安全に実行できるようです。".to_string(),
            ),
            (RiskLevel::Critical, OutputLanguage::English) => (
                ExecutionRecommendation::Blocked,
                "BLOCK EXECUTION: This script contains critical security risks that could cause immediate system damage or compromise. Manual review required before execution.".to_string(),
            ),
            (RiskLevel::High, OutputLanguage::English) => (
                ExecutionRecommendation::Dangerous,
                "CAUTION REQUIRED: This script contains high-risk operations. Carefully review the identified issues and consider safer alternatives. Execute only if you trust the source and understand the implications.".to_string(),
            ),
            (RiskLevel::Medium, OutputLanguage::English) => (
                ExecutionRecommendation::Caution,
                "REVIEW RECOMMENDED: This script performs operations that access system resources. Review the analysis results and ensure you understand what the script will do.".to_string(),
            ),
            (RiskLevel::Low, OutputLanguage::English) => (
                ExecutionRecommendation::Safe,
                "LOW RISK: This script appears to perform standard operations with minimal security impact. Standard precautions apply.".to_string(),
            ),
            (RiskLevel::Info | RiskLevel::None, OutputLanguage::English) => (
                ExecutionRecommendation::Safe,
                "MINIMAL RISK: No significant security concerns identified. This script appears safe to execute.".to_string(),
            ),
        }
    }

    pub fn format_analysis_summary(
        language_str: &str,
        line_count: usize,
        size_bytes: usize,
        language: &OutputLanguage,
    ) -> String {
        match language {
            OutputLanguage::Japanese => {
                format!("{}スクリプトを分析しました（{}行、{}バイト）", language_str, line_count, size_bytes)
            }
            OutputLanguage::English => {
                format!("Analyzed {} script ({} lines, {} bytes)", language_str, line_count, size_bytes)
            }
        }
    }

    pub fn format_static_analysis_summary(
        critical_nodes: usize,
        high_risk_nodes: usize,
        language: &OutputLanguage,
    ) -> Option<String> {
        if critical_nodes > 0 || high_risk_nodes > 0 {
            match language {
                OutputLanguage::Japanese => Some(format!(
                    "静的解析で{}個の重要な操作と{}個の高リスク操作が見つかりました",
                    critical_nodes, high_risk_nodes
                )),
                OutputLanguage::English => Some(format!(
                    "Static analysis found {} critical and {} high-risk operations",
                    critical_nodes, high_risk_nodes
                )),
            }
        } else {
            None
        }
    }

    pub fn format_code_vulnerability_analysis(
        risk_level: &str,
        confidence: f32,
        language: &OutputLanguage,
    ) -> String {
        match language {
            OutputLanguage::Japanese => {
                format!("コード脆弱性分析: {}リスク（信頼度: {:.0}%）", risk_level, confidence * 100.0)
            }
            OutputLanguage::English => {
                format!("Code vulnerability analysis: {} risk (confidence: {:.0}%)", risk_level, confidence * 100.0)
            }
        }
    }

    pub fn format_injection_detection(
        risk_level: &str,
        confidence: f32,
        language: &OutputLanguage,
    ) -> String {
        match language {
            OutputLanguage::Japanese => {
                format!("インジェクション検出: {}リスク（信頼度: {:.0}%）", risk_level, confidence * 100.0)
            }
            OutputLanguage::English => {
                format!("Injection detection: {} risk (confidence: {:.0}%)", risk_level, confidence * 100.0)
            }
        }
    }

    pub fn format_overall_risk_assessment(
        risk_level: &str,
        language: &OutputLanguage,
    ) -> String {
        match language {
            OutputLanguage::Japanese => {
                format!("総合リスク評価: {}", risk_level)
            }
            OutputLanguage::English => {
                format!("Overall risk assessment: {}", risk_level)
            }
        }
    }

    pub fn get_prompt_message(risk_level: &RiskLevel, language: &OutputLanguage) -> &'static str {
        match (risk_level, language) {
            (RiskLevel::Critical, OutputLanguage::Japanese) => {
                "🚨 重大リスクが検出されました - 安全のため実行は自動的にブロックされます。"
            }
            (RiskLevel::High, OutputLanguage::Japanese) => {
                "⚠️  高リスクが検出されました\n\
                 このスクリプトは危険な操作を実行します。\n\
                 実行前に分析結果を慎重に確認してください。"
            }
            (RiskLevel::Medium, OutputLanguage::Japanese) => {
                "🔸 中リスクが検出されました\n\
                 このスクリプトはシステムリソースにアクセスします。\n\
                 実行前に分析結果を確認してください。"
            }
            (RiskLevel::Low | RiskLevel::None, OutputLanguage::Japanese) => {
                "✅ 低リスクが検出されました\n\
                 このスクリプトは比較的安全です。"
            }
            (RiskLevel::Info, OutputLanguage::Japanese) => {
                "ℹ️  分析完了\n\
                 重大なセキュリティ上の問題は特定されませんでした。"
            }
            (RiskLevel::Critical, OutputLanguage::English) => {
                "🚨 CRITICAL RISK DETECTED - Execution automatically blocked for safety."
            }
            (RiskLevel::High, OutputLanguage::English) => {
                "⚠️  HIGH RISK DETECTED\n\
                 This script performs operations that could be dangerous.\n\
                 Please review the analysis carefully before proceeding."
            }
            (RiskLevel::Medium, OutputLanguage::English) => {
                "🔸 MEDIUM RISK DETECTED\n\
                 This script accesses system resources.\n\
                 Please review the analysis before proceeding."
            }
            (RiskLevel::Low | RiskLevel::None, OutputLanguage::English) => {
                "✅ LOW RISK DETECTED\n\
                 This script appears relatively safe."
            }
            (RiskLevel::Info, OutputLanguage::English) => {
                "ℹ️  ANALYSIS COMPLETE\n\
                 No significant security concerns identified."
            }
        }
    }

    pub fn get_critical_warning(language: &OutputLanguage) -> &'static str {
        match language {
            OutputLanguage::Japanese => {
                "🚨 重要な警告: このスクリプトは極めて危険と判定されました！\n\
                 実行により深刻なセキュリティ被害を受ける可能性があります。\n\
                 本当に実行する必要があるか慎重に検討してください。"
            }
            OutputLanguage::English => {
                "🚨 CRITICAL WARNING: This script has been identified as extremely dangerous!\n\
                 Execution may result in severe security compromise.\n\
                 Please carefully consider if execution is truly necessary."
            }
        }
    }

    pub fn get_prompt_text(risk_level: &RiskLevel, language: &OutputLanguage) -> &'static str {
        match (risk_level, language) {
            (RiskLevel::Critical, OutputLanguage::Japanese) => {
                "🚨 極めて危険と判定されましたが、実行を強行しますか？ \n\
                 本当に実行するには 'yes'、キャンセルするには 'no'、詳細を確認するには 'review' を入力してください: "
            }
            (RiskLevel::Critical, OutputLanguage::English) => {
                "🚨 This script is CRITICALLY dangerous. Do you want to force execution? \n\
                 Type 'yes' to execute anyway, 'no' to cancel, or 'review' to see full details: "
            }
            (RiskLevel::High, OutputLanguage::Japanese) => {
                "⚠️  高リスクにも関わらず実行を続行しますか？ \n\
                 実行するには 'yes'、キャンセルするには 'no'、詳細を確認するには 'review' を入力してください: "
            }
            (RiskLevel::Medium, OutputLanguage::Japanese) => {
                "🔸 実行を続行しますか？ \n\
                 実行するには 'yes'、キャンセルするには 'no'、詳細を確認するには 'review' を入力してください: "
            }
            (RiskLevel::Low | RiskLevel::Info | RiskLevel::None, OutputLanguage::Japanese) => {
                "実行するには 'yes'、キャンセルするには 'no' を入力してください: "
            }
            (RiskLevel::High, OutputLanguage::English) => {
                "⚠️  Do you want to proceed with execution despite the HIGH RISK? \n\
                 Type 'yes' to execute anyway, 'no' to cancel, or 'review' to see full details: "
            }
            (RiskLevel::Medium, OutputLanguage::English) => {
                "🔸 Do you want to proceed with execution? \n\
                 Type 'yes' to execute, 'no' to cancel, or 'review' to see full details: "
            }
            (RiskLevel::Low | RiskLevel::Info | RiskLevel::None, OutputLanguage::English) => {
                "Type 'yes' to execute, 'no' to cancel: "
            }
        }
    }
}

impl LocaleDetector {
    /// Detect the system locale and return the appropriate OutputLanguage
    pub fn detect_system_locale() -> OutputLanguage {
        // Try multiple environment variables in order of preference
        let locale_vars = [
            "LC_ALL",
            "LC_MESSAGES", 
            "LANG",
            "LANGUAGE"
        ];

        for var in &locale_vars {
            if let Ok(locale) = env::var(var) {
                if let Some(lang) = Self::parse_locale(&locale) {
                    return lang;
                }
            }
        }

        // Fallback to English if no locale is detected
        OutputLanguage::English
    }

    /// Parse a locale string and extract the language
    fn parse_locale(locale: &str) -> Option<OutputLanguage> {
        // Handle various locale formats:
        // - ja_JP.UTF-8
        // - ja_JP
        // - ja
        // - Japanese_Japan.932
        // - C.UTF-8 (fallback to English)
        
        let locale_lower = locale.to_lowercase();
        
        // Check for Japanese locale indicators
        if locale_lower.starts_with("ja") || 
           locale_lower.contains("japanese") ||
           locale_lower.contains("japan") {
            return Some(OutputLanguage::Japanese);
        }
        
        // Check for English locale indicators
        if locale_lower.starts_with("en") || 
           locale_lower.contains("english") ||
           locale_lower.contains("american") ||
           locale_lower.contains("british") ||
           locale_lower == "c" ||
           locale_lower == "posix" {
            return Some(OutputLanguage::English);
        }
        
        // If we can't determine the language, return None
        None
    }

    /// Get the current system locale string for debugging
    pub fn get_system_locale_info() -> String {
        let mut info = Vec::new();
        
        let locale_vars = [
            ("LC_ALL", "LC_ALL"),
            ("LC_MESSAGES", "LC_MESSAGES"), 
            ("LANG", "LANG"),
            ("LANGUAGE", "LANGUAGE")
        ];

        for (var, name) in &locale_vars {
            match env::var(var) {
                Ok(value) => info.push(format!("{}={}", name, value)),
                Err(_) => info.push(format!("{}=(not set)", name)),
            }
        }
        
        info.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_locale_japanese() {
        assert_eq!(LocaleDetector::parse_locale("ja_JP.UTF-8"), Some(OutputLanguage::Japanese));
        assert_eq!(LocaleDetector::parse_locale("ja_JP"), Some(OutputLanguage::Japanese));
        assert_eq!(LocaleDetector::parse_locale("ja"), Some(OutputLanguage::Japanese));
        assert_eq!(LocaleDetector::parse_locale("Japanese_Japan.932"), Some(OutputLanguage::Japanese));
        assert_eq!(LocaleDetector::parse_locale("japanese"), Some(OutputLanguage::Japanese));
    }

    #[test]
    fn test_parse_locale_english() {
        assert_eq!(LocaleDetector::parse_locale("en_US.UTF-8"), Some(OutputLanguage::English));
        assert_eq!(LocaleDetector::parse_locale("en_US"), Some(OutputLanguage::English));
        assert_eq!(LocaleDetector::parse_locale("en"), Some(OutputLanguage::English));
        assert_eq!(LocaleDetector::parse_locale("English_United States.1252"), Some(OutputLanguage::English));
        assert_eq!(LocaleDetector::parse_locale("english"), Some(OutputLanguage::English));
        assert_eq!(LocaleDetector::parse_locale("C.UTF-8"), Some(OutputLanguage::English));
        assert_eq!(LocaleDetector::parse_locale("POSIX"), Some(OutputLanguage::English));
    }

    #[test]
    fn test_parse_locale_unknown() {
        assert_eq!(LocaleDetector::parse_locale("fr_FR.UTF-8"), None);
        assert_eq!(LocaleDetector::parse_locale("de_DE"), None);
        assert_eq!(LocaleDetector::parse_locale("zh_CN"), None);
        assert_eq!(LocaleDetector::parse_locale(""), None);
    }

    #[test]
    fn test_detect_system_locale_with_env() {
        // Test with Japanese locale
        env::set_var("LANG", "ja_JP.UTF-8");
        let detected = LocaleDetector::detect_system_locale();
        assert_eq!(detected, OutputLanguage::Japanese);
        env::remove_var("LANG");

        // Test with English locale
        env::set_var("LANG", "en_US.UTF-8");
        let detected = LocaleDetector::detect_system_locale();
        assert_eq!(detected, OutputLanguage::English);
        env::remove_var("LANG");

        // Test with unknown locale (should fallback to English)
        env::set_var("LANG", "fr_FR.UTF-8");
        let detected = LocaleDetector::detect_system_locale();
        assert_eq!(detected, OutputLanguage::English);
        env::remove_var("LANG");
    }

    #[test]
    fn test_locale_priority() {
        // LC_ALL should take priority over LANG
        env::set_var("LANG", "en_US.UTF-8");
        env::set_var("LC_ALL", "ja_JP.UTF-8");
        let detected = LocaleDetector::detect_system_locale();
        assert_eq!(detected, OutputLanguage::Japanese);
        env::remove_var("LANG");
        env::remove_var("LC_ALL");
    }

    #[test]
    fn test_get_system_locale_info() {
        let info = LocaleDetector::get_system_locale_info();
        assert!(info.contains("LANG="));
        assert!(info.contains("LC_ALL="));
    }
}