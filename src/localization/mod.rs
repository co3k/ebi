use crate::models::OutputLanguage;

pub mod locale;
pub mod strings;

pub use locale::LocaleDetector;

pub struct LocalizedStrings {
    pub output_language: OutputLanguage,
}

impl LocalizedStrings {
    pub fn new(output_language: OutputLanguage) -> Self {
        Self { output_language }
    }

    pub fn get(&self, key: &str) -> &'static str {
        match self.output_language {
            OutputLanguage::English => strings::ENGLISH_STRINGS.get(key).unwrap_or(&""),
            OutputLanguage::Japanese => strings::JAPANESE_STRINGS.get(key).unwrap_or(&""),
        }
    }

    pub fn get_risk_level(&self, risk_level: &str) -> &'static str {
        let key = format!("risk_level_{}", risk_level.to_lowercase());
        self.get(&key)
    }

    pub fn get_execution_recommendation(&self, recommendation: &str) -> &'static str {
        let key = format!("execution_{}", recommendation.to_lowercase());
        self.get(&key)
    }

    pub fn get_analysis_section(&self, section: &str) -> &'static str {
        let key = format!("section_{}", section.to_lowercase());
        self.get(&key)
    }

    pub fn get_message(&self, message: &str) -> &'static str {
        let key = format!("message_{}", message.to_lowercase());
        self.get(&key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_english_localization() {
        let localized = LocalizedStrings::new(OutputLanguage::English);

        assert_eq!(localized.get_risk_level("critical"), "CRITICAL");
        assert_eq!(localized.get_risk_level("high"), "HIGH");
        assert_eq!(localized.get_execution_recommendation("safe"), "SAFE");
        assert_eq!(
            localized.get_analysis_section("analysis_summary"),
            "ANALYSIS SUMMARY"
        );
        assert_eq!(localized.get_message("analysis_error"), "ANALYSIS ERROR");
    }

    #[test]
    fn test_japanese_localization() {
        let localized = LocalizedStrings::new(OutputLanguage::Japanese);

        assert_eq!(localized.get_risk_level("critical"), "クリティカル");
        assert_eq!(localized.get_risk_level("high"), "高");
        assert_eq!(localized.get_execution_recommendation("safe"), "安全");
        assert_eq!(
            localized.get_analysis_section("analysis_summary"),
            "分析サマリー"
        );
        assert_eq!(localized.get_message("analysis_error"), "分析エラー");
    }

    #[test]
    fn test_missing_key_returns_empty() {
        let localized = LocalizedStrings::new(OutputLanguage::English);
        assert_eq!(localized.get("nonexistent_key"), "");
    }
}
