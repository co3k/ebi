use crate::models::OutputLanguage;
use crate::error::EbiError;
use std::env;

pub struct LocaleDetector;

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