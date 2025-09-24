use crate::cli::args::Cli;
use crate::localization::LocalizedStrings;
use crate::models::{AnalysisReport, RiskLevel};

pub struct ReportFormatter {
    use_colors: bool,
    verbose: bool,
    localized_strings: LocalizedStrings,
}

impl ReportFormatter {
    pub fn new(cli: &Cli) -> Result<Self, crate::error::EbiError> {
        let output_language = cli.get_output_language()?;
        Ok(Self {
            use_colors: cli.should_use_color(),
            verbose: cli.is_verbose(),
            localized_strings: LocalizedStrings::new(output_language),
        })
    }

    pub fn format_analysis_report(&self, report: &AnalysisReport) -> String {
        let mut output = String::new();

        // Header
        output.push_str(&self.format_header(report));
        output.push('\n');

        // Risk Level (prominently displayed)
        output.push_str(&self.format_risk_level(&report.overall_risk));
        output.push_str("\n\n");

        // Summary
        if !report.analysis_summary.is_empty() {
            let section_title = self
                .localized_strings
                .get_analysis_section("analysis_summary");
            output.push_str(&self.format_section(section_title, &report.analysis_summary));
            output.push_str("\n\n");
        }

        // Code Analysis Results
        if let Some(ref code_analysis) = report.code_analysis {
            let section_title = self
                .localized_strings
                .get_analysis_section("code_vulnerability_analysis");
            output.push_str(&self.format_section(
                section_title,
                &format!(
                    "Risk Level: {}\nConfidence: {:.0}%\nModel: {} ({}ms)\n\nSummary:\n{}",
                    code_analysis.risk_level.as_str(),
                    code_analysis.confidence * 100.0,
                    code_analysis.model_used,
                    code_analysis.analysis_duration_ms,
                    code_analysis.summary
                ),
            ));

            if self.verbose {
                if let Some(ref details) = code_analysis.details {
                    output.push_str("\n\nDetailed Analysis:\n");
                    output.push_str(details);
                }
            }
            output.push_str("\n\n");
        }

        // Injection Analysis Results
        if let Some(ref injection_analysis) = report.injection_analysis {
            let section_title = self
                .localized_strings
                .get_analysis_section("injection_detection_analysis");
            output.push_str(&self.format_section(
                section_title,
                &format!(
                    "Risk Level: {}\nConfidence: {:.0}%\nModel: {} ({}ms)\n\nSummary:\n{}",
                    injection_analysis.risk_level.as_str(),
                    injection_analysis.confidence * 100.0,
                    injection_analysis.model_used,
                    injection_analysis.analysis_duration_ms,
                    injection_analysis.summary
                ),
            ));

            if self.verbose {
                if let Some(ref details) = injection_analysis.details {
                    output.push_str("\n\nDetailed Analysis:\n");
                    output.push_str(details);
                }
            }
            output.push_str("\n\n");
        }

        // Risk Explanation
        if let Some(ref explanation) = report.risk_explanation {
            let section_title = self
                .localized_strings
                .get_analysis_section("risk_explanation");
            output.push_str(&self.format_section(section_title, explanation));
            output.push_str("\n\n");
        }

        // Mitigation Suggestions
        if !report.mitigation_suggestions.is_empty() {
            let suggestions = report
                .mitigation_suggestions
                .iter()
                .enumerate()
                .map(|(i, suggestion)| format!("{}. {}", i + 1, suggestion))
                .collect::<Vec<_>>()
                .join("\n");

            let section_title = self
                .localized_strings
                .get_analysis_section("recommended_mitigations");
            output.push_str(&self.format_section(section_title, &suggestions));
            output.push_str("\n\n");
        }

        // Execution Recommendation
        output.push_str(&self.format_execution_recommendation(report));

        output
    }

    fn format_header(&self, report: &AnalysisReport) -> String {
        let header_text = self.localized_strings.get("report_header");
        let script_text = self.localized_strings.get("report_script_info");

        if self.use_colors {
            format!(
                "\x1b[1m\x1b[36m🦐 ═══ {} ═══ 🍤\x1b[0m\n\
                 {}: {} ({} lines, {} bytes)",
                header_text,
                script_text,
                report.script_info.language.as_str(),
                report.script_info.line_count,
                report.script_info.size_bytes
            )
        } else {
            format!(
                "🦐 === {} === 🍤\n\
                 {}: {} ({} lines, {} bytes)",
                header_text,
                script_text,
                report.script_info.language.as_str(),
                report.script_info.line_count,
                report.script_info.size_bytes
            )
        }
    }

    fn format_risk_level(&self, risk_level: &RiskLevel) -> String {
        let (color_code, emoji) = if self.use_colors {
            match risk_level {
                RiskLevel::Critical => ("\x1b[1m\x1b[31m", "🚨"), // Bold red
                RiskLevel::High => ("\x1b[1m\x1b[33m", "⚠️"),     // Bold yellow
                RiskLevel::Medium => ("\x1b[1m\x1b[35m", "🔸"),   // Bold magenta
                RiskLevel::Low => ("\x1b[1m\x1b[32m", "✅"),      // Bold green
                RiskLevel::Info | RiskLevel::None => ("\x1b[1m\x1b[34m", "ℹ️"), // Bold blue
            }
        } else {
            ("", "")
        };

        let reset = if self.use_colors { "\x1b[0m" } else { "" };
        let risk_text = self.localized_strings.get_risk_level(risk_level.as_str());
        let overall_risk_text = self.localized_strings.get("report_overall_risk");

        format!(
            "{}{} {}: {}{}{}",
            color_code,
            emoji,
            overall_risk_text,
            risk_text,
            reset,
            if !emoji.is_empty() { "" } else { "" }
        )
    }

    fn format_section(&self, title: &str, content: &str) -> String {
        if self.use_colors {
            format!("\x1b[1m\x1b[37m{}\x1b[0m\n{}", title, content)
        } else {
            format!(
                "{}\n{}{}",
                title,
                "─".repeat(title.len()),
                format!("\n{}", content)
            )
        }
    }

    fn format_execution_recommendation(&self, report: &AnalysisReport) -> String {
        let (color_code, emoji) = if self.use_colors {
            match report.overall_risk {
                RiskLevel::Critical => ("\x1b[1m\x1b[31m", "🛑"),
                RiskLevel::High => ("\x1b[1m\x1b[33m", "⚠️"),
                RiskLevel::Medium => ("\x1b[1m\x1b[35m", "🔍"),
                RiskLevel::Low => ("\x1b[1m\x1b[32m", "✅"),
                RiskLevel::Info | RiskLevel::None => ("\x1b[1m\x1b[34m", "ℹ️"),
            }
        } else {
            ("", "")
        };

        let reset = if self.use_colors { "\x1b[0m" } else { "" };
        let section_title = self
            .localized_strings
            .get_analysis_section("execution_recommendation");

        let recommendation_text = report
            .execution_advice
            .as_deref()
            .unwrap_or_else(|| report.execution_recommendation.description());

        format!(
            "{}{} {}{}\n\n{}",
            color_code, emoji, section_title, reset, recommendation_text
        )
    }

    pub fn format_compact_summary(&self, report: &AnalysisReport) -> String {
        let risk_icon = match report.overall_risk {
            RiskLevel::Critical => "🚨",
            RiskLevel::High => "⚠️",
            RiskLevel::Medium => "🔸",
            RiskLevel::Low => "✅",
            RiskLevel::Info | RiskLevel::None => "ℹ️",
        };

        let risk_text = self
            .localized_strings
            .get_risk_level(report.overall_risk.as_str());
        let blocked_text = self.localized_strings.get_message("blocked");
        let review_text = self.localized_strings.get_message("review_required");

        format!(
            "{} {} | {} | {}",
            risk_icon,
            risk_text,
            report.script_info.language.as_str(),
            if report.should_block_execution() {
                blocked_text
            } else {
                review_text
            }
        )
    }

    pub fn format_error(&self, error: &crate::error::EbiError) -> String {
        let (color_code, reset) = if self.use_colors {
            ("\x1b[1m\x1b[31m", "\x1b[0m")
        } else {
            ("", "")
        };

        let error_title = self.localized_strings.get_message("analysis_error");
        let error_desc = self.localized_strings.get("desc_analysis_failure");

        format!(
            "{}🦐🚨 {}{}\n\n{}\n\n{}",
            color_code, error_title, reset, error, error_desc
        )
    }

    pub fn format_progress(&self, message: &str) -> String {
        if self.use_colors {
            format!("\x1b[36m🦐 {}\x1b[0m", message)
        } else {
            format!("🦐 {}", message)
        }
    }
}

// Display implementation moved to models/report.rs to avoid conflict

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ExecutionRecommendation, Language, ScriptInfo};
    use clap::Parser;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn test_report_formatting() {
        let script_info = ScriptInfo::new(Language::Bash, 100, 5);
        let mut report = AnalysisReport::new(script_info);
        report.overall_risk = RiskLevel::High;
        report.analysis_summary = "Test summary".to_string();
        report.execution_recommendation = ExecutionRecommendation::Dangerous;
        report.execution_advice = Some("Test recommendation".to_string());

        let _guard = env_lock().lock().unwrap();
        std::env::set_var("LANG", "en_US.UTF-8");
        std::env::set_var("LC_ALL", "en_US.UTF-8");
        let cli =
            crate::cli::args::Cli::try_parse_from(vec!["ebi", "--output-lang", "english", "bash"])
                .unwrap();
        let formatter = ReportFormatter::new(&cli).unwrap();

        let formatted = formatter.format_analysis_report(&report);

        assert!(
            formatted.contains("EBI SECURITY ANALYSIS REPORT"),
            "report: {}",
            formatted
        );
        assert!(formatted.contains("HIGH"), "report: {}", formatted);
        assert!(formatted.contains("Test summary"), "report: {}", formatted);
        assert!(
            formatted.contains("Test recommendation"),
            "report: {}",
            formatted
        );

        std::env::remove_var("LANG");
        std::env::remove_var("LC_ALL");
    }

    #[test]
    fn test_compact_summary() {
        let script_info = ScriptInfo::new(Language::Python, 200, 10);
        let mut report = AnalysisReport::new(script_info);
        report.overall_risk = RiskLevel::Critical;
        report.execution_recommendation = ExecutionRecommendation::Blocked;
        report.execution_advice = Some("BLOCK EXECUTION".to_string());

        let _guard = env_lock().lock().unwrap();
        std::env::set_var("LANG", "en_US.UTF-8");
        std::env::set_var("LC_ALL", "en_US.UTF-8");
        let cli = crate::cli::args::Cli::try_parse_from(vec![
            "ebi",
            "--output-lang",
            "english",
            "python",
        ])
        .unwrap();
        let formatter = ReportFormatter::new(&cli).unwrap();

        let summary = formatter.format_compact_summary(&report);

        assert!(summary.contains("CRITICAL"), "summary: {}", summary);
        assert!(summary.contains("python"), "summary: {}", summary);
        assert!(summary.contains("BLOCKED"), "summary: {}", summary);

        std::env::remove_var("LANG");
        std::env::remove_var("LC_ALL");
    }

    #[test]
    fn test_error_formatting() {
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("LANG", "en_US.UTF-8");
        std::env::set_var("LC_ALL", "en_US.UTF-8");
        let cli =
            crate::cli::args::Cli::try_parse_from(vec!["ebi", "--output-lang", "english", "bash"])
                .unwrap();
        let formatter = ReportFormatter::new(&cli).unwrap();

        let error = crate::error::EbiError::AnalysisTimeout { timeout: 60 };
        let formatted = formatter.format_error(&error);

        assert!(formatted.contains("ANALYSIS ERROR"), "error: {}", formatted);
        assert!(formatted.contains("blocked"), "error: {}", formatted);

        std::env::remove_var("LANG");
        std::env::remove_var("LC_ALL");
    }

    #[test]
    fn test_color_handling() {
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("LANG", "en_US.UTF-8");
        std::env::set_var("LC_ALL", "en_US.UTF-8");
        let cli =
            crate::cli::args::Cli::try_parse_from(vec!["ebi", "--output-lang", "english", "bash"])
                .unwrap();
        let formatter = ReportFormatter::new(&cli).unwrap();

        // This test will vary based on environment variables
        // In a real environment, NO_COLOR might be set
        let risk_formatted = formatter.format_risk_level(&RiskLevel::Critical);
        assert!(risk_formatted.contains("CRITICAL"));

        std::env::remove_var("LANG");
        std::env::remove_var("LC_ALL");
    }
}
