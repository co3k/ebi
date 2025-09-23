use crate::models::{AnalysisReport, RiskLevel};
use crate::cli::args::Cli;
use std::fmt;

pub struct ReportFormatter {
    use_colors: bool,
    verbose: bool,
}

impl ReportFormatter {
    pub fn new(cli: &Cli) -> Self {
        Self {
            use_colors: cli.should_use_color(),
            verbose: cli.is_verbose(),
        }
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
            output.push_str(&self.format_section("ANALYSIS SUMMARY", &report.analysis_summary));
            output.push_str("\n\n");
        }

        // Code Analysis Results
        if let Some(ref code_analysis) = report.code_analysis {
            output.push_str(&self.format_section("CODE VULNERABILITY ANALYSIS", &format!(
                "Risk Level: {}\nConfidence: {:.0}%\nModel: {} ({}ms)\n\nSummary:\n{}",
                code_analysis.risk_level.as_str(),
                code_analysis.confidence * 100.0,
                code_analysis.model_used,
                code_analysis.analysis_duration_ms,
                code_analysis.summary
            )));

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
            output.push_str(&self.format_section("INJECTION DETECTION ANALYSIS", &format!(
                "Risk Level: {}\nConfidence: {:.0}%\nModel: {} ({}ms)\n\nSummary:\n{}",
                injection_analysis.risk_level.as_str(),
                injection_analysis.confidence * 100.0,
                injection_analysis.model_used,
                injection_analysis.analysis_duration_ms,
                injection_analysis.summary
            )));

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
            output.push_str(&self.format_section("RISK EXPLANATION", explanation));
            output.push_str("\n\n");
        }

        // Mitigation Suggestions
        if !report.mitigation_suggestions.is_empty() {
            let suggestions = report.mitigation_suggestions
                .iter()
                .enumerate()
                .map(|(i, suggestion)| format!("{}. {}", i + 1, suggestion))
                .collect::<Vec<_>>()
                .join("\n");

            output.push_str(&self.format_section("RECOMMENDED MITIGATIONS", &suggestions));
            output.push_str("\n\n");
        }

        // Execution Recommendation
        output.push_str(&self.format_execution_recommendation(report));

        output
    }

    fn format_header(&self, report: &AnalysisReport) -> String {
        if self.use_colors {
            format!(
                "\x1b[1m\x1b[36m═══ EBI SECURITY ANALYSIS REPORT ═══\x1b[0m\n\
                 Script: {} ({} lines, {} bytes)",
                report.script_info.language.as_str(),
                report.script_info.line_count,
                report.script_info.size_bytes
            )
        } else {
            format!(
                "=== EBI SECURITY ANALYSIS REPORT ===\n\
                 Script: {} ({} lines, {} bytes)",
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
                RiskLevel::Info => ("\x1b[1m\x1b[34m", "ℹ️"),    // Bold blue
            }
        } else {
            ("", "")
        };

        let reset = if self.use_colors { "\x1b[0m" } else { "" };

        format!(
            "{}{} OVERALL RISK LEVEL: {}{}{}",
            color_code,
            emoji,
            risk_level.as_str(),
            reset,
            if !emoji.is_empty() { "" } else { "" }
        )
    }

    fn format_section(&self, title: &str, content: &str) -> String {
        if self.use_colors {
            format!(
                "\x1b[1m\x1b[37m{}\x1b[0m\n{}",
                title,
                content
            )
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
                RiskLevel::Info => ("\x1b[1m\x1b[34m", "ℹ️"),
            }
        } else {
            ("", "")
        };

        let reset = if self.use_colors { "\x1b[0m" } else { "" };

        format!(
            "{}{} EXECUTION RECOMMENDATION{}\n\n{}",
            color_code,
            emoji,
            reset,
            report.execution_recommendation
        )
    }

    pub fn format_compact_summary(&self, report: &AnalysisReport) -> String {
        let risk_icon = match report.overall_risk {
            RiskLevel::Critical => "🚨",
            RiskLevel::High => "⚠️",
            RiskLevel::Medium => "🔸",
            RiskLevel::Low => "✅",
            RiskLevel::Info => "ℹ️",
        };

        format!(
            "{} {} | {} | {}",
            risk_icon,
            report.overall_risk.as_str(),
            report.script_info.language.as_str(),
            if report.should_block_execution() { "BLOCKED" } else { "REVIEW REQUIRED" }
        )
    }

    pub fn format_error(&self, error: &crate::error::EbiError) -> String {
        let (color_code, reset) = if self.use_colors {
            ("\x1b[1m\x1b[31m", "\x1b[0m")
        } else {
            ("", "")
        };

        format!(
            "{}🚨 ANALYSIS ERROR{}\n\n{}\n\n\
             For security, script execution is blocked when analysis fails.",
            color_code,
            reset,
            error
        )
    }

    pub fn format_progress(&self, message: &str) -> String {
        if self.use_colors {
            format!("\x1b[36m{}\x1b[0m", message)
        } else {
            message.to_string()
        }
    }
}

impl fmt::Display for AnalysisReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Default formatting without colors for compatibility
        let formatter = ReportFormatter {
            use_colors: false,
            verbose: true,
        };
        write!(f, "{}", formatter.format_analysis_report(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ScriptInfo, Language};

    #[test]
    fn test_report_formatting() {
        let script_info = ScriptInfo::new(Language::Bash, 100, 5);
        let mut report = AnalysisReport::new(script_info);
        report.overall_risk = RiskLevel::High;
        report.analysis_summary = "Test summary".to_string();
        report.execution_recommendation = "Test recommendation".to_string();

        let cli = crate::cli::args::Cli::try_parse_from(vec!["ebi", "bash"]).unwrap();
        let formatter = ReportFormatter::new(&cli);

        let formatted = formatter.format_analysis_report(&report);

        assert!(formatted.contains("SECURITY ANALYSIS REPORT"));
        assert!(formatted.contains("HIGH"));
        assert!(formatted.contains("Test summary"));
        assert!(formatted.contains("Test recommendation"));
    }

    #[test]
    fn test_compact_summary() {
        let script_info = ScriptInfo::new(Language::Python, 200, 10);
        let mut report = AnalysisReport::new(script_info);
        report.overall_risk = RiskLevel::Critical;

        let cli = crate::cli::args::Cli::try_parse_from(vec!["ebi", "python"]).unwrap();
        let formatter = ReportFormatter::new(&cli);

        let summary = formatter.format_compact_summary(&report);

        assert!(summary.contains("CRITICAL"));
        assert!(summary.contains("python"));
        assert!(summary.contains("BLOCKED"));
    }

    #[test]
    fn test_error_formatting() {
        let cli = crate::cli::args::Cli::try_parse_from(vec!["ebi", "bash"]).unwrap();
        let formatter = ReportFormatter::new(&cli);

        let error = crate::error::EbiError::AnalysisTimeout { timeout: 60 };
        let formatted = formatter.format_error(&error);

        assert!(formatted.contains("ANALYSIS ERROR"));
        assert!(formatted.contains("blocked"));
    }

    #[test]
    fn test_color_handling() {
        let cli = crate::cli::args::Cli::try_parse_from(vec!["ebi", "bash"]).unwrap();
        let formatter = ReportFormatter::new(&cli);

        // This test will vary based on environment variables
        // In a real environment, NO_COLOR might be set
        let risk_formatted = formatter.format_risk_level(&RiskLevel::Critical);
        assert!(risk_formatted.contains("CRITICAL"));
    }
}