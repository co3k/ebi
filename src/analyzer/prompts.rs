use crate::models::{Language, AnalysisType, ScriptSource};

pub struct PromptTemplate;

impl PromptTemplate {
    pub fn build_vulnerability_analysis_prompt(
        content: &str,
        language: &Language,
        source: &ScriptSource,
    ) -> String {
        let language_specific_guidance = match language {
            Language::Bash => Self::get_bash_security_guidance(),
            Language::Python => Self::get_python_security_guidance(),
            Language::Unknown => "Analyze this script for general security issues.",
        };

        format!(
            r#"SECURITY ANALYSIS REQUEST

SCRIPT LANGUAGE: {}
SCRIPT SOURCE: {}
CONTENT LENGTH: {} characters

SCRIPT CONTENT:
```{}
{}
```

ANALYSIS REQUIREMENTS:
1. Perform comprehensive security analysis
2. Identify potential vulnerabilities
3. Assess overall risk level (Critical/High/Medium/Low/Info)
4. Provide specific remediation recommendations

LANGUAGE-SPECIFIC GUIDANCE:
{}

OUTPUT FORMAT:
Please structure your response as follows:

RISK LEVEL: [Critical/High/Medium/Low/Info]

VULNERABILITIES FOUND:
[List each vulnerability with specific line references where possible]

RISK ASSESSMENT:
[Detailed explanation of the security implications]

RECOMMENDED ACTIONS:
[Specific steps to mitigate identified risks]

CONFIDENCE LEVEL: [High/Medium/Low]
[Brief explanation of analysis confidence]"#,
            language.as_str(),
            source,
            content.len(),
            language.as_str().to_lowercase(),
            content,
            language_specific_guidance
        )
    }

    pub fn build_injection_analysis_prompt(
        content: &str,
        language: &Language,
        source: &ScriptSource,
    ) -> String {
        format!(
            r#"INJECTION DETECTION ANALYSIS

SCRIPT LANGUAGE: {}
SCRIPT SOURCE: {}

EXTRACTED CONTENT FOR ANALYSIS:
{}

ANALYSIS FOCUS:
This content consists of comments and string literals extracted from a {} script.
Please analyze for potential injection attacks, social engineering, or malicious content.

SPECIFIC CHECKS:
1. **Obfuscation Detection**: Look for base64, hex, or other encoding that might hide malicious content
2. **Social Engineering**: Check for misleading comments or instructions
3. **Injection Patterns**: Identify potential code injection attempts in strings
4. **Suspicious URLs**: Flag any suspicious domains or IP addresses
5. **Command Injection**: Look for shell metacharacters in strings
6. **Data Exfiltration**: Identify patterns that might indicate data theft

LANGUAGE-SPECIFIC PATTERNS:
{}

OUTPUT FORMAT:
RISK LEVEL: [Critical/High/Medium/Low/Info]

SUSPICIOUS PATTERNS:
[List any concerning patterns found]

INJECTION RISKS:
[Assess potential for injection attacks]

SOCIAL ENGINEERING INDICATORS:
[Note any misleading or suspicious content]

RECOMMENDATIONS:
[Specific steps to address identified issues]

CONFIDENCE LEVEL: [High/Medium/Low]"#,
            language.as_str(),
            source,
            content,
            language.as_str(),
            Self::get_injection_patterns_guidance(language)
        )
    }

    fn get_bash_security_guidance() -> &'static str {
        r#"BASH SECURITY FOCUS AREAS:

HIGH-RISK PATTERNS:
- Command substitution: $(command) or `command`
- eval statements: eval $variable
- Unquoted variables: $var vs "$var"
- Process substitution: <(command) or >(command)
- Piped downloads: curl/wget | bash
- File redirections to sensitive locations
- Privilege escalation: sudo, su
- Network operations: ssh, scp, nc
- Destructive commands: rm -rf, dd, mkfs

CRITICAL VULNERABILITIES:
- Remote code execution via curl/wget pipes
- Command injection through unvalidated input
- Path traversal in file operations
- Privilege escalation without proper validation

MITIGATION PATTERNS:
- Proper variable quoting
- Input validation and sanitization
- Use of absolute paths
- Principle of least privilege"#
    }

    fn get_python_security_guidance() -> &'static str {
        r#"PYTHON SECURITY FOCUS AREAS:

HIGH-RISK PATTERNS:
- Code execution: exec(), eval(), compile()
- System commands: os.system(), subprocess with shell=True
- Dynamic imports: __import__(), importlib
- Deserialization: pickle.loads(), marshal.loads()
- File operations with user input
- Network requests without SSL verification
- ctypes for system calls

CRITICAL VULNERABILITIES:
- Arbitrary code execution via exec/eval
- Command injection through subprocess
- Deserialization attacks
- Path traversal in file operations
- SQL injection in database queries
- SSRF in network requests

SECURE ALTERNATIVES:
- Use subprocess with argument lists instead of shell=True
- Validate and sanitize all user input
- Use ast.literal_eval() instead of eval() for data
- Implement proper input validation
- Use parameterized queries for databases"#
    }

    fn get_injection_patterns_guidance(language: &Language) -> &'static str {
        match language {
            Language::Bash => {
                r#"BASH INJECTION PATTERNS:
- Shell metacharacters: ; & | ` $ ( ) { } [ ] < > * ? ~ !
- Command separators in strings: &&, ||, ;
- Variable expansion: ${var}, $(cmd)
- Escape sequences: \n, \t, \x, \u
- Here-documents: <<EOF patterns
- Process substitution patterns"#
            }
            Language::Python => {
                r#"PYTHON INJECTION PATTERNS:
- String formatting vulnerabilities: % formatting, .format()
- Template injection: Jinja2, Django templates
- Code injection markers: exec, eval, compile
- Import injection: __import__, importlib
- File path injection: ../, absolute paths
- SQL injection indicators: quotes, semicolons in strings"#
            }
            Language::Unknown => {
                r#"GENERAL INJECTION PATTERNS:
- Encoding/obfuscation: base64, hex, unicode escapes
- Suspicious URLs or IP addresses
- Command-like strings with shell metacharacters
- Social engineering language
- Misleading comments or instructions"#
            }
        }
    }

    pub fn build_context_prompt(analysis_type: &AnalysisType) -> String {
        match analysis_type {
            AnalysisType::CodeVulnerability => {
                r#"You are a cybersecurity expert performing static analysis on a script.
Your goal is to identify security vulnerabilities that could compromise system security,
enable unauthorized access, or cause damage if the script is executed.

Focus on practical security risks and provide actionable recommendations.
Be thorough but avoid false positives for standard, safe operations."#.to_string()
            }
            AnalysisType::InjectionDetection => {
                r#"You are a security analyst specializing in injection attack detection.
Your goal is to identify potential injection attacks, social engineering attempts,
or malicious content hidden in comments and string literals.

Look for obfuscated content, suspicious patterns, and anything that might indicate
an attempt to trick users or hide malicious functionality."#.to_string()
            }
        }
    }

    pub fn build_system_prompt(analysis_type: &AnalysisType) -> String {
        let base_instructions = r#"You are an AI security analyst. Provide accurate, actionable security analysis.

IMPORTANT GUIDELINES:
- Be precise and specific in your findings
- Provide line numbers when referencing code issues
- Explain the security impact of each finding
- Suggest concrete mitigation steps
- Use the requested output format consistently
- If no significant issues are found, clearly state this"#;

        let context = Self::build_context_prompt(analysis_type);

        format!("{}\n\n{}", base_instructions, context)
    }

    pub fn validate_prompt_length(prompt: &str, max_tokens: usize) -> Result<String, String> {
        // Rough estimation: 1 token ≈ 4 characters
        let estimated_tokens = prompt.len() / 4;

        if estimated_tokens > max_tokens {
            // Truncate the content section while preserving instructions
            let reserved_instruction_chars = 512; // keep room for analysis checklist
            let max_content_chars = max_tokens
                .saturating_mul(4)
                .saturating_sub(reserved_instruction_chars);

            if let Some(content_start) = prompt.find("SCRIPT CONTENT:") {
                if let Some(content_end) = prompt[content_start..].find("\n\nANALYSIS REQUIREMENTS:") {
                    let full_content_end = content_start + content_end;
                    let content_section = &prompt[content_start..full_content_end];

                    if content_section.len() > max_content_chars {
                        const CONTENT_PREFIX: &str = "SCRIPT CONTENT:\n";
                        let content_body = content_section
                            .strip_prefix(CONTENT_PREFIX)
                            .unwrap_or(content_section);

                        let total_chars = content_body.chars().count();
                        let excerpt_len = max_content_chars.min(total_chars);
                        let excerpt = content_body
                            .chars()
                            .take(excerpt_len)
                            .collect::<String>();

                        let truncated_content = format!(
                            "SCRIPT CONTENT:\n```\n{}\n[... TRUNCATED - showing first {} characters of {} total ...]\n```",
                            excerpt,
                            excerpt_len,
                            total_chars
                        );

                        let result = format!(
                            "{}{}\n\nANALYSIS REQUIREMENTS:{}",
                            &prompt[..content_start],
                            truncated_content,
                            &prompt[full_content_end + 2..]
                        );

                        return Ok(result);
                    }
                }
            }

            Err(format!("Prompt too long: {} estimated tokens (max: {})", estimated_tokens, max_tokens))
        } else {
            Ok(prompt.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerability_analysis_prompt() {
        let prompt = PromptTemplate::build_vulnerability_analysis_prompt(
            "echo hello",
            &Language::Bash,
            &ScriptSource::Stdin,
        );

        assert!(prompt.contains("SECURITY ANALYSIS REQUEST"));
        assert!(prompt.contains("bash"));
        assert!(prompt.contains("echo hello"));
        assert!(prompt.contains("VULNERABILITIES FOUND"));
    }

    #[test]
    fn test_injection_analysis_prompt() {
        let content = "# This is a comment\n\"Hello world\"";
        let prompt = PromptTemplate::build_injection_analysis_prompt(
            content,
            &Language::Python,
            &ScriptSource::Stdin,
        );

        assert!(prompt.contains("INJECTION DETECTION"));
        assert!(prompt.contains("python"));
        assert!(prompt.contains("This is a comment"));
        assert!(prompt.contains("SUSPICIOUS PATTERNS"));
    }

    #[test]
    fn test_system_prompt_generation() {
        let prompt = PromptTemplate::build_system_prompt(&AnalysisType::CodeVulnerability);
        assert!(prompt.contains("security analyst"));
        assert!(prompt.contains("vulnerabilities"));

        let prompt = PromptTemplate::build_system_prompt(&AnalysisType::InjectionDetection);
        assert!(prompt.contains("injection attack"));
    }

    #[test]
    fn test_prompt_length_validation() {
        let short_prompt = "Short prompt";
        let result = PromptTemplate::validate_prompt_length(short_prompt, 1000);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), short_prompt);

        let long_content = "x".repeat(10000);
        let long_prompt = format!("SCRIPT CONTENT:\n{}\n\nANALYSIS REQUIREMENTS:\nAnalyze this", long_content);
        let result = PromptTemplate::validate_prompt_length(&long_prompt, 100);
        assert!(result.is_ok());
        assert!(result.unwrap().contains("TRUNCATED"));
    }

    #[test]
    fn test_language_specific_guidance() {
        let bash_guidance = PromptTemplate::get_bash_security_guidance();
        assert!(bash_guidance.contains("Command substitution"));
        assert!(bash_guidance.contains("eval"));

        let python_guidance = PromptTemplate::get_python_security_guidance();
        assert!(python_guidance.contains("exec()"));
        assert!(python_guidance.contains("subprocess"));
    }
}
