use crate::models::{Language, AnalysisType, ScriptSource, OutputLanguage};

pub struct PromptTemplate;

impl PromptTemplate {
    pub fn build_vulnerability_analysis_prompt(
        content: &str,
        language: &Language,
        source: &ScriptSource,
        output_language: &OutputLanguage,
    ) -> String {
        let language_specific_guidance = match language {
            Language::Bash => Self::get_bash_security_guidance(),
            Language::Python => Self::get_python_security_guidance(),
            Language::Unknown => "Analyze this script for general security issues.",
        };

        format!(
            r#"SECURITY VULNERABILITY ANALYSIS

SCRIPT LANGUAGE: {}
SCRIPT SOURCE: {}
CONTENT LENGTH: {} characters
OUTPUT LANGUAGE: {}

SCRIPT CONTENT:
```{}
{}
```

ANALYSIS INSTRUCTIONS:
You are a security expert analyzing this script for vulnerabilities. Focus on providing CONCRETE, ACTIONABLE findings that help users make informed decisions.

CRITICAL ANALYSIS CRITERIA:
- ONLY flag as CRITICAL if there are immediate, severe security risks (remote code execution, privilege escalation, data destruction)
- HIGH risk for operations requiring elevated privileges or network access with potential for abuse
- MEDIUM risk for operations that access system resources or modify files in controlled ways
- LOW risk for standard operations with minimal security impact
- INFO for informational findings or best practice suggestions

SPECIFIC REQUIREMENTS:
1. **Line-by-Line Analysis**: Reference specific line numbers (e.g., "Line 42: curl command")
2. **Context Assessment**: Consider if this is likely a legitimate script (e.g., official installers, build scripts)
3. **Risk Justification**: Explain WHY each finding is dangerous, not just WHAT it does
4. **Practical Impact**: Focus on realistic attack scenarios, not theoretical vulnerabilities
5. **False Positive Avoidance**: Don't flag standard operations as dangerous unless there's clear risk

LANGUAGE-SPECIFIC GUIDANCE:
{}

OUTPUT FORMAT (BE SPECIFIC):

RISK LEVEL: [Critical/High/Medium/Low/Info]

SPECIFIC VULNERABILITIES:
Line X: [Vulnerable pattern] - [Why this is dangerous] - [Attack scenario]
Line Y: [Another finding] - [Security implication] - [Realistic impact]

SECURITY ASSESSMENT:
[Overall evaluation considering script purpose, source, and actual risks]

ACTIONABLE RECOMMENDATIONS:
1. [Specific action] - [Why this helps]
2. [Another recommendation] - [Security benefit]

CONFIDENCE: [High/Medium/Low] - [Reasoning for confidence level]

CONTEXT CONSIDERATIONS:
- Is this likely a legitimate script? (installer, build tool, etc.)
- Are the risky operations justified by the script's apparent purpose?
- What would an attacker realistically gain from this script?

IMPORTANT: Provide all output in {} language. Be precise and helpful, not alarmist."#,
            language.as_str(),
            source,
            content.len(),
            output_language.as_llm_language(),
            language.as_str().to_lowercase(),
            content,
            language_specific_guidance,
            output_language.as_llm_language()
        )
    }

    pub fn build_injection_analysis_prompt(
        content: &str,
        language: &Language,
        source: &ScriptSource,
        output_language: &OutputLanguage,
    ) -> String {
        format!(
            r#"INJECTION DETECTION ANALYSIS

SCRIPT LANGUAGE: {}
SCRIPT SOURCE: {}
OUTPUT LANGUAGE: {}

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

CONFIDENCE LEVEL: [High/Medium/Low]

IMPORTANT: Please provide all output in {} language."#,
            language.as_str(),
            source,
            output_language.as_llm_language(),
            content,
            language.as_str(),
            Self::get_injection_patterns_guidance(language),
            output_language.as_llm_language()
        )
    }

    fn get_bash_security_guidance() -> &'static str {
        r#"BASH SECURITY ANALYSIS PRIORITIES:

CRITICAL RISK INDICATORS (Immediate danger):
- curl/wget | bash patterns (remote code execution)
- eval with user input (arbitrary code execution)
- Uncontrolled privilege escalation (sudo without validation)
- File operations on system directories without checks (/etc, /usr, /bin)

HIGH RISK PATTERNS (Potential for abuse):
- Network downloads to executable locations
- Command substitution with external input: $(curl ...), `wget ...`
- File modifications in sensitive areas
- Process substitution: <(curl), >(command)
- Password/credential handling in clear text

LEGITIMATE vs SUSPICIOUS PATTERNS:
✓ NORMAL: Package manager operations (apt, brew, yum)
✓ NORMAL: Standard file operations in user directories
✓ NORMAL: Environment setup and path modification
✗ SUSPICIOUS: Downloading and executing without verification
✗ SUSPICIOUS: Disabling security features (set +e without context)
✗ SUSPICIOUS: Unusual network operations or data exfiltration patterns

CONTEXT-AWARE ANALYSIS:
- Official installers (Homebrew, Node.js, etc.) have expected risky patterns
- Build scripts legitimately need compilation and system access
- Development tools require elevated permissions for installation
- Consider script source and apparent purpose before flagging as malicious

FOCUS ON:
1. Line-specific findings with exact line numbers
2. Realistic attack scenarios for each finding
3. Whether risky operations are justified by script purpose
4. Actionable recommendations for genuine security improvements"#
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
                r#"VULNERABILITY ANALYSIS FOCUS:
Your task is to identify genuine security vulnerabilities in this script that pose real risks to users.

ANALYSIS PRIORITIES:
1. Distinguish between LEGITIMATE operations and ACTUAL threats
2. Consider script context (official installer, development tool, etc.)
3. Focus on exploitable vulnerabilities with realistic attack scenarios
4. Provide specific line numbers and concrete explanations
5. Avoid flagging standard operations as dangerous unless genuinely risky

DECISION FRAMEWORK:
- Would a malicious actor realistically exploit this?
- Are the risky operations justified by the script's apparent purpose?
- What specific harm could result from this vulnerability?
- How can users mitigate genuine risks while maintaining functionality?

Remember: Users need practical guidance, not theoretical security lectures."#.to_string()
            }
            AnalysisType::InjectionDetection => {
                r#"INJECTION DETECTION FOCUS:
Analyze comments and string literals for potential injection attacks or malicious content.

DETECTION PRIORITIES:
1. Obfuscated or encoded content that might hide malicious code
2. Social engineering attempts in comments or strings
3. Unusual patterns that suggest injection attempts
4. Suspicious URLs, domains, or IP addresses
5. Command injection patterns in string literals

CONTEXT AWARENESS:
- Legitimate scripts may contain complex patterns for valid reasons
- Focus on genuinely suspicious content, not normal script complexity
- Consider the overall script purpose when evaluating findings
- Distinguish between technical complexity and actual malicious intent"#.to_string()
            }
        }
    }

    pub fn build_system_prompt(analysis_type: &AnalysisType, output_language: &OutputLanguage) -> String {
        let base_instructions = r#"You are a practical cybersecurity analyst helping users make informed decisions about script safety.

CORE PRINCIPLES:
- Provide CONCRETE, LINE-SPECIFIC findings with exact line numbers
- Explain WHY something is dangerous, not just WHAT it does
- Consider CONTEXT: official installers vs suspicious scripts
- Focus on REALISTIC threats, not theoretical vulnerabilities
- Be HELPFUL, not alarmist - users need actionable guidance
- Distinguish between LEGITIMATE risky operations and ACTUAL threats

ANALYSIS APPROACH:
1. Identify the script's apparent purpose (installer, build tool, etc.)
2. Evaluate if risky operations are justified by that purpose
3. Flag only genuine security concerns with clear explanations
4. Provide specific line references: "Line 42: curl command downloads..."
5. Suggest practical improvements where applicable

RISK ASSESSMENT STANDARDS:
- CRITICAL: Immediate, severe threats (RCE, data destruction, malware)
- HIGH: Operations with significant abuse potential
- MEDIUM: Standard system operations with some risk
- LOW: Minor concerns or best practice suggestions
- INFO: Educational findings, no immediate risk"#;

        let context = Self::build_context_prompt(analysis_type);

        format!("{}\n\n{}\n\nOUTPUT LANGUAGE: {}", base_instructions, context, output_language.as_llm_language())
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
            &OutputLanguage::English,
        );

        assert!(prompt.contains("SECURITY ANALYSIS REQUEST"));
        assert!(prompt.contains("bash"));
        assert!(prompt.contains("echo hello"));
        assert!(prompt.contains("VULNERABILITIES FOUND"));
        assert!(prompt.contains("OUTPUT LANGUAGE: English"));
    }

    #[test]
    fn test_injection_analysis_prompt() {
        let content = "# This is a comment\n\"Hello world\"";
        let prompt = PromptTemplate::build_injection_analysis_prompt(
            content,
            &Language::Python,
            &ScriptSource::Stdin,
            &OutputLanguage::English,
        );

        assert!(prompt.contains("INJECTION DETECTION"));
        assert!(prompt.contains("python"));
        assert!(prompt.contains("This is a comment"));
        assert!(prompt.contains("SUSPICIOUS PATTERNS"));
        assert!(prompt.contains("OUTPUT LANGUAGE: English"));
    }

    #[test]
    fn test_system_prompt_generation() {
        let prompt = PromptTemplate::build_system_prompt(&AnalysisType::CodeVulnerability, &OutputLanguage::English);
        assert!(prompt.contains("security analyst"));
        assert!(prompt.contains("vulnerabilities"));
        assert!(prompt.contains("OUTPUT LANGUAGE: English"));

        let prompt = PromptTemplate::build_system_prompt(&AnalysisType::InjectionDetection, &OutputLanguage::Japanese);
        assert!(prompt.contains("injection attack"));
        assert!(prompt.contains("OUTPUT LANGUAGE: Japanese"));
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
