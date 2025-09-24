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
You are a cybersecurity expert analyzing this script. Your goal is to help users make informed decisions by distinguishing between legitimate system operations and genuine security threats.

CONTEXT-AWARE RISK ASSESSMENT:
Before rating risk levels, consider the script's apparent purpose and legitimacy:

**LEGITIMATE SCRIPT INDICATORS:**
- Official software installers (Homebrew, Docker, package managers)
- Build/deployment scripts with clear purpose
- System administration utilities
- Scripts from trusted sources (GitHub official repos, major vendors)

**CRITICAL RISK CRITERIA (only for genuinely dangerous scripts):**
- Unexplained privilege escalation beyond script purpose
- Suspicious network communications to unknown hosts
- Data exfiltration or destruction patterns
- Code obfuscation or evasion techniques
- Remote shell establishment without clear purpose

**RISK LEVEL GUIDELINES:**
- CRITICAL: Clear malicious intent or immediate severe threats
- HIGH: Risky operations that exceed apparent legitimate purpose
- MEDIUM: Operations requiring caution but justified by apparent purpose
- LOW: Standard operations with minimal risk in context
- INFO: Best practices or informational notes

REQUIRED ANALYSIS APPROACH:
1. **Script Purpose Assessment**: Identify what this script appears to do
2. **Legitimacy Evaluation**: Does it match expected behavior for its apparent purpose?
3. **Specific Concerns**: List exact lines/operations that warrant attention
4. **Risk Justification**: Explain why each finding matters in context
5. **Actionable Guidance**: Provide specific steps to verify safety

LANGUAGE-SPECIFIC GUIDANCE:
{}

OUTPUT FORMAT:

SCRIPT PURPOSE: [What this script appears to be designed to do]

LEGITIMACY ASSESSMENT: [Legitimate/Suspicious/Unknown] - [Brief reasoning]

RISK LEVEL: [Critical/High/Medium/Low/Info]

SPECIFIC FINDINGS:
[Only list actual concerns - if no significant issues, state "No significant security concerns identified"]

Line XXX: [Specific operation]
→ Concern: [What makes this concerning]
→ Context: [Why this matters for this script type]
→ Verification: [How user can verify this is safe]

OVERALL ASSESSMENT:
[Balanced evaluation considering legitimacy and actual risks]

RECOMMENDED ACTIONS:
[Only if there are genuine concerns to address]
• [Specific, actionable step with clear benefit]
• [Another recommendation if applicable]

CONFIDENCE: [High/Medium/Low] - [Based on script clarity and analysis completeness]

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

    pub fn build_detailed_risk_analysis_prompt(
        content: &str,
        language: &Language,
        source: &ScriptSource,
        output_language: &OutputLanguage,
        initial_findings: &[String],
    ) -> String {
        let findings_context = if initial_findings.is_empty() {
            "No specific preliminary findings provided.".to_string()
        } else {
            format!("Preliminary findings:\n{}", initial_findings.join("\n"))
        };

        format!(
            r#"DETAILED SECURITY RISK ANALYSIS

SCRIPT LANGUAGE: {}
SCRIPT SOURCE: {}
CONTENT LENGTH: {} characters
OUTPUT LANGUAGE: {}

PRELIMINARY ANALYSIS CONTEXT:
{}

SCRIPT CONTENT:
```{}
{}
```

DETAILED ANALYSIS INSTRUCTIONS:
Perform an exhaustive, line-by-line security analysis. Be EXTREMELY DETAILED and SPECIFIC. Even if it seems verbose, provide comprehensive findings.

REQUIRED ANALYSIS DEPTH:
1. **Every Risky Operation**: Analyze EVERY potentially dangerous command, function call, or pattern
2. **Line-by-Line Breakdown**: For scripts with high-risk patterns, analyze significant lines individually
3. **Attack Vector Analysis**: Detail HOW each vulnerability could be exploited
4. **Impact Assessment**: Explain the SPECIFIC damage each vulnerability could cause
5. **Exploitation Scenarios**: Provide realistic step-by-step attack scenarios
6. **Mitigation Details**: Give detailed, actionable remediation steps

ANALYSIS PRIORITIES (BE VERBOSE):
- Network operations (downloads, uploads, connections)
- File system operations (read, write, delete, permission changes)
- Process execution (system calls, subprocess creation, command injection)
- Privilege operations (sudo, su, setuid, file permissions)
- Environment manipulation (PATH, variables, exports)
- User input handling (arguments, environment variables, stdin)
- Cryptographic operations (keys, certificates, signatures)
- Configuration changes (system files, startup scripts)

OUTPUT FORMAT (EXTREMELY DETAILED):

RISK LEVEL: [Critical/High/Medium/Low/Info]

COMPREHENSIVE VULNERABILITY BREAKDOWN:
[For EVERY significant line, provide:]
Line XX: [Exact code snippet]
  - Pattern: [Type of operation/vulnerability]
  - Risk Level: [Critical/High/Medium/Low]
  - Attack Vector: [How this could be exploited]
  - Potential Impact: [Specific damage that could occur]
  - Exploitation Steps: [Step-by-step attack scenario]
  - Likelihood: [High/Medium/Low and why]
  - Mitigation: [Specific steps to reduce risk]

CUMULATIVE RISK ASSESSMENT:
[Overall evaluation considering all findings together]

DETAILED ATTACK SCENARIOS:
[Multiple realistic attack scenarios combining various vulnerabilities]

COMPREHENSIVE MITIGATION STRATEGY:
[Detailed plan for addressing all identified risks]

EXECUTION SAFETY ANALYSIS:
[Detailed assessment of whether execution is advisable and under what conditions]

IMPORTANT: Be exhaustively detailed. Provide all output in {} language."#,
            language.as_str(),
            source,
            content.len(),
            output_language.as_llm_language(),
            findings_context,
            language.as_str().to_lowercase(),
            content,
            output_language.as_llm_language()
        )
    }

    pub fn build_specific_threat_analysis_prompt(
        content: &str,
        language: &Language,
        source: &ScriptSource,
        output_language: &OutputLanguage,
        focus_lines: &[usize],
    ) -> String {
        let lines: Vec<&str> = content.lines().collect();
        let focus_context = if focus_lines.is_empty() {
            "Analyze all high-risk patterns found in the script.".to_string()
        } else {
            let mut context = String::from("Focus on these specific lines:\n");
            for &line_num in focus_lines {
                if let Some(line) = lines.get(line_num.saturating_sub(1)) {
                    context.push_str(&format!("Line {}: {}\n", line_num, line));
                }
            }
            context
        };

        format!(
            r#"SPECIFIC THREAT ANALYSIS

SCRIPT LANGUAGE: {}
SCRIPT SOURCE: {}
OUTPUT LANGUAGE: {}

FOCUS AREAS:
{}

FULL SCRIPT CONTENT:
```{}
{}
```

THREAT-SPECIFIC ANALYSIS INSTRUCTIONS:
Provide ULTRA-DETAILED analysis of specific security threats. Be comprehensive and verbose.

ANALYSIS REQUIREMENTS:
1. **Threat Identification**: Identify every potential security threat
2. **Technical Details**: Explain the technical mechanisms of each threat
3. **Exploitation Methods**: Detail multiple ways each threat could be exploited
4. **Real-World Examples**: Provide examples of how similar vulnerabilities have been exploited
5. **Detection Methods**: Explain how to detect if exploitation has occurred
6. **Forensic Indicators**: What signs would indicate this script was malicious

DETAILED OUTPUT FORMAT:

IDENTIFIED THREATS:

THREAT 1: [Threat Name]
  Location: Line XX: [code snippet]
  Classification: [Type of threat - RCE, Privilege Escalation, Data Exfiltration, etc.]
  Severity: [Critical/High/Medium/Low]

  Technical Analysis:
  - Mechanism: [How the threat works technically]
  - Prerequisites: [What conditions enable this threat]
  - Scope: [What systems/data could be affected]

  Exploitation Analysis:
  - Attack Vectors: [Multiple ways to exploit this]
  - Skill Level Required: [Script kiddie/Intermediate/Advanced]
  - Tools Needed: [What tools an attacker would use]
  - Time to Exploit: [How quickly this could be exploited]

  Impact Analysis:
  - Immediate Effects: [What happens immediately upon exploitation]
  - Secondary Effects: [Follow-on impacts and lateral movement possibilities]
  - Data at Risk: [Specific data types that could be compromised]
  - System Integrity: [How system integrity could be affected]

  Real-World Context:
  - Similar Attacks: [Examples of similar real-world attacks]
  - Common Targets: [Who typically gets targeted by this type of attack]
  - Industry Impact: [How this type of attack affects different industries]

[Repeat for each threat...]

THREAT INTERACTION ANALYSIS:
[How multiple threats could be chained together for more complex attacks]

DEFENSIVE ANALYSIS:
[Detailed breakdown of detection and prevention methods]

IMPORTANT: Be extremely thorough and detailed. Provide all output in {} language."#,
            language.as_str(),
            source,
            output_language.as_llm_language(),
            focus_context,
            language.as_str().to_lowercase(),
            content,
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
            AnalysisType::DetailedRiskAnalysis => {
                r#"DETAILED RISK ANALYSIS FOCUS:
Perform comprehensive, exhaustive analysis of all security risks. Be verbose and thorough.

ANALYSIS REQUIREMENTS:
1. Analyze EVERY potentially risky operation in extreme detail
2. Provide line-by-line breakdown of significant security patterns
3. Detail multiple attack vectors for each vulnerability
4. Explain technical mechanisms and exploitation methods
5. Assess realistic impact and likelihood of exploitation
6. Provide comprehensive mitigation strategies

VERBOSITY EXPECTATION:
- Be extremely detailed even if it seems excessive
- Provide multiple examples and scenarios
- Include technical explanations and context
- Detail both immediate and secondary impacts
- Cover multiple exploitation methods per vulnerability

Remember: The goal is comprehensive understanding, not brevity."#.to_string()
            }
            AnalysisType::SpecificThreatAnalysis => {
                r#"SPECIFIC THREAT ANALYSIS FOCUS:
Provide ultra-detailed analysis of specific security threats and attack patterns.

ANALYSIS DEPTH:
1. Technical mechanism analysis for each threat
2. Multiple exploitation methods and attack vectors
3. Real-world attack examples and case studies
4. Forensic indicators and detection methods
5. Threat actor profiling and motivation analysis
6. Industry-specific impact assessment

COMPREHENSIVE COVERAGE:
- Include threat classification and severity assessment
- Detail prerequisite conditions and attack requirements
- Analyze threat interactions and chaining possibilities
- Provide extensive mitigation and detection guidance
- Consider various threat actor skill levels and motivations

Focus on actionable intelligence and comprehensive threat understanding."#.to_string()
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
