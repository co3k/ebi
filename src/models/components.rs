use serde::{Deserialize, Serialize};
use crate::models::script::Language;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScriptComponents {
    pub code_body: String,         // Code with comments/literals removed
    pub comments: Vec<String>,      // All extracted comments
    pub string_literals: Vec<String>, // All extracted string literals
    pub metadata: ParseMetadata,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParseMetadata {
    pub total_nodes: usize,
    pub parse_time_ms: u64,
    pub truncated: bool,
    pub priority_nodes: Vec<NodeInfo>,
    pub language: Language,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeInfo {
    pub node_type: String,
    pub line_start: usize,
    pub line_end: usize,
    pub security_relevance: SecurityRelevance,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SecurityRelevance {
    Critical,  // exec, eval, system calls
    High,      // file I/O, network
    Medium,    // env vars, subprocess
    Low,       // regular code
}

impl ScriptComponents {
    pub fn new() -> Self {
        Self {
            code_body: String::new(),
            comments: Vec::new(),
            string_literals: Vec::new(),
            metadata: ParseMetadata::new(),
        }
    }

    pub fn with_code_body(mut self, code_body: String) -> Self {
        self.code_body = code_body;
        self
    }

    pub fn add_comment(&mut self, comment: String) {
        self.comments.push(comment);
    }

    pub fn add_string_literal(&mut self, literal: String) {
        self.string_literals.push(literal);
    }

    pub fn add_function_definition(&mut self, name: String, line: usize) {
        self.add_node_info(NodeInfo {
            node_type: format!("function_definition: {}", name),
            line_start: line,
            line_end: line,
            security_relevance: SecurityRelevance::Low,
        });
    }

    pub fn add_class_definition(&mut self, name: String, line: usize) {
        self.add_node_info(NodeInfo {
            node_type: format!("class_definition: {}", name),
            line_start: line,
            line_end: line,
            security_relevance: SecurityRelevance::Low,
        });
    }

    pub fn add_variable_assignment(&mut self, name: String, line: usize) {
        self.add_node_info(NodeInfo {
            node_type: format!("variable_assignment: {}", name),
            line_start: line,
            line_end: line,
            security_relevance: SecurityRelevance::Medium,
        });
    }

    pub fn add_import_statement(&mut self, statement: String, line: usize) {
        self.add_node_info(NodeInfo {
            node_type: format!("import: {}", statement),
            line_start: line,
            line_end: line,
            security_relevance: SecurityRelevance::Medium,
        });
    }

    pub fn add_command_substitution(&mut self, command: String) {
        // Extract line number from command if possible
        let line = if command.starts_with("Line ") {
            command[5..].split(':').next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1)
        } else {
            1
        };

        self.add_node_info(NodeInfo {
            node_type: format!("command_substitution: {}", command),
            line_start: line,
            line_end: line,
            security_relevance: SecurityRelevance::Critical,
        });
    }

    pub fn add_node_info(&mut self, node_info: NodeInfo) {
        self.metadata.priority_nodes.push(node_info);
        // Keep nodes sorted by security relevance
        self.metadata.priority_nodes.sort_by(|a, b| {
            use SecurityRelevance::*;
            match (&a.security_relevance, &b.security_relevance) {
                (Critical, Critical) => a.line_start.cmp(&b.line_start),
                (Critical, _) => std::cmp::Ordering::Less,
                (_, Critical) => std::cmp::Ordering::Greater,
                (High, High) => a.line_start.cmp(&b.line_start),
                (High, _) => std::cmp::Ordering::Less,
                (_, High) => std::cmp::Ordering::Greater,
                (Medium, Medium) => a.line_start.cmp(&b.line_start),
                (Medium, _) => std::cmp::Ordering::Less,
                (_, Medium) => std::cmp::Ordering::Greater,
                (Low, Low) => a.line_start.cmp(&b.line_start),
            }
        });
    }

    pub fn has_content(&self) -> bool {
        !self.code_body.trim().is_empty() ||
        !self.comments.is_empty() ||
        !self.string_literals.is_empty()
    }

    pub fn total_extracted_items(&self) -> usize {
        self.comments.len() + self.string_literals.len()
    }

    pub fn get_critical_nodes(&self) -> Vec<&NodeInfo> {
        self.metadata.priority_nodes
            .iter()
            .filter(|node| matches!(node.security_relevance, SecurityRelevance::Critical))
            .collect()
    }

    pub fn get_high_risk_nodes(&self) -> Vec<&NodeInfo> {
        self.metadata.priority_nodes
            .iter()
            .filter(|node| matches!(
                node.security_relevance,
                SecurityRelevance::Critical | SecurityRelevance::High
            ))
            .collect()
    }

    /// Get a string representation suitable for LLM analysis
    pub fn get_analysis_content(&self, language: &Language, include_priority_nodes: bool) -> String {
        let mut content = String::new();

        // Add language context
        content.push_str(&format!("# {} Script Analysis\n\n", language.as_str()));

        // Add code body
        if !self.code_body.trim().is_empty() {
            content.push_str("## Code Logic:\n");
            content.push_str(&self.code_body);
            content.push_str("\n\n");
        }

        // Add priority nodes if requested
        if include_priority_nodes && !self.metadata.priority_nodes.is_empty() {
            content.push_str("## Security-Relevant Operations:\n");
            for node in &self.metadata.priority_nodes {
                content.push_str(&format!(
                    "- {}: {} (lines {}-{})\n",
                    node.security_relevance.as_str(),
                    node.node_type,
                    node.line_start,
                    node.line_end
                ));
            }
            content.push_str("\n");
        }

        content
    }

    /// Get comments and strings for injection analysis
    pub fn get_injection_content(&self) -> String {
        let mut content = String::new();

        if !self.comments.is_empty() {
            content.push_str("## Comments:\n");
            for (i, comment) in self.comments.iter().enumerate() {
                content.push_str(&format!("{}. {}\n", i + 1, comment));
            }
            content.push_str("\n");
        }

        if !self.string_literals.is_empty() {
            content.push_str("## String Literals:\n");
            for (i, literal) in self.string_literals.iter().enumerate() {
                content.push_str(&format!("{}. {}\n", i + 1, literal));
            }
            content.push_str("\n");
        }

        if content.is_empty() {
            content.push_str("No comments or string literals found.\n");
        }

        content
    }
}

impl ParseMetadata {
    pub fn new() -> Self {
        Self {
            total_nodes: 0,
            parse_time_ms: 0,
            truncated: false,
            priority_nodes: Vec::new(),
            language: Language::Unknown,
        }
    }

    pub fn with_language(mut self, language: Language) -> Self {
        self.language = language;
        self
    }

    pub fn with_total_nodes(mut self, count: usize) -> Self {
        self.total_nodes = count;
        self
    }

    pub fn with_parse_time(mut self, time_ms: u64) -> Self {
        self.parse_time_ms = time_ms;
        self
    }

    pub fn mark_truncated(mut self) -> Self {
        self.truncated = true;
        self
    }
}

impl SecurityRelevance {
    pub fn as_str(&self) -> &'static str {
        match self {
            SecurityRelevance::Critical => "CRITICAL",
            SecurityRelevance::High => "HIGH",
            SecurityRelevance::Medium => "MEDIUM",
            SecurityRelevance::Low => "LOW",
        }
    }

    pub fn from_node_type(node_type: &str) -> Self {
        match node_type.to_lowercase().as_str() {
            // Critical operations
            "command_substitution" | "process_substitution" | "eval" | "exec" => SecurityRelevance::Critical,

            // High risk operations
            "file_redirect" | "pipe" | "curl" | "wget" | "ssh" | "scp" => SecurityRelevance::High,

            // Medium risk
            "variable_assignment" | "export" | "source" | "import" => SecurityRelevance::Medium,

            // Everything else is low
            _ => SecurityRelevance::Low,
        }
    }
}

impl Default for ScriptComponents {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for ParseMetadata {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_components_creation() {
        let mut components = ScriptComponents::new();

        assert!(!components.has_content());

        components.add_comment("This is a comment".to_string());
        components.add_string_literal("Hello world".to_string());
        components = components.with_code_body("echo test".to_string());

        assert!(components.has_content());
        assert_eq!(components.total_extracted_items(), 2);
    }

    #[test]
    fn test_node_priority_sorting() {
        let mut components = ScriptComponents::new();

        components.add_node_info(NodeInfo {
            node_type: "echo".to_string(),
            line_start: 1,
            line_end: 1,
            security_relevance: SecurityRelevance::Low,
        });

        components.add_node_info(NodeInfo {
            node_type: "eval".to_string(),
            line_start: 2,
            line_end: 2,
            security_relevance: SecurityRelevance::Critical,
        });

        // Critical should come first
        assert_eq!(components.metadata.priority_nodes[0].security_relevance, SecurityRelevance::Critical);
        assert_eq!(components.metadata.priority_nodes[1].security_relevance, SecurityRelevance::Low);
    }

    #[test]
    fn test_security_relevance_from_node_type() {
        assert_eq!(SecurityRelevance::from_node_type("eval"), SecurityRelevance::Critical);
        assert_eq!(SecurityRelevance::from_node_type("curl"), SecurityRelevance::High);
        assert_eq!(SecurityRelevance::from_node_type("export"), SecurityRelevance::Medium);
        assert_eq!(SecurityRelevance::from_node_type("echo"), SecurityRelevance::Low);
    }

    #[test]
    fn test_analysis_content_generation() {
        let mut components = ScriptComponents::new();
        components = components.with_code_body("echo hello".to_string());
        components.add_comment("This is a test".to_string());

        let content = components.get_analysis_content(&Language::Bash, false);
        assert!(content.contains("bash Script Analysis"));
        assert!(content.contains("echo hello"));

        let injection_content = components.get_injection_content();
        assert!(content.contains("Comments"));
        assert!(injection_content.contains("This is a test"));
    }
}