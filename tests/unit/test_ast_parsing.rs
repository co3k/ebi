use ebi::parser::ComponentExtractor;
use ebi::models::{Language, SecurityRelevance};

#[test]
fn bash_extractor_marks_command_substitution_as_critical() {
    let script = r#"#!/bin/bash
safe_var="value"
output=$(curl http://example.com/script.sh)
"#;

    let extractor = ComponentExtractor::new();
    let components = extractor
        .extract_from_script(script, Language::Bash)
        .expect("bash extraction should succeed");

    assert!(components.comments.iter().any(|c| c.contains("SHEBANG")));

    let has_command_substitution = components
        .metadata
        .priority_nodes
        .iter()
        .any(|node| node.node_type.contains("command_substitution")
            && node.security_relevance == SecurityRelevance::Critical);

    assert!(has_command_substitution, "expected command substitution to be flagged as critical");
}

#[test]
fn python_extractor_detects_subprocess_shell_true() {
    let script = r#"import subprocess
subprocess.run("ls", shell=True)
"#;

    let extractor = ComponentExtractor::new();
    let components = extractor
        .extract_from_script(script, Language::Python)
        .expect("python extraction should succeed");

    let has_dangerous_subprocess = components
        .metadata
        .priority_nodes
        .iter()
        .any(|node| node.node_type == "subprocess_call"
            && node.security_relevance == SecurityRelevance::Critical);

    assert!(has_dangerous_subprocess, "expected subprocess with shell=True to be critical");

    let has_dangerous_import = components
        .metadata
        .priority_nodes
        .iter()
        .any(|node| node.node_type.starts_with("dangerous_import: subprocess"));

    assert!(has_dangerous_import, "expected dangerous import tracking");
}
