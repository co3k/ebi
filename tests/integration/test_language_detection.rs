use std::process::Stdio;
use std::io::Write;
use tokio::process::Command;

#[tokio::test]
async fn test_explicit_language_flag() {
    // This test will fail because we haven't implemented the main binary yet
    let python_script = r#"
print("Hello from Python")
import os
os.system("echo test")
"#;

    // Explicitly specify Python language
    let mut child = Command::new("cargo")
        .args(&["run", "--", "--lang", "python", "python3"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn ebi process");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(python_script.as_bytes()).await.unwrap();
        drop(stdin);
    }

    let output = child.wait_with_output().await.unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should show Python in the analysis report
    assert!(stdout.contains("EBI SECURITY ANALYSIS REPORT"));
    assert!(stdout.contains("Python") || stdout.contains("python"));
}

#[tokio::test]
async fn test_command_name_inference() {
    let bash_script = r#"
#!/bin/bash
echo "Detected from command name"
"#;

    // Should infer bash from command name
    let mut child = Command::new("cargo")
        .args(&["run", "--", "bash"])  // Command name should indicate bash
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn ebi process");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(bash_script.as_bytes()).await.unwrap();
        drop(stdin);
    }

    let output = child.wait_with_output().await.unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("EBI SECURITY ANALYSIS REPORT"));
    assert!(stdout.contains("Bash") || stdout.contains("bash"));
}

#[tokio::test]
async fn test_shebang_detection() {
    let python_script_with_shebang = r#"#!/usr/bin/env python3
import sys
print("Detected from shebang")
sys.exit(0)
"#;

    // Use generic command, should detect Python from shebang
    let mut child = Command::new("cargo")
        .args(&["run", "--", "env", "python3"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn ebi process");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(python_script_with_shebang.as_bytes()).await.unwrap();
        drop(stdin);
    }

    let output = child.wait_with_output().await.unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("EBI SECURITY ANALYSIS REPORT"));
    assert!(stdout.contains("Python") || stdout.contains("python"));
}

#[tokio::test]
async fn test_language_priority_flag_wins() {
    let script_content = r#"#!/usr/bin/env python3
# This has a Python shebang but we'll force it to be bash
echo "Priority test"
"#;

    // Explicit flag should override shebang
    let mut child = Command::new("cargo")
        .args(&["run", "--", "--lang", "bash", "python3"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn ebi process");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script_content.as_bytes()).await.unwrap();
        drop(stdin);
    }

    let output = child.wait_with_output().await.unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should be treated as bash due to explicit flag
    assert!(stdout.contains("EBI SECURITY ANALYSIS REPORT"));
    assert!(stdout.contains("Bash") || stdout.contains("bash"));
}

#[tokio::test]
async fn test_unknown_language_error() {
    let ambiguous_script = r#"
some random text
that doesn't look like any programming language
@#$%^&*()
"#;

    let mut child = Command::new("cargo")
        .args(&["run", "--", "unknown-interpreter"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn ebi process");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(ambiguous_script.as_bytes()).await.unwrap();
        drop(stdin);
    }

    let output = child.wait_with_output().await.unwrap();

    // Should exit with code 2 for parse error
    assert_eq!(output.status.code(), Some(2));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should show error about unknown language
    assert!(
        stdout.contains("Cannot determine script language") ||
        stderr.contains("Cannot determine script language") ||
        stdout.contains("Unknown language") ||
        stderr.contains("Unknown language")
    );
}

#[tokio::test]
async fn test_various_python_commands() {
    let python_script = "print('Python version test')";

    let python_commands = vec!["python", "python3", "python3.9", "python3.11"];

    for cmd in python_commands {
        let mut child = Command::new("cargo")
            .args(&["run", "--", cmd])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to spawn ebi process");

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(python_script.as_bytes()).await.unwrap();
            drop(stdin);
        }

        let output = child.wait_with_output().await.unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);

        // All should be detected as Python
        assert!(stdout.contains("Python") || stdout.contains("python"),
                "Failed for command: {}", cmd);
    }
}

#[tokio::test]
async fn test_various_shell_commands() {
    let shell_script = "echo 'Shell test'";

    let shell_commands = vec!["bash", "sh", "zsh", "dash"];

    for cmd in shell_commands {
        let mut child = Command::new("cargo")
            .args(&["run", "--", cmd])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to spawn ebi process");

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(shell_script.as_bytes()).await.unwrap();
            drop(stdin);
        }

        let output = child.wait_with_output().await.unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);

        // All should be detected as bash/shell
        assert!(
            stdout.contains("Bash") ||
            stdout.contains("bash") ||
            stdout.contains("Shell") ||
            stdout.contains("shell"),
            "Failed for command: {}", cmd
        );
    }
}