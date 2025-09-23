use std::process::Stdio;
use std::io::Write;
use tokio::process::Command;

#[tokio::test]
async fn test_analyze_simple_bash_script() {
    // This test will fail because we haven't implemented the main binary yet
    let script_content = "echo 'Hello, World!'";

    let mut child = Command::new("cargo")
        .args(&["run", "--", "bash"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn ebi process");

    // Write script to stdin
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script_content.as_bytes()).await.unwrap();
        stdin.write_all(b"\n").await.unwrap();
        drop(stdin); // Close stdin
    }

    let output = child.wait_with_output().await.unwrap();

    // Should show analysis report
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("EBI SECURITY ANALYSIS REPORT"));
    assert!(stdout.contains("Script Type: Bash"));
    assert!(stdout.contains("Risk Level:"));
    assert!(stdout.contains("Execute this script? (yes/no):"));

    // For this test, we'll simulate user declining
    // In a real scenario, this would need user input simulation
}

#[tokio::test]
async fn test_analyze_python_script() {
    let script_content = r#"
import sys
print("Hello from Python")
sys.exit(0)
"#;

    let mut child = Command::new("cargo")
        .args(&["run", "--", "--lang", "python", "python"])
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

    assert!(stdout.contains("EBI SECURITY ANALYSIS REPORT"));
    assert!(stdout.contains("Script Type:"));
    assert!(stdout.contains("Python") || stdout.contains("python"));
}

#[tokio::test]
async fn test_safe_script_analysis() {
    let script_content = r#"
#!/bin/bash
# A simple, safe script
date
whoami
pwd
"#;

    let mut child = Command::new("cargo")
        .args(&["run", "--", "bash"])
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

    // Should show low or no risk
    assert!(stdout.contains("Risk Level:"));
    // Should not show critical or high risk for this safe script
    assert!(!stdout.contains("CRITICAL"));
}

#[tokio::test]
async fn test_script_with_arguments() {
    let script_content = "echo $1 $2";

    let mut child = Command::new("cargo")
        .args(&["run", "--", "bash", "-s", "--", "arg1", "arg2"])
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

    // Should show that arguments are being passed through
    assert!(stdout.contains("EBI SECURITY ANALYSIS REPORT"));
}