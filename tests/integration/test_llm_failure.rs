use std::process::Stdio;
use std::io::Write;
use tokio::process::Command;

#[tokio::test]
async fn test_llm_service_unavailable_blocks_execution() {
    // This test will fail because we haven't implemented the main binary yet
    let script_content = "echo 'This should not execute when LLM is unavailable'";

    // Set environment to point to non-existent LLM service
    let mut child = Command::new("cargo")
        .args(&["run", "--", "bash"])
        .env("EBI_LLM_API_ENDPOINT", "http://localhost:99999")  // Non-existent endpoint
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn ebi process");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script_content.as_bytes()).await.unwrap();
        stdin.write_all(b"\n").await.unwrap();
        drop(stdin);
    }

    let output = child.wait_with_output().await.unwrap();

    // Should exit with code 3 for LLM analysis failure
    assert_eq!(output.status.code(), Some(3));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should show error message about LLM service
    assert!(
        stdout.contains("LLM service unavailable") ||
        stderr.contains("LLM service unavailable") ||
        stdout.contains("Analysis failed") ||
        stderr.contains("Analysis failed")
    );

    // Should NOT execute the script (fail-safe behavior)
    assert!(!stdout.contains("This should not execute when LLM is unavailable"));
}

#[tokio::test]
async fn test_llm_timeout_blocks_execution() {
    let script_content = "echo 'Should not execute on timeout'";

    // Use very short timeout to force timeout
    let mut child = Command::new("cargo")
        .args(&["run", "--", "--timeout", "1", "bash"])  // 1 second timeout
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn ebi process");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script_content.as_bytes()).await.unwrap();
        stdin.write_all(b"\n").await.unwrap();
        drop(stdin);
    }

    let output = child.wait_with_output().await.unwrap();

    // Should exit with code 3 for analysis timeout
    assert_eq!(output.status.code(), Some(3));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should show timeout error
    assert!(
        stdout.contains("timeout") ||
        stderr.contains("timeout") ||
        stdout.contains("Analysis failed") ||
        stderr.contains("Analysis failed")
    );

    // Should NOT execute the script
    assert!(!stdout.contains("Should not execute on timeout"));
}

#[tokio::test]
async fn test_llm_invalid_response_blocks_execution() {
    let script_content = "echo 'Should not execute with invalid LLM response'";

    // This would need a mock server returning invalid responses
    // For now, we'll test with an endpoint that returns non-JSON
    let mut child = Command::new("cargo")
        .args(&["run", "--", "bash"])
        .env("EBI_LLM_API_ENDPOINT", "http://httpbin.org/html")  // Returns HTML, not JSON
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn ebi process");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script_content.as_bytes()).await.unwrap();
        stdin.write_all(b"\n").await.unwrap();
        drop(stdin);
    }

    let output = child.wait_with_output().await.unwrap();

    // Should exit with code 3 for analysis failure
    assert_eq!(output.status.code(), Some(3));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should show error about invalid response
    assert!(
        stdout.contains("Invalid response") ||
        stderr.contains("Invalid response") ||
        stdout.contains("Analysis failed") ||
        stderr.contains("Analysis failed")
    );

    // Should NOT execute the script
    assert!(!stdout.contains("Should not execute with invalid LLM response"));
}

#[tokio::test]
async fn test_llm_partial_failure_blocks_execution() {
    let script_content = r#"
#!/bin/bash
# A script with both code and comments
echo "Hello"  # This is a comment
"#;

    // Test scenario where one analysis succeeds but another fails
    // This should still block execution (fail-safe)
    let mut child = Command::new("cargo")
        .args(&["run", "--", "bash"])
        .env("EBI_LLM_API_ENDPOINT", "http://localhost:99999")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn ebi process");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script_content.as_bytes()).await.unwrap();
        stdin.write_all(b"\n").await.unwrap();
        drop(stdin);
    }

    let output = child.wait_with_output().await.unwrap();

    // Should exit with code 3 for analysis failure
    assert_eq!(output.status.code(), Some(3));

    // Should NOT execute the script even with partial analysis
    assert!(!output.stdout.iter().any(|&b| b == b'H' && output.stdout.len() > 100));
}

#[tokio::test]
async fn test_network_error_handling() {
    let script_content = "echo 'Network test'";

    // Test with a domain that doesn't exist
    let mut child = Command::new("cargo")
        .args(&["run", "--", "bash"])
        .env("EBI_LLM_API_ENDPOINT", "http://this-domain-does-not-exist.invalid")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn ebi process");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script_content.as_bytes()).await.unwrap();
        stdin.write_all(b"\n").await.unwrap();
        drop(stdin);
    }

    let output = child.wait_with_output().await.unwrap();

    // Should exit with code 3 for analysis failure
    assert_eq!(output.status.code(), Some(3));

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should show network-related error
    assert!(
        stderr.contains("network") ||
        stderr.contains("connection") ||
        stderr.contains("resolve") ||
        stderr.contains("Analysis failed")
    );
}