use std::process::Stdio;
use std::io::Write;
use tokio::process::Command;

#[tokio::test]
async fn test_user_declines_execution() {
    // This test will fail because we haven't implemented the main binary yet
    let script_content = "echo 'This should not execute'";

    let mut child = Command::new("cargo")
        .args(&["run", "--", "bash"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn ebi process");

    if let Some(mut stdin) = child.stdin.take() {
        // Write script content
        stdin.write_all(script_content.as_bytes()).await.unwrap();
        stdin.write_all(b"\n").await.unwrap();

        // Simulate user typing "no" when prompted
        stdin.write_all(b"no\n").await.unwrap();
        drop(stdin);
    }

    let output = child.wait_with_output().await.unwrap();

    // Should exit with code 1 for user decline
    assert_eq!(output.status.code(), Some(1));

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should show analysis report
    assert!(stdout.contains("EBI SECURITY ANALYSIS REPORT"));
    assert!(stdout.contains("Execute this script? (yes/no):"));

    // Should NOT contain the script output since user declined
    assert!(!stdout.contains("This should not execute"));
}

#[tokio::test]
async fn test_user_declines_with_various_inputs() {
    let test_cases = vec!["n", "N", "no", "NO", "No"];

    for decline_input in test_cases {
        let script_content = "echo 'Should not run'";

        let mut child = Command::new("cargo")
            .args(&["run", "--", "bash"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to spawn ebi process");

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(script_content.as_bytes()).await.unwrap();
            stdin.write_all(b"\n").await.unwrap();
            stdin.write_all(decline_input.as_bytes()).await.unwrap();
            stdin.write_all(b"\n").await.unwrap();
            drop(stdin);
        }

        let output = child.wait_with_output().await.unwrap();

        // All should result in user decline (exit code 1)
        assert_eq!(output.status.code(), Some(1),
                   "Failed for input: {}", decline_input);

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(!stdout.contains("Should not run"));
    }
}

#[tokio::test]
async fn test_user_accepts_execution() {
    let script_content = "echo 'User accepted execution'";

    let mut child = Command::new("cargo")
        .args(&["run", "--", "bash"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn ebi process");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script_content.as_bytes()).await.unwrap();
        stdin.write_all(b"\n").await.unwrap();

        // Simulate user typing "yes" when prompted
        stdin.write_all(b"yes\n").await.unwrap();
        drop(stdin);
    }

    let output = child.wait_with_output().await.unwrap();

    // Should exit with code 0 for successful execution
    assert_eq!(output.status.code(), Some(0));

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should show analysis report AND script output
    assert!(stdout.contains("EBI SECURITY ANALYSIS REPORT"));
    assert!(stdout.contains("User accepted execution"));
}

#[tokio::test]
async fn test_invalid_user_input_reprompt() {
    let script_content = "echo 'test'";

    let mut child = Command::new("cargo")
        .args(&["run", "--", "bash"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn ebi process");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script_content.as_bytes()).await.unwrap();
        stdin.write_all(b"\n").await.unwrap();

        // Send invalid inputs followed by valid decline
        stdin.write_all(b"maybe\n").await.unwrap();  // Invalid
        stdin.write_all(b"sure\n").await.unwrap();   // Invalid
        stdin.write_all(b"no\n").await.unwrap();     // Valid decline
        drop(stdin);
    }

    let output = child.wait_with_output().await.unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should re-prompt for invalid inputs
    assert!(stdout.contains("Execute this script? (yes/no):"));

    // Should eventually respect the "no" and exit with code 1
    assert_eq!(output.status.code(), Some(1));
}

#[tokio::test]
async fn test_eof_treated_as_decline() {
    let script_content = "echo 'Should not execute on EOF'";

    let mut child = Command::new("cargo")
        .args(&["run", "--", "bash"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn ebi process");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script_content.as_bytes()).await.unwrap();
        stdin.write_all(b"\n").await.unwrap();
        // Close stdin without providing user input (EOF)
        drop(stdin);
    }

    let output = child.wait_with_output().await.unwrap();

    // EOF should be treated as decline (exit code 1)
    assert_eq!(output.status.code(), Some(1));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("Should not execute on EOF"));
}