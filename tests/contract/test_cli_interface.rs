use clap::Parser;

#[test]
fn test_basic_cli_parsing() {
    // This test will fail because we haven't implemented the CLI args yet
    let args = vec!["ebi", "bash"];
    let cli = ebi::cli::args::Cli::try_parse_from(args);

    assert!(cli.is_ok());
    let cli = cli.unwrap();

    assert_eq!(cli.command_and_args, vec!["bash"]);
    assert_eq!(cli.model, "gemini-pro");  // Default model
    assert_eq!(cli.timeout, 60);  // Default timeout
    assert!(cli.lang.is_none());
}

#[test]
fn test_cli_with_all_options() {
    let args = vec![
        "ebi",
        "--lang", "python",
        "--model", "gpt-4-turbo",
        "--timeout", "120",
        "--verbose",
        "python",
        "-",
        "--some-arg"
    ];

    let cli = ebi::cli::args::Cli::try_parse_from(args);
    assert!(cli.is_ok());
    let cli = cli.unwrap();

    assert_eq!(cli.lang, Some("python".to_string()));
    assert_eq!(cli.model, "gpt-4-turbo");
    assert_eq!(cli.timeout, 120);
    assert!(cli.verbose);
    assert_eq!(cli.command_and_args, vec!["python", "-", "--some-arg"]);
}

#[test]
fn test_cli_short_flags() {
    let args = vec!["ebi", "-l", "bash", "-m", "claude-3", "-t", "30", "-v", "sh", "-c", "echo test"];

    let cli = ebi::cli::args::Cli::try_parse_from(args);
    assert!(cli.is_ok());
    let cli = cli.unwrap();

    assert_eq!(cli.lang, Some("bash".to_string()));
    assert_eq!(cli.model, "claude-3");
    assert_eq!(cli.timeout, 30);
    assert!(cli.verbose);
    assert_eq!(cli.command_and_args, vec!["sh", "-c", "echo test"]);
}

#[test]
fn test_cli_trailing_args() {
    let args = vec!["ebi", "python", "script.py", "--arg1", "value1", "--flag"];

    let cli = ebi::cli::args::Cli::try_parse_from(args);
    assert!(cli.is_ok());
    let cli = cli.unwrap();

    assert_eq!(cli.command_and_args, vec!["python", "script.py", "--arg1", "value1", "--flag"]);
}

#[test]
fn test_cli_timeout_validation() {
    // Test timeout below minimum
    let args = vec!["ebi", "--timeout", "5", "bash"];
    let cli = ebi::cli::args::Cli::try_parse_from(args);
    assert!(cli.is_err()); // Should fail validation

    // Test timeout above maximum
    let args = vec!["ebi", "--timeout", "400", "bash"];
    let cli = ebi::cli::args::Cli::try_parse_from(args);
    assert!(cli.is_err()); // Should fail validation

    // Test valid timeout
    let args = vec!["ebi", "--timeout", "120", "bash"];
    let cli = ebi::cli::args::Cli::try_parse_from(args);
    assert!(cli.is_ok());
}

#[test]
fn test_cli_no_command_error() {
    // Test that providing no command fails
    let args = vec!["ebi", "--verbose"];
    let cli = ebi::cli::args::Cli::try_parse_from(args);
    assert!(cli.is_err()); // Should require at least a command
}

#[test]
fn test_cli_help_flag() {
    let args = vec!["ebi", "--help"];
    let cli = ebi::cli::args::Cli::try_parse_from(args);
    // Help should trigger an early exit, this is expected behavior
    assert!(cli.is_err());
}

#[test]
fn test_cli_version_flag() {
    let args = vec!["ebi", "--version"];
    let cli = ebi::cli::args::Cli::try_parse_from(args);
    // Version should trigger an early exit, this is expected behavior
    assert!(cli.is_err());
}