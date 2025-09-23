use ebi::parser::ComponentExtractor;
use ebi::models::Language;
use ebi::error::EbiError;
use ebi::analyzer::llm_client::create_llm_client;
use ebi::executor::{ExecutionConfig, ScriptRunner};

#[test]
fn extractor_rejects_unknown_language() {
    let extractor = ComponentExtractor::new();
    let result = extractor.extract_from_script("echo test", Language::Unknown);

    assert!(matches!(result, Err(EbiError::UnknownLanguage)));
}

#[test]
fn llm_client_creation_fails_for_unsupported_model() {
    let client = create_llm_client("claude-3", Some("test".to_string()), 60);
    assert!(client.is_err());
}

#[test]
fn script_runner_prepare_sandbox_fails_for_empty_command() {
    let config = ExecutionConfig::new("".to_string(), vec![], "echo test".to_string());
    let runner = ScriptRunner::new(config);

    let err = runner.prepare_sandbox().unwrap_err();
    assert!(matches!(err, EbiError::InvalidArguments(_)));
}
