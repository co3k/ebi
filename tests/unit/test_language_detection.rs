use ebi::{Script, ScriptSource, Language, EbiError};

#[test]
fn cli_override_takes_priority() {
    let mut script = Script::new("echo 'hello'".to_string(), ScriptSource::Stdin);
    script.detect_language(Some("python"), Some("bash")).unwrap();

    assert_eq!(script.language, Language::Python);
}

#[test]
fn command_name_inference_detects_bash() {
    let mut script = Script::new("echo 'hi'".to_string(), ScriptSource::Stdin);
    script.detect_language(None, Some("bash")).unwrap();

    assert_eq!(script.language, Language::Bash);
}

#[test]
fn shebang_detection_falls_back_when_no_overrides() {
    let content = "#!/usr/bin/env python3\nprint('hi')";
    let mut script = Script::new(content.to_string(), ScriptSource::Stdin);

    script.detect_language(None, None).unwrap();

    assert_eq!(script.language, Language::Python);
}

#[test]
fn unknown_language_returns_error() {
    let mut script = Script::new("some custom syntax".to_string(), ScriptSource::Stdin);
    let err = script.detect_language(None, Some("mystery")).unwrap_err();

    assert!(matches!(err, EbiError::UnknownLanguage));
}

#[test]
fn invalid_cli_language_is_rejected() {
    let mut script = Script::new("echo hi".to_string(), ScriptSource::Stdin);
    let err = script.detect_language(Some("invalid"), None).unwrap_err();

    assert!(matches!(err, EbiError::UnknownLanguage));
}
