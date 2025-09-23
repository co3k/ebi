use mockito::Server;
use serde_json::json;

#[tokio::test]
async fn test_llm_analysis_request_format() {
    let mut server = Server::new_async().await;

    // Mock LLM API endpoint
    let _mock = server
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(json!({
            "id": "chatcmpl-123",
            "object": "chat.completion",
            "created": 1677652288,
            "model": "gpt-5-mini",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": json!({
                        "risk_level": "low",
                        "summary": "Script appears to be a simple echo command",
                        "findings": [],
                        "confidence": 0.95
                    }).to_string()
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 50,
                "total_tokens": 150
            }
        }).to_string())
        .create_async()
        .await;

    // This test will fail because we haven't implemented the LLM client yet
    let client = ebi::analyzer::llm_client::LlmClient::new(&server.url());
    let request = ebi::models::analysis::AnalysisRequest {
        analysis_type: ebi::models::analysis::AnalysisType::CodeVulnerability,
        content: "echo 'hello world'".to_string(),
        context: ebi::models::analysis::AnalysisContext {
            language: ebi::models::script::Language::Bash,
            script_type: Some("simple".to_string()),
            truncated: false,
        },
        model: "gpt-5-mini".to_string(),
        timeout_seconds: 60,
    };

    let result = client.analyze(request).await;
    assert!(result.is_ok());

    let analysis_result = result.unwrap();
    assert_eq!(analysis_result.risk_level, ebi::models::analysis::RiskLevel::Low);
    assert!(!analysis_result.summary.is_empty());
}

#[tokio::test]
async fn test_llm_api_timeout() {
    let mut server = Server::new_async().await;

    // Mock slow response that will timeout
    let _mock = server
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("{}")
        .with_delay(std::time::Duration::from_secs(10))  // Longer than timeout
        .create_async()
        .await;

    let client = ebi::analyzer::llm_client::LlmClient::new(&server.url());
    let request = ebi::models::analysis::AnalysisRequest {
        analysis_type: ebi::models::analysis::AnalysisType::InjectionDetection,
        content: "# This is a comment".to_string(),
        context: ebi::models::analysis::AnalysisContext {
            language: ebi::models::script::Language::Bash,
            script_type: None,
            truncated: false,
        },
        model: "gpt-5-mini".to_string(),
        timeout_seconds: 1,  // Short timeout
    };

    let result = client.analyze(request).await;
    assert!(result.is_err());

    // Should be a timeout error
    let error = result.unwrap_err();
    assert!(matches!(error, ebi::error::EbiError::AnalysisTimeout));
}

#[tokio::test]
async fn test_llm_api_unavailable() {
    // Test against a non-existent server
    let client = ebi::analyzer::llm_client::LlmClient::new("http://localhost:99999");
    let request = ebi::models::analysis::AnalysisRequest {
        analysis_type: ebi::models::analysis::AnalysisType::CodeVulnerability,
        content: "rm -rf /".to_string(),
        context: ebi::models::analysis::AnalysisContext {
            language: ebi::models::script::Language::Bash,
            script_type: Some("dangerous".to_string()),
            truncated: false,
        },
        model: "gpt-5-mini".to_string(),
        timeout_seconds: 5,
    };

    let result = client.analyze(request).await;
    assert!(result.is_err());

    // Should be a service unavailable error
    let error = result.unwrap_err();
    assert!(matches!(error, ebi::error::EbiError::AnalysisUnavailable));
}