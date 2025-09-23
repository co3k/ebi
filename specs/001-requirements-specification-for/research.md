# Research & Technical Decisions: EBI Tool

## Executive Summary
This document captures the research findings and technical decisions for implementing the EBI script analysis tool, resolving all NEEDS CLARIFICATION items from the specification phase.

## Technical Decisions

### 1. LLM Integration Strategy
**Decision**: Use `llm-chain` with provider abstraction
**Rationale**:
- Provides unified API across multiple LLM providers (Gemini, OpenAI, Anthropic)
- Avoids vendor lock-in
- Simplifies switching between models via command-line flag
**Alternatives Considered**:
- Direct API integration: More control but requires maintaining multiple implementations
- `langchain-rust`: More heavyweight, includes features we don't need

### 2. Tree-sitter Language Support
**Decision**: Start with bash and python, use dynamic grammar loading
**Rationale**:
- Covers 80% of common script analysis use cases
- Tree-sitter allows adding languages without recompilation
- Grammar files can be embedded or downloaded on-demand
**Alternatives Considered**:
- Static compilation of all grammars: Larger binary size
- Regex-based parsing: Less accurate, harder to maintain

### 3. Concurrent Analysis Architecture
**Decision**: Use tokio with bounded concurrency (2 parallel LLM calls)
**Rationale**:
- Optimizes for latency while respecting rate limits
- Clean async/await pattern in Rust
- Built-in timeout support via `tokio::time::timeout`
**Alternatives Considered**:
- Sequential calls: Slower user experience
- Unbounded parallelism: Risk of rate limiting

### 4. Error Handling Philosophy
**Decision**: Fail-safe with descriptive errors using `thiserror`
**Rationale**:
- Security tool must never execute uncertain scripts
- Clear error messages improve user trust
- `thiserror` provides zero-cost abstractions
**Alternatives Considered**:
- `anyhow`: Better for applications, but we need typed errors for testing
- Manual `Display` implementations: More boilerplate

### 5. CLI Argument Parsing
**Decision**: Use `clap` v4 with derive macros and `trailing_var_arg`
**Rationale**:
- Industry standard for Rust CLIs
- Derive macros reduce boilerplate
- `trailing_var_arg` cleanly captures target command and args
**Implementation Detail**:
```rust
#[derive(Parser)]
struct Cli {
    #[arg(long, short = 'l')]
    lang: Option<String>,

    #[arg(long, short = 'm', default_value = "gemini-pro")]
    model: String,

    #[arg(long, short = 't', default_value = "60")]
    timeout: u64,

    #[arg(trailing_var_arg = true)]
    command_and_args: Vec<String>,
}
```

### 6. Testing Strategy
**Decision**: Three-tier testing with mocked LLMs
**Rationale**:
- Unit tests: Fast feedback on individual components
- Integration tests: Verify module interactions
- Contract tests: Ensure LLM request/response formats
**Tools**:
- `mockito`: HTTP mocking for LLM APIs
- `insta`: Snapshot testing for AST outputs
- `proptest`: Property-based testing for parser edge cases

### 7. Token Limit Handling
**Decision**: Priority-based extraction using AST node importance
**Rationale**:
- Focus on security-critical operations (exec, eval, network, file I/O)
- Maintains context better than truncation
- Provides clear warning about omitted content
**Priority Order**:
1. Entry points (main functions, script start)
2. External command execution
3. Network operations
4. File system operations
5. String manipulations
6. Control flow
7. Variable assignments

### 8. Language Detection Algorithm
**Decision**: Three-tier detection with clear precedence
**Implementation**:
```rust
fn detect_language(cli: &Cli, script: &str) -> Result<Language> {
    // 1. Explicit --lang flag (highest priority)
    if let Some(lang) = &cli.lang {
        return Language::from_str(lang);
    }

    // 2. Command name inference
    if let Some(cmd) = cli.command_and_args.first() {
        if let Some(lang) = infer_from_command(cmd) {
            return Ok(lang);
        }
    }

    // 3. Shebang parsing fallback
    if let Some(lang) = parse_shebang(script) {
        return Ok(lang);
    }

    Err(EbiError::UnknownLanguage)
}
```

### 9. Build System Configuration
**Decision**: Use `build.rs` for Tree-sitter grammar compilation
**Rationale**:
- Compiles C grammars at build time
- Reduces runtime overhead
- Standard Rust pattern for native dependencies
**Implementation**: Use `cc` crate in build dependencies

### 10. User Interaction Design
**Decision**: Clear, structured report with risk levels
**Format**:
```
═══════════════════════════════════════════════════════════
 EBI SECURITY ANALYSIS REPORT
═══════════════════════════════════════════════════════════

Script Type: Bash Installation Script
Risk Level: MEDIUM

▶ CODE ANALYSIS
Purpose: Installs software package with system modifications
Vulnerabilities:
- Downloads from unverified source
- Modifies system PATH
- Requires sudo privileges

▶ INJECTION ANALYSIS
Suspicious Patterns: None detected
Hidden Instructions: None found

═══════════════════════════════════════════════════════════
Execute this script? (yes/no):
```

## Best Practices Adoption

### Rust Patterns
- Builder pattern for complex configurations
- Type-state pattern for execution flow
- Result<T, E> for all fallible operations
- Zero-copy parsing where possible

### Security Practices
- No logging by default (privacy-first)
- Constant-time string comparisons for confirmations
- Bounded resource consumption (timeouts, memory limits)
- Principle of least privilege (no unnecessary permissions)

### Performance Optimizations
- Lazy static compilation of Tree-sitter languages
- Stream processing for large scripts
- Connection pooling for LLM APIs
- Early exit on critical errors

## Resolved Clarifications

All NEEDS CLARIFICATION items from the specification have been resolved:

1. **LLM Failure Behavior**: Fail-safe approach - block execution completely
2. **Timeout Configuration**: 10-300 seconds range, 60s default, via --timeout flag
3. **Token Limit Strategy**: Priority-based extraction of security-critical code
4. **Performance Targets**: Best-effort, constrained by LLM response times
5. **Security Filters**: Deferred to future version based on user feedback
6. **Logging Behavior**: Disabled by default, enabled via --verbose/--debug flags

## Dependencies Justification

| Crate | Why This Specific Version | Security Considerations |
|-------|--------------------------|------------------------|
| clap ~4.0 | Stable API, derive macro support | Well-audited, no known CVEs |
| tokio ~1.0 | LTS version, stable runtime | Battle-tested in production |
| tree-sitter ~0.20 | Latest stable, good language support | Memory-safe parser generator |
| llm-chain ~0.9 | Most recent with provider support | Review API key handling |
| serde ~1.0 | De facto standard | Extensive fuzzing history |
| thiserror ~1.0 | Maintained by dtolnay | Compile-time only, no runtime overhead |
| shebang-rs ~0.2 | Simple, focused library | Minimal attack surface |

## Next Steps

With all technical decisions made and clarifications resolved, we can proceed to Phase 1:
- Define data models for script analysis
- Create API contracts for LLM interactions
- Generate quickstart guide for users
- Prepare contract tests

All research items are complete and no blockers remain for implementation.