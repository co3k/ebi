# Tasks: EBI - Script Analysis Tool

**Input**: Design documents from `/specs/001-requirements-specification-for/`
**Prerequisites**: plan.md (required), research.md, data-model.md, contracts/

## Execution Flow (main)
```
1. Load plan.md from feature directory
   → Extract: Rust 1.75+, clap, tokio, tree-sitter, llm-chain
   → Structure: Single project with CLI utility
2. Load design documents:
   → data-model.md: 7 entities → model tasks
   → contracts/: LLM API + CLI interface → contract test tasks
   → quickstart.md: User scenarios → integration tests
3. Generate tasks by category:
   → Setup: Cargo.toml, project structure, linting
   → Tests: Contract tests, integration tests
   → Core: Models, parsing, analysis, execution
   → Integration: LLM chain, Tree-sitter, user interaction
   → Polish: Unit tests, error handling, docs
4. Apply TDD ordering: Tests before implementation
5. Mark [P] for parallel execution (different files)
6. SUCCESS: 34 tasks ready for execution
```

## Format: `[ID] [P?] Description`
- **[P]**: Can run in parallel (different files, no dependencies)
- Include exact file paths in descriptions

## Phase 3.1: Setup

- [x] T001 Create Rust project structure with `cargo init` and organize directories: `src/`, `src/cli/`, `src/parser/`, `src/analyzer/`, `src/executor/`, `tests/unit/`, `tests/integration/`, `tests/contract/`

- [x] T002 Initialize Cargo.toml with dependencies: clap ~4.0, tokio ~1.0, tree-sitter ~0.20, llm-chain ~0.9, serde ~1.0, thiserror ~1.0, shebang-rs ~0.2, and dev dependencies mockito, insta

- [x] T003 [P] Configure clippy, rustfmt, and create build.rs for Tree-sitter grammar compilation

- [x] T004 [P] Create .gitignore with Rust target/, Cargo.lock (for binaries), and environment files

## Phase 3.2: Tests First (TDD) ⚠️ MUST COMPLETE BEFORE 3.3
**CRITICAL: These tests MUST be written and MUST FAIL before ANY implementation**

- [x] T005 [P] Contract test for LLM analysis API request/response in `tests/contract/test_llm_api.rs`

- [x] T006 [P] Contract test for CLI argument parsing in `tests/contract/test_cli_interface.rs`

- [x] T007 [P] Integration test for "analyze simple script" scenario in `tests/integration/test_simple_analysis.rs`

- [x] T008 [P] Integration test for "analyze installation script" scenario in `tests/integration/test_installation_script.rs`

- [x] T009 [P] Integration test for "user declines execution" scenario in `tests/integration/test_user_decline.rs`

- [x] T010 [P] Integration test for "LLM service unavailable" scenario in `tests/integration/test_llm_failure.rs`

- [x] T011 [P] Integration test for "language detection" scenarios in `tests/integration/test_language_detection.rs`

## Phase 3.3: Core Implementation (ONLY after tests are failing)

### Error Types and Core Structures

- [x] T012 [P] Define EbiError enum with all error variants in `src/error.rs`

- [x] T013 [P] Implement Script entity with language detection in `src/models/script.rs`

- [x] T014 [P] Implement ScriptComponents and ParseMetadata structs in `src/models/components.rs`

- [x] T015 [P] Implement AnalysisRequest and AnalysisResult structs in `src/models/analysis.rs`

- [x] T016 [P] Implement AnalysisReport and ExecutionDecision structs in `src/models/report.rs`

### CLI Parsing

- [x] T017 Implement CLI argument parsing with clap derive in `src/cli/args.rs`

- [x] T018 Implement main CLI entry point and command dispatcher in `src/cli/mod.rs`

### Language Detection

- [x] T019 [P] Implement language detection from CLI args, command name, and shebang in `src/parser/language.rs`

- [x] T020 [P] Implement shebang parsing integration in `src/parser/shebang.rs`

### AST Parsing

- [x] T021 [P] Implement Tree-sitter parser setup and configuration in `src/parser/tree_sitter.rs`

- [x] T022 [P] Implement AST traversal and component extraction in `src/parser/extractor.rs`

- [x] T023 [P] Implement security relevance classification in `src/parser/classifier.rs`

### LLM Integration

- [x] T024 [P] Implement LLM client abstraction and provider configuration in `src/analyzer/llm_client.rs`

- [x] T025 [P] Implement prompt templates for injection and vulnerability analysis in `src/analyzer/prompts.rs`

- [x] T026 [P] Implement parallel analysis orchestration in `src/analyzer/orchestrator.rs`

- [x] T027 [P] Implement analysis result aggregation in `src/analyzer/aggregator.rs`

### User Interaction

- [x] T028 Implement analysis report formatting and display in `src/cli/reporter.rs`

- [x] T029 Implement user confirmation prompt handling in `src/cli/prompt.rs`

### Script Execution

- [x] T030 [P] Implement script execution wrapper in `src/executor/runner.rs`

- [x] T031 [P] Implement execution configuration and environment setup in `src/executor/config.rs`

## Phase 3.4: Integration

- [x] T032 Integrate all modules in main.rs with proper error handling and flow control

- [ ] T033 Implement timeout handling for LLM requests and user prompts

## Phase 3.5: Polish

- [ ] T034 [P] Add comprehensive unit tests for language detection in `tests/unit/test_language_detection.rs`

- [ ] T035 [P] Add unit tests for AST parsing edge cases in `tests/unit/test_ast_parsing.rs`

- [ ] T036 [P] Add unit tests for analysis aggregation logic in `tests/unit/test_analysis_aggregation.rs`

- [ ] T037 [P] Add unit tests for error handling scenarios in `tests/unit/test_error_handling.rs`

- [ ] T038 Run quickstart.md manual testing scenarios and fix any issues

## Dependencies

### Critical Path
- Setup (T001-T004) → Tests (T005-T011) → Core (T012-T031) → Integration (T032-T033) → Polish (T034-T038)

### Specific Dependencies
- T012 (error types) blocks all implementation tasks
- T013-T016 (models) must complete before T017-T031
- T017-T018 (CLI) blocks T028-T029 (user interaction)
- T019-T020 (language detection) blocks T021-T023 (parsing)
- T021-T023 (parsing) blocks T024-T027 (analysis)
- T024-T027 (analysis) blocks T028-T029 (reporting)
- T030-T031 (execution) needs T017-T018 (CLI args)
- T032 (integration) needs all core modules (T017-T031)

## Parallel Execution Examples

### Phase 3.2 - All Tests Together
```bash
# Launch T005-T011 in parallel:
Task: "Contract test for LLM analysis API request/response in tests/contract/test_llm_api.rs"
Task: "Contract test for CLI argument parsing in tests/contract/test_cli_interface.rs"
Task: "Integration test for analyze simple script scenario in tests/integration/test_simple_analysis.rs"
Task: "Integration test for analyze installation script scenario in tests/integration/test_installation_script.rs"
Task: "Integration test for user declines execution scenario in tests/integration/test_user_decline.rs"
Task: "Integration test for LLM service unavailable scenario in tests/integration/test_llm_failure.rs"
Task: "Integration test for language detection scenarios in tests/integration/test_language_detection.rs"
```

### Phase 3.3 - Models in Parallel
```bash
# After T012 completes, launch T013-T016:
Task: "Implement Script entity with language detection in src/models/script.rs"
Task: "Implement ScriptComponents and ParseMetadata structs in src/models/components.rs"
Task: "Implement AnalysisRequest and AnalysisResult structs in src/models/analysis.rs"
Task: "Implement AnalysisReport and ExecutionDecision structs in src/models/report.rs"
```

### Phase 3.5 - Unit Tests in Parallel
```bash
# Launch T034-T037:
Task: "Add comprehensive unit tests for language detection in tests/unit/test_language_detection.rs"
Task: "Add unit tests for AST parsing edge cases in tests/unit/test_ast_parsing.rs"
Task: "Add unit tests for analysis aggregation logic in tests/unit/test_analysis_aggregation.rs"
Task: "Add unit tests for error handling scenarios in tests/unit/test_error_handling.rs"
```

## Validation Checklist
*GATE: Checked before task execution*

- [x] All contracts have corresponding tests (T005-T006)
- [x] All entities have model tasks (T013-T016)
- [x] All tests come before implementation (T005-T011 → T012-T033)
- [x] Parallel tasks truly independent (different files)
- [x] Each task specifies exact file path
- [x] No task modifies same file as another [P] task
- [x] TDD ordering enforced (tests must fail before implementation)

## Notes
- All tests T005-T011 must be written first and must fail before ANY implementation
- [P] tasks can run simultaneously as they modify different files
- Commit after completing each task for clean git history
- Use `cargo test` to verify test failures before implementing
- Integration tests should use mocked LLM responses via mockito
- Follow Rust conventions: snake_case for files, PascalCase for types