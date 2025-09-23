# Data Model: EBI Tool

## Core Entities

### 1. Script
**Purpose**: Represents the input script to be analyzed
```rust
pub struct Script {
    pub content: String,
    pub language: Language,
    pub source: ScriptSource,
}

pub enum ScriptSource {
    Stdin,
    File(PathBuf),
}

pub enum Language {
    Bash,
    Python,
    Unknown,
}
```

**Validation Rules**:
- `content` must not be empty
- `language` must be determinable or error
- Maximum size enforced by available memory

### 2. ScriptComponents
**Purpose**: Parsed AST components for separate analysis
```rust
pub struct ScriptComponents {
    pub code_body: String,         // Code with comments/literals removed
    pub comments: Vec<String>,      // All extracted comments
    pub string_literals: Vec<String>, // All extracted string literals
    pub metadata: ParseMetadata,
}

pub struct ParseMetadata {
    pub total_nodes: usize,
    pub parse_time_ms: u64,
    pub truncated: bool,
    pub priority_nodes: Vec<NodeInfo>,
}

pub struct NodeInfo {
    pub node_type: String,
    pub line_start: usize,
    pub line_end: usize,
    pub security_relevance: SecurityRelevance,
}

pub enum SecurityRelevance {
    Critical,  // exec, eval, system calls
    High,      // file I/O, network
    Medium,    // env vars, subprocess
    Low,       // regular code
}
```

**Validation Rules**:
- At least one component must contain content
- Comments and literals maintain original ordering
- Priority nodes sorted by security relevance

### 3. AnalysisRequest
**Purpose**: Request payload for LLM analysis
```rust
pub struct AnalysisRequest {
    pub analysis_type: AnalysisType,
    pub content: String,
    pub context: AnalysisContext,
    pub model: String,
    pub timeout_seconds: u64,
}

pub enum AnalysisType {
    InjectionDetection,  // For comments/strings
    CodeVulnerability,   // For code body
}

pub struct AnalysisContext {
    pub language: Language,
    pub script_type: Option<String>, // e.g., "installer", "config"
    pub truncated: bool,
}
```

### 4. AnalysisResult
**Purpose**: Individual LLM analysis result
```rust
pub struct AnalysisResult {
    pub analysis_type: AnalysisType,
    pub risk_level: RiskLevel,
    pub summary: String,
    pub details: Vec<Finding>,
    pub confidence: f32,
    pub model_used: String,
    pub response_time_ms: u64,
}

pub enum RiskLevel {
    None,
    Info,
    Low,
    Medium,
    High,
    Critical,
}

pub struct Finding {
    pub description: String,
    pub severity: RiskLevel,
    pub location: Option<String>, // Line numbers or code snippet
    pub recommendation: Option<String>,
}
```

**Validation Rules**:
- `confidence` must be between 0.0 and 1.0
- `summary` must be non-empty
- `risk_level` derived from highest finding severity

### 5. AnalysisReport
**Purpose**: Aggregated analysis for user presentation
```rust
pub struct AnalysisReport {
    pub script_info: ScriptInfo,
    pub overall_risk: RiskLevel,
    pub injection_analysis: Option<AnalysisResult>,
    pub code_analysis: Option<AnalysisResult>,
    pub execution_recommendation: ExecutionRecommendation,
    pub warnings: Vec<String>,
}

pub struct ScriptInfo {
    pub language: Language,
    pub size_bytes: usize,
    pub line_count: usize,
    pub detected_type: String, // e.g., "Installation Script"
}

pub enum ExecutionRecommendation {
    Safe,           // Low risk, likely safe
    Caution,        // Medium risk, review carefully
    Dangerous,      // High risk, not recommended
    Blocked,        // Critical risk or analysis failure
}
```

### 6. ExecutionDecision
**Purpose**: User's response to analysis
```rust
pub struct ExecutionDecision {
    pub proceed: bool,
    pub timestamp: SystemTime,
    pub analysis_report_hash: String, // For audit trail
}
```

### 7. ExecutionConfig
**Purpose**: Configuration for script execution
```rust
pub struct ExecutionConfig {
    pub target_command: String,
    pub target_args: Vec<String>,
    pub original_script: String,
    pub environment: HashMap<String, String>,
}
```

## State Transitions

### Script Analysis Flow
```
1. Script[New] → Script[Parsed] (via Tree-sitter)
2. Script[Parsed] → ScriptComponents[Ready]
3. ScriptComponents → AnalysisRequest[Created]
4. AnalysisRequest → AnalysisResult[Pending] (async)
5. AnalysisResult[Pending] → AnalysisResult[Complete]
6. Multiple AnalysisResult → AnalysisReport[Ready]
7. AnalysisReport → ExecutionDecision[Awaiting]
8. ExecutionDecision[Yes] → ExecutionConfig[Execute]
9. ExecutionDecision[No] → Terminated
```

### Error States
- `ParseError`: Cannot determine language or parse AST
- `AnalysisTimeout`: LLM request exceeds timeout
- `AnalysisUnavailable`: LLM service unreachable
- `TokenLimitExceeded`: Script too large, using prioritized analysis
- `ExecutionBlocked`: Analysis indicates critical risk

## Relationships

```
Script (1) → (1) ScriptComponents
ScriptComponents (1) → (2) AnalysisRequest (injection + code)
AnalysisRequest (1) → (1) AnalysisResult
AnalysisResult (2) → (1) AnalysisReport
AnalysisReport (1) → (1) ExecutionDecision
ExecutionDecision (1) → (0..1) ExecutionConfig
```

## Serialization Requirements

### For LLM APIs (JSON)
- `AnalysisRequest` → JSON for API calls
- `AnalysisResult` ← JSON from API responses
- Use `serde` with `#[derive(Serialize, Deserialize)]`

### For Display (Human-readable)
- `AnalysisReport` implements custom `Display` trait
- Formatted terminal output with colors (when TTY)
- Risk levels mapped to unicode symbols and colors

## Constraints

### Memory
- Maximum script size: 10MB (configurable)
- Component extraction memory-bounded
- Stream processing for large scripts

### Concurrency
- Maximum 2 concurrent LLM requests
- Shared nothing between analysis threads
- Results aggregation synchronized

### Security
- No persistence of script content
- No logging of sensitive data
- Constant-time string comparison for user input