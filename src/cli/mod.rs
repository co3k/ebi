pub mod args;
pub mod reporter;
pub mod prompt;

pub use args::Cli;
pub use reporter::ReportFormatter;
pub use prompt::UserPrompter;

use std::io::{self, Read};
use crate::error::EbiError;
use crate::models::{Script, ScriptSource, AnalysisReport, ExecutionDecision, ScriptInfo};
use crate::executor::ExecutionConfig;
use crate::parser::ComponentExtractor;
use crate::analyzer::{AnalysisOrchestrator, AnalysisAggregator};

pub struct CliHandler {
    cli: Cli,
}

impl CliHandler {
    pub fn new(cli: Cli) -> Self {
        Self { cli }
    }

    pub async fn run(&self) -> Result<i32, EbiError> {
        // Step 1: Read script from stdin
        let script_content = self.read_stdin()?;
        if script_content.trim().is_empty() {
            return Err(EbiError::NoInput);
        }

        if self.cli.is_verbose() {
            eprintln!("📥 Read {} bytes from stdin", script_content.len());
        }

        // Step 2: Create script and detect language
        let mut script = Script::new(script_content, ScriptSource::Stdin);
        script.detect_language(
            self.cli.lang.as_deref(),
            Some(self.cli.get_target_command()),
        )?;

        if self.cli.is_verbose() {
            eprintln!("🔍 Detected language: {}", script.language.as_str());
        }

        if self.cli.is_debug() {
            eprintln!("🌐 Language detection:");
            eprintln!("{}", self.cli.get_language_debug_info());
        }

        // Step 3: Parse script components using integrated parser
        let components = self.parse_script_components(&script).await?;

        if self.cli.is_verbose() {
            eprintln!(
                "🔧 Extracted {} comments, {} string literals, {} priority nodes",
                components.comments.len(),
                components.string_literals.len(),
                components.metadata.priority_nodes.len()
            );
        }

        // Step 4: Perform LLM analysis using integrated analyzer
        let analysis_report = self.analyze_script(&script, &components).await?;

        // Step 5: Display analysis report using integrated formatter
        let formatter = ReportFormatter::new(&self.cli)?;
        println!("{}", formatter.format_analysis_report(&analysis_report));

        // Step 6: Check if execution is blocked
        if analysis_report.should_block_execution() {
            if self.cli.is_verbose() {
                eprintln!("❌ Execution blocked due to security concerns");
            }
            return Ok(3); // Exit code 3 for analysis failure/blocking
        }

        // Step 7: Get user decision using integrated prompter
        let prompter = UserPrompter::for_cli(&self.cli);
        let decision = match prompter.prompt_execution_decision(&analysis_report) {
            Ok(decision) => decision,
            Err(EbiError::UserInputTimeout) => {
                if self.cli.is_verbose() {
                    eprintln!("⏰ User input timeout reached; defaulting to decline.");
                }
                return Ok(1);
            }
            Err(e) => return Err(e),
        };

        if !decision.proceed {
            if self.cli.is_verbose() {
                eprintln!("🚫 User declined execution");
            }
            return Ok(1); // Exit code 1 for user decline
        }

        // Step 8: Execute script
        if self.cli.is_verbose() {
            eprintln!("✅ User approved - executing script");
        }

        let exit_code = self.execute_script(&script, &decision).await?;
        Ok(exit_code)
    }

    fn read_stdin(&self) -> Result<String, EbiError> {
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer)?;
        Ok(buffer)
    }

    async fn parse_script_components(&self, script: &Script) -> Result<crate::models::ScriptComponents, EbiError> {
        let extractor = ComponentExtractor::new();
        extractor.extract_from_script(&script.content, script.language.clone())
    }

    async fn analyze_script(
        &self,
        script: &Script,
        components: &crate::models::ScriptComponents,
    ) -> Result<AnalysisReport, EbiError> {
        if self.cli.is_verbose() {
            eprintln!("🤖 Starting LLM analysis with model: {}", self.cli.get_llm_model());
        }

        // Create script info
        let script_info = ScriptInfo::new(
            script.language.clone(),
            script.size_bytes(),
            script.line_count(),
        );

        // Create LLM analysis orchestrator
        let api_key = self.get_api_key_for_model(self.cli.get_llm_model());
        let orchestrator = AnalysisOrchestrator::new(
            self.cli.get_llm_model(),
            api_key,
            self.cli.get_timeout_seconds(),
            2, // Max 2 concurrent requests
        )?;

        // Perform LLM analysis
        let output_language = self.cli.get_output_language()?;
        let analysis_results = orchestrator.analyze_script_components(
            components,
            &script.language,
            &ScriptSource::Stdin,
            self.cli.get_llm_model(),
            &output_language,
        ).await?;

        // Aggregate the results
        let aggregator = AnalysisAggregator::new();
        let report = aggregator.aggregate_analysis_results(
            analysis_results,
            script_info,
            components,
        )?;

        if self.cli.is_verbose() {
            eprintln!("📊 Analysis complete - Risk level: {}", report.overall_risk.as_str());
        }

        Ok(report)
    }


    async fn execute_script(
        &self,
        script: &Script,
        _decision: &ExecutionDecision,
    ) -> Result<i32, EbiError> {
        use std::process::{Command, Stdio};
        use std::io::Write;

        // Create execution config
        let config = ExecutionConfig::new(
            self.cli.get_target_command().to_string(),
            self.cli.get_target_args().to_vec(),
            script.content.clone(),
        );

        if self.cli.is_debug() {
            eprintln!("🔧 Executing: {:?}", config.get_full_command());
        }

        // Spawn the target command
        let mut child = Command::new(&config.target_command)
            .args(&config.target_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|_| EbiError::CommandNotFound {
                command: config.target_command.clone(),
            })?;

        // Write the original script to the command's stdin
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(script.content.as_bytes())
                .map_err(|e| EbiError::ExecutionFailed(e.to_string()))?;
        }

        // Wait for the command to complete
        let output = child.wait()
            .map_err(|e| EbiError::ExecutionFailed(e.to_string()))?;

        let exit_code = output.code().unwrap_or(1);

        if self.cli.is_verbose() {
            eprintln!("🏁 Script execution completed with exit code: {}", exit_code);
        }

        Ok(exit_code)
    }

    fn get_api_key_for_model(&self, model: &str) -> Option<String> {
        // Determine which API key to use based on model prefix
        if model.starts_with("gpt-")
            || model.starts_with("o1-")
            || model.starts_with("o3-")
            || model.starts_with("o4-") {
            std::env::var("OPENAI_API_KEY").ok()
        } else if model.starts_with("gemini-") {
            std::env::var("GEMINI_API_KEY").ok()
        } else if model.starts_with("claude-") {
            std::env::var("ANTHROPIC_API_KEY").ok()
        } else {
            // Fallback to generic EBI_LLM_API_KEY or OPENAI_API_KEY
            std::env::var("EBI_LLM_API_KEY")
                .or_else(|_| std::env::var("OPENAI_API_KEY"))
                .ok()
        }
    }
}
