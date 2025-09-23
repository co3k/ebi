use ebi::{
    cli::{Cli, CliHandler},
    error::EbiError,
};
use std::process;

#[tokio::main]
async fn main() {
    // Parse command line arguments
    let cli = match Cli::parse_args() {
        Ok(cli) => cli,
        Err(e) => {
            eprintln!("❌ Argument parsing failed: {}", e);
            process::exit(2);
        }
    };

    // Create and run the CLI handler
    let handler = CliHandler::new(cli);

    // Execute the main workflow
    let exit_code = match handler.run().await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("❌ Execution failed: {}", e);
            match e {
                EbiError::ExecutionBlocked => 3,        // Security analysis blocked execution
                EbiError::AnalysisTimeout { .. } => 4,  // Analysis timed out
                EbiError::LlmClientError(_) => 5,       // LLM service error
                EbiError::UserInputTimeout => 6,        // User input timeout
                EbiError::CommandNotFound { .. } => 7,  // Target command not found
                _ => 1,                                  // General error
            }
        }
    };

    process::exit(exit_code);
}
