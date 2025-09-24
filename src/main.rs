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
            eprintln!("🦐❌ Argument parsing failed: {}", e);
            process::exit(2);
        }
    };

    // Create and run the CLI handler
    let handler = CliHandler::new(cli);

    // Execute the main workflow
    let exit_code = match handler.run().await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("🦐❌ Execution failed: {}", e);
            match e {
                EbiError::UnknownLanguage | EbiError::ParseError(_) => 2,
                EbiError::NoInput => 4,
                EbiError::InvalidArguments(_) => 5,
                EbiError::CommandNotFound { .. } => 6,
                EbiError::ExecutionFailed(_) => 7,
                EbiError::AnalysisTimeout { .. }
                | EbiError::AnalysisUnavailable(_)
                | EbiError::LlmClientError(_)
                | EbiError::ExecutionBlocked
                | EbiError::TokenLimitExceeded => 3,
                EbiError::UserInputTimeout => 1,
                _ => 1,
            }
        }
    };

    process::exit(exit_code);
}
