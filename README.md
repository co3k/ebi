# EBI - Evaluate Before Invocation

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-%3E%3D1.75-orange.svg)](https://www.rust-lang.org)

EBI is a security tool that analyzes scripts before execution using LLM-powered analysis. It acts as a protective wrapper around any command, detecting malicious code, vulnerabilities, and hidden instructions to keep your system safe.

## Features

- 🛡️ **Security-First Design**: Blocks execution of suspicious scripts by default
- 🤖 **AI-Powered Analysis**: Uses LLMs to detect vulnerabilities and malicious patterns
- 🔍 **Multi-Language Support**: Currently supports Bash and Python scripts
- 🎯 **Smart Detection**: Analyzes code structure, comments, and string literals separately
- ⚡ **Fast & Efficient**: Parallel analysis with configurable timeouts
- 🎨 **User-Friendly**: Clear, colored reports with risk levels and recommendations

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/ebi.git
cd ebi

# Build with Cargo
cargo build --release

# Install to system
sudo cp target/release/ebi /usr/local/bin/

# Verify installation
ebi --version
```

### Prerequisites

- Rust 1.75 or higher
- Internet connection (for LLM API calls)
- API key for OpenAI or compatible LLM service

## Configuration

Set your LLM API key:

```bash
# For OpenAI
export OPENAI_API_KEY="sk-your-api-key"

# For Google Gemini
export GEMINI_API_KEY="your-gemini-api-key"

# For Anthropic Claude
export ANTHROPIC_API_KEY="your-anthropic-api-key"

# Optional: Set default model
export EBI_DEFAULT_MODEL="gemini-2.5-flash"

# Optional: Set default timeout (seconds)
export EBI_DEFAULT_TIMEOUT=120
```

## Usage

### Basic Usage

Analyze a simple script before execution:

```bash
echo 'echo "Hello, World!"' | ebi bash
```

### Analyze Installation Scripts

Safely analyze scripts from the internet:

```bash
# Instead of this dangerous approach:
# curl -sL https://example.com/install.sh | bash

# Use EBI to analyze first:
curl -sL https://example.com/install.sh | ebi bash
```

### Command Line Options

```bash
ebi [OPTIONS] <COMMAND> [COMMAND_ARGS...]
```

Options:
- `-l, --lang <LANGUAGE>`: Override automatic language detection
- `-m, --model <MODEL>`: LLM model to use (default: gpt-5-mini)
- `-t, --timeout <SECONDS>`: Analysis timeout in seconds (10-300, default: 60)
- `-v, --verbose`: Enable verbose output
- `-d, --debug`: Enable debug output with LLM communications
- `-h, --help`: Display help message
- `-V, --version`: Display version

### Examples

```bash
# Analyze Python script with custom model
cat script.py | ebi --model gemini-2.5-flash python

# Analyze with verbose output
cat installer.sh | ebi --verbose bash

# Force language detection
cat ambiguous_script | ebi --lang bash sh

# Increase timeout for large scripts
cat large_script.py | ebi --timeout 120 python
```

## Understanding Risk Levels

| Level | Description | Recommendation |
|-------|-------------|----------------|
| **NONE** | No security risks detected | Safe to execute |
| **LOW** | Minor concerns identified | Review and proceed |
| **MEDIUM** | Notable risks found | Careful review needed |
| **HIGH** | Significant security risks | Not recommended to execute |
| **CRITICAL** | Dangerous operations detected | Execution blocked |

## How It Works

1. **Input Processing**: Receives script via stdin
2. **Language Detection**: Identifies script language via CLI args, command name, or shebang
3. **AST Parsing**: Parses script structure using Tree-sitter
4. **Component Extraction**: Separates code, comments, and string literals
5. **Parallel Analysis**: Performs vulnerability and injection detection using LLMs
6. **Risk Assessment**: Aggregates results and determines overall risk level
7. **User Interaction**: Presents report and prompts for execution decision
8. **Safe Execution**: Executes only after user confirmation (if safe)

## Safety Features

- **Fail-Safe Default**: Blocks execution when LLM service is unavailable
- **No Logging**: Doesn't store scripts or analysis results by default
- **Timeout Protection**: Configurable timeouts for both analysis and user input
- **Explicit Consent**: Always requires user confirmation before execution
- **Conservative Analysis**: When uncertain, defaults to higher risk levels

## Development

### Building from Source

```bash
# Clone repository
git clone https://github.com/yourusername/ebi.git
cd ebi

# Run tests
cargo test

# Run with clippy
cargo clippy

# Build release version
cargo build --release
```

### Running Tests

```bash
# Run all tests
cargo test

# Run with verbose output
cargo test -- --nocapture

# Run specific test module
cargo test analyzer::
```

### Project Structure

```
ebi/
├── src/
│   ├── analyzer/       # LLM analysis modules
│   ├── cli/           # CLI interface and user interaction
│   ├── executor/      # Script execution handling
│   ├── models/        # Data models and types
│   ├── parser/        # Script parsing and AST analysis
│   └── main.rs        # Entry point
├── tests/
│   ├── contract/      # API contract tests
│   ├── integration/   # Integration tests
│   └── unit/         # Unit tests
└── Cargo.toml        # Dependencies and metadata
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Tree-sitter for robust code parsing
- The Rust community for excellent libraries and tools
- OpenAI for providing powerful LLM capabilities

## Disclaimer

EBI is a security tool that provides analysis and recommendations. While it aims to detect malicious code and vulnerabilities, it is not infallible. Always review scripts carefully and use your judgment before execution. The authors are not responsible for any damage caused by scripts executed after EBI analysis.

## Support

For issues, questions, or suggestions, please open an issue on GitHub.