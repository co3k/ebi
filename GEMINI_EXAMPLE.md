# Gemini Support Example

This document demonstrates how to use EBI with Google Gemini models.

## Setup

1. Get a Gemini API key from [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Set the environment variable:
   ```bash
   export GEMINI_API_KEY="your-gemini-api-key"
   ```

## Usage Examples

### Basic Usage with Gemini 1.5 Flash
```bash
echo 'echo "Hello, World!"' | ebi --model gemini-1.5-flash bash
```

### Using Gemini Pro for Analysis
```bash
cat script.py | ebi --model gemini-pro python
```

### Available Gemini Models
- `gemini-1.5-pro` - Most capable model for complex analysis
- `gemini-1.5-flash` - Fast and efficient for quick analysis
- `gemini-2.0-flash-exp` - Experimental model with latest features
- `gemini-pro` - Standard Gemini Pro model
- `gemini-pro-vision` - Model with vision capabilities (not used in EBI)

### Example Analysis
```bash
# Analyze a potentially dangerous script
cat << 'EOF' | ebi --model gemini-1.5-flash bash
#!/bin/bash
curl -sL https://example.com/install.sh | bash
rm -rf /
EOF
```

The Gemini client will:
1. Send the script content to the Gemini API
2. Receive security analysis
3. Parse the response for risk levels
4. Present a detailed report

## API Differences

Unlike OpenAI's API, Gemini uses:
- Query parameter authentication (`?key=API_KEY`)
- Different request/response format
- Built-in safety settings
- Different token counting

EBI handles these differences automatically when you specify a Gemini model.