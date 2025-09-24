use crate::error::EbiError;
use crate::models::Language;

#[derive(Debug, Clone)]
pub struct ShebangInfo {
    pub interpreter: String,
    pub args: Vec<String>,
    pub full_path: String,
}

pub struct ShebangParser;

impl ShebangParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse(content: &str) -> Option<ShebangInfo> {
        let first_line = content.lines().next()?;

        if !first_line.starts_with("#!") {
            return None;
        }

        let shebang_content = &first_line[2..].trim();

        if shebang_content.is_empty() {
            return None;
        }

        let parts: Vec<&str> = shebang_content.split_whitespace().collect();
        if parts.is_empty() {
            return None;
        }

        let interpreter_path = parts[0];
        let interpreter = std::path::Path::new(interpreter_path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(interpreter_path)
            .to_string();

        let args = parts[1..].iter().map(|s| s.to_string()).collect();

        Some(ShebangInfo {
            interpreter,
            args,
            full_path: interpreter_path.to_string(),
        })
    }

    pub fn extract_language(shebang_info: &ShebangInfo) -> Option<Language> {
        match shebang_info.interpreter.as_str() {
            "bash" | "sh" | "zsh" | "fish" | "dash" => Some(Language::Bash),
            "python" | "python3" | "python2" | "py" => Some(Language::Python),
            _ => {
                // Check if the full path contains language indicators
                let full_path_lower = shebang_info.full_path.to_lowercase();
                if full_path_lower.contains("bash") || full_path_lower.contains("/bin/sh") {
                    Some(Language::Bash)
                } else if full_path_lower.contains("python") {
                    Some(Language::Python)
                } else {
                    None
                }
            }
        }
    }

    pub fn is_env_shebang(shebang_info: &ShebangInfo) -> bool {
        shebang_info.interpreter == "env" && !shebang_info.args.is_empty()
    }

    pub fn resolve_env_interpreter(shebang_info: &ShebangInfo) -> Option<String> {
        if Self::is_env_shebang(shebang_info) && !shebang_info.args.is_empty() {
            Some(shebang_info.args[0].clone())
        } else {
            None
        }
    }

    pub fn parse_and_detect_language(content: &str) -> Option<Language> {
        let shebang = Self::parse(content)?;

        // Handle env shebang (#!/usr/bin/env python, etc.)
        if Self::is_env_shebang(&shebang) {
            if let Some(real_interpreter) = Self::resolve_env_interpreter(&shebang) {
                let env_shebang = ShebangInfo {
                    interpreter: real_interpreter,
                    args: shebang.args[1..].to_vec(),
                    full_path: shebang.full_path,
                };
                return Self::extract_language(&env_shebang);
            }
        }

        Self::extract_language(&shebang)
    }

    pub fn validate_shebang(content: &str) -> Result<(), EbiError> {
        if let Some(shebang) = Self::parse(content) {
            // Basic validation - ensure the interpreter path looks reasonable
            if shebang.full_path.is_empty() {
                return Err(EbiError::ParseError(
                    "Empty shebang interpreter".to_string(),
                ));
            }

            // Check for potentially dangerous interpreters
            let dangerous_interpreters = ["rm", "dd", "mkfs", "fdisk"];
            if dangerous_interpreters.contains(&shebang.interpreter.as_str()) {
                return Err(EbiError::ParseError(format!(
                    "Potentially dangerous interpreter in shebang: {}",
                    shebang.interpreter
                )));
            }
        }

        Ok(())
    }
}

impl Default for ShebangParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bash_shebang() {
        let content = "#!/bin/bash\necho hello";
        let shebang = ShebangParser::parse(content).unwrap();

        assert_eq!(shebang.interpreter, "bash");
        assert_eq!(shebang.full_path, "/bin/bash");
        assert!(shebang.args.is_empty());
    }

    #[test]
    fn test_parse_python_env_shebang() {
        let content = "#!/usr/bin/env python3 -u\nprint('hello')";
        let shebang = ShebangParser::parse(content).unwrap();

        assert_eq!(shebang.interpreter, "env");
        assert_eq!(shebang.args, vec!["python3", "-u"]);
    }

    #[test]
    fn test_language_detection() {
        assert_eq!(
            ShebangParser::parse_and_detect_language("#!/bin/bash\necho test"),
            Some(Language::Bash)
        );

        assert_eq!(
            ShebangParser::parse_and_detect_language("#!/usr/bin/env python3\nprint('test')"),
            Some(Language::Python)
        );
    }

    #[test]
    fn test_no_shebang() {
        let content = "echo hello";
        assert!(ShebangParser::parse(content).is_none());
    }

    #[test]
    fn test_validate_dangerous_shebang() {
        let content = "#!/bin/rm\necho test";
        assert!(ShebangParser::validate_shebang(content).is_err());
    }
}
