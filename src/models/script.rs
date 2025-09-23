use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use crate::error::EbiError;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Script {
    pub content: String,
    pub language: Language,
    pub source: ScriptSource,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ScriptSource {
    Stdin,
    File(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Language {
    Bash,
    Python,
    Unknown,
}

impl Language {
    pub fn from_str(s: &str) -> Result<Self, EbiError> {
        match s.to_lowercase().as_str() {
            "bash" | "sh" | "shell" => Ok(Language::Bash),
            "python" | "python3" | "py" => Ok(Language::Python),
            _ => Err(EbiError::UnknownLanguage),
        }
    }

    pub fn from_command(command: &str) -> Option<Self> {
        match command {
            "bash" | "sh" | "zsh" | "dash" | "fish" => Some(Language::Bash),
            cmd if cmd.starts_with("python") => Some(Language::Python),
            _ => None,
        }
    }

    pub fn from_shebang(shebang_line: &str) -> Option<Self> {
        let shebang = shebang_line.trim();

        if shebang.starts_with("#!") {
            let interpreter = shebang.trim_start_matches("#!");

            if interpreter.contains("python") {
                Some(Language::Python)
            } else if interpreter.contains("bash") || interpreter.contains("/sh") {
                Some(Language::Bash)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Language::Bash => "bash",
            Language::Python => "python",
            Language::Unknown => "unknown",
        }
    }
}

impl Script {
    pub fn new(content: String, source: ScriptSource) -> Self {
        Self {
            content,
            language: Language::Unknown,
            source,
        }
    }

    pub fn with_language(mut self, language: Language) -> Self {
        self.language = language;
        self
    }

    pub fn detect_language(&mut self, cli_lang: Option<&str>, command: Option<&str>) -> Result<(), EbiError> {
        // Priority 1: Explicit CLI flag
        if let Some(lang_str) = cli_lang {
            self.language = Language::from_str(lang_str)?;
            return Ok(());
        }

        // Priority 2: Command name inference
        if let Some(cmd) = command {
            if let Some(lang) = Language::from_command(cmd) {
                self.language = lang;
                return Ok(());
            }
        }

        // Priority 3: Shebang parsing
        if let Some(first_line) = self.content.lines().next() {
            if let Some(lang) = Language::from_shebang(first_line) {
                self.language = lang;
                return Ok(());
            }
        }

        // If all detection methods fail
        Err(EbiError::UnknownLanguage)
    }

    pub fn is_empty(&self) -> bool {
        self.content.trim().is_empty()
    }

    pub fn size_bytes(&self) -> usize {
        self.content.len()
    }

    pub fn line_count(&self) -> usize {
        self.content.lines().count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_language_from_str() {
        assert_eq!(Language::from_str("bash").unwrap(), Language::Bash);
        assert_eq!(Language::from_str("python").unwrap(), Language::Python);
        assert_eq!(Language::from_str("Python").unwrap(), Language::Python);
        assert!(Language::from_str("unknown").is_err());
    }

    #[test]
    fn test_language_from_command() {
        assert_eq!(Language::from_command("bash"), Some(Language::Bash));
        assert_eq!(Language::from_command("python3"), Some(Language::Python));
        assert_eq!(Language::from_command("unknown"), None);
    }

    #[test]
    fn test_language_from_shebang() {
        assert_eq!(Language::from_shebang("#!/bin/bash"), Some(Language::Bash));
        assert_eq!(Language::from_shebang("#!/usr/bin/env python3"), Some(Language::Python));
        assert_eq!(Language::from_shebang("not a shebang"), None);
    }

    #[test]
    fn test_script_language_detection_priority() {
        let mut script = Script::new(
            "#!/usr/bin/env python3\nprint('hello')".to_string(),
            ScriptSource::Stdin,
        );

        // CLI flag should take priority over shebang
        script.detect_language(Some("bash"), Some("python3")).unwrap();
        assert_eq!(script.language, Language::Bash);

        // Reset and test command priority
        script.language = Language::Unknown;
        script.detect_language(None, Some("python3")).unwrap();
        assert_eq!(script.language, Language::Python);

        // Reset and test shebang fallback
        script.language = Language::Unknown;
        script.detect_language(None, None).unwrap();
        assert_eq!(script.language, Language::Python);
    }
}