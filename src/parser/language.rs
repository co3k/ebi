use crate::error::EbiError;
use crate::models::Language;
use std::path::Path;

pub struct LanguageDetector;

impl LanguageDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect_from_cli_override(lang_str: &str) -> Result<Language, EbiError> {
        Language::from_str(lang_str)
    }

    pub fn detect_from_command(command: &str) -> Option<Language> {
        let command_name = Path::new(command)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(command);

        match command_name {
            "bash" | "sh" | "zsh" | "fish" | "dash" => Some(Language::Bash),
            "python" | "python3" | "python2" | "py" => Some(Language::Python),
            _ => None,
        }
    }

    pub fn detect_from_shebang(content: &str) -> Option<Language> {
        let first_line = content.lines().next()?;

        if !first_line.starts_with("#!") {
            return None;
        }

        let shebang = first_line.trim();

        if shebang.contains("bash") || shebang.contains("/bin/sh") || shebang.contains("zsh") {
            Some(Language::Bash)
        } else if shebang.contains("python") {
            Some(Language::Python)
        } else {
            None
        }
    }

    pub fn detect_from_extension(filename: &str) -> Option<Language> {
        let path = Path::new(filename);
        match path.extension().and_then(|ext| ext.to_str()) {
            Some("sh") | Some("bash") => Some(Language::Bash),
            Some("py") | Some("python") => Some(Language::Python),
            _ => None,
        }
    }

    pub fn detect_language(
        &self,
        content: &str,
        cli_override: Option<&str>,
        command: Option<&str>,
        filename: Option<&str>,
    ) -> Result<Language, EbiError> {
        // Priority order as per requirements:
        // 1. CLI override (--lang flag)
        if let Some(lang_str) = cli_override {
            return Self::detect_from_cli_override(lang_str);
        }

        // 2. Command name detection
        if let Some(cmd) = command {
            if let Some(lang) = Self::detect_from_command(cmd) {
                return Ok(lang);
            }
        }

        // 3. Shebang line detection
        if let Some(lang) = Self::detect_from_shebang(content) {
            return Ok(lang);
        }

        // 4. File extension (if filename provided)
        if let Some(name) = filename {
            if let Some(lang) = Self::detect_from_extension(name) {
                return Ok(lang);
            }
        }

        // 5. Content-based heuristics as fallback
        self.detect_from_content_heuristics(content)
    }

    fn detect_from_content_heuristics(&self, content: &str) -> Result<Language, EbiError> {
        let lines: Vec<&str> = content.lines().collect();
        let mut bash_score = 0;
        let mut python_score = 0;

        for line in &lines {
            let trimmed = line.trim();

            // Bash indicators
            if trimmed.starts_with("export ")
                || trimmed.contains("$") && (trimmed.contains("{") || trimmed.contains("("))
                || trimmed.contains("[[")
                || trimmed.contains("]]")
                || trimmed.starts_with("if [")
                || trimmed.starts_with("while [")
                || trimmed.contains(">&")
                || trimmed.contains("2>&1")
                || trimmed.starts_with("function ")
                || trimmed.contains(" && ")
                || trimmed.contains(" || ")
            {
                bash_score += 1;
            }

            // Python indicators
            if trimmed.starts_with("def ")
                || trimmed.starts_with("class ")
                || trimmed.starts_with("import ")
                || trimmed.starts_with("from ")
                || trimmed.contains("if __name__ == '__main__'")
                || trimmed.contains("print(")
                || trimmed.ends_with(":")
                    && (trimmed.starts_with("if ")
                        || trimmed.starts_with("for ")
                        || trimmed.starts_with("while ")
                        || trimmed.starts_with("try:")
                        || trimmed.starts_with("except "))
            {
                python_score += 1;
            }
        }

        if bash_score > python_score && bash_score > 0 {
            Ok(Language::Bash)
        } else if python_score > 0 {
            Ok(Language::Python)
        } else {
            Err(EbiError::UnknownLanguage)
        }
    }
}

impl Default for LanguageDetector {
    fn default() -> Self {
        Self::new()
    }
}
