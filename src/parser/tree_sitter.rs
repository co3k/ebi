use crate::models::{Language, ScriptComponents};
use crate::error::EbiError;
use std::time::Instant;

// Placeholder tree-sitter structures since we don't have actual grammars
pub struct TreeSitterParser {
    language: Language,
}

pub struct ParsedNode {
    pub node_type: String,
    pub text: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_row: usize,
    pub end_row: usize,
}

pub struct ParseTree {
    pub root_node: ParsedNode,
    pub language: Language,
    pub total_nodes: usize,
}

impl TreeSitterParser {
    pub fn new(language: Language) -> Result<Self, EbiError> {
        // Validate that we support this language
        match language {
            Language::Bash | Language::Python => Ok(Self { language }),
            Language::Unknown => Err(EbiError::UnknownLanguage),
        }
    }

    pub fn parse(&self, source_code: &str) -> Result<ParseTree, EbiError> {
        let start_time = Instant::now();

        // Since we don't have actual tree-sitter grammars, we'll create a mock parse tree
        // In a real implementation, this would use tree-sitter-bash or tree-sitter-python
        let parse_tree = self.create_mock_parse_tree(source_code)?;

        let _parse_duration = start_time.elapsed();

        Ok(parse_tree)
    }

    fn create_mock_parse_tree(&self, source_code: &str) -> Result<ParseTree, EbiError> {
        let lines: Vec<&str> = source_code.lines().collect();
        let total_nodes = lines.len();

        let root_node = ParsedNode {
            node_type: "source_file".to_string(),
            text: source_code.to_string(),
            start_byte: 0,
            end_byte: source_code.len(),
            start_row: 0,
            end_row: lines.len().saturating_sub(1),
        };

        Ok(ParseTree {
            root_node,
            language: self.language.clone(),
            total_nodes,
        })
    }

    pub fn extract_components(&self, parse_tree: &ParseTree) -> Result<ScriptComponents, EbiError> {
        let start_time = Instant::now();

        let mut components = ScriptComponents::new();

        // Extract components based on language
        match self.language {
            Language::Bash => {
                self.extract_bash_components(&parse_tree.root_node, &mut components)?;
            }
            Language::Python => {
                self.extract_python_components(&parse_tree.root_node, &mut components)?;
            }
            Language::Unknown => {
                return Err(EbiError::UnknownLanguage);
            }
        }

        // Update metadata
        let parse_time_ms = start_time.elapsed().as_millis() as u64;
        components.metadata.total_nodes = parse_tree.total_nodes;
        components.metadata.parse_time_ms = parse_time_ms;
        components.metadata.language = self.language.clone();

        Ok(components)
    }

    fn extract_bash_components(
        &self,
        node: &ParsedNode,
        components: &mut ScriptComponents,
    ) -> Result<(), EbiError> {
        let lines: Vec<&str> = node.text.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Extract comments
            if let Some(comment_start) = trimmed.find('#') {
                // Ensure it's not in a string (basic check)
                let before_hash = &trimmed[..comment_start];
                let quote_count = before_hash.chars().filter(|&c| c == '"' || c == '\'').count();

                if quote_count % 2 == 0 { // Even number of quotes means we're not inside a string
                    let comment = trimmed[comment_start..].to_string();
                    components.add_comment(comment);
                }
            }

            // Extract string literals (basic implementation)
            self.extract_string_literals_bash(line, components);

            // Extract function definitions
            if trimmed.starts_with("function ") || trimmed.contains("() {") {
                let func_name = self.extract_function_name_bash(trimmed);
                if let Some(name) = func_name {
                    components.add_function_definition(name, i + 1);
                }
            }

            // Extract variable assignments
            if let Some(equals_pos) = trimmed.find('=') {
                if equals_pos > 0 && !trimmed[..equals_pos].contains(' ') {
                    let var_name = trimmed[..equals_pos].to_string();
                    components.add_variable_assignment(var_name, i + 1);
                }
            }

            // Extract command substitutions
            if trimmed.contains("$(") || trimmed.contains("`") {
                components.add_command_substitution(format!("Line {}: {}", i + 1, trimmed));
            }
        }

        // Set the cleaned code body (remove comments and empty lines)
        let code_body = lines
            .iter()
            .map(|line| {
                if let Some(comment_pos) = line.find('#') {
                    let before_hash = &line[..comment_pos];
                    let quote_count = before_hash.chars().filter(|&c| c == '"' || c == '\'').count();
                    if quote_count % 2 == 0 {
                        line[..comment_pos].trim_end().to_string()
                    } else {
                        line.to_string()
                    }
                } else {
                    line.to_string()
                }
            })
            .filter(|line| !line.trim().is_empty())
            .collect::<Vec<_>>()
            .join("\n");

        components.code_body = code_body;

        Ok(())
    }

    fn extract_python_components(
        &self,
        node: &ParsedNode,
        components: &mut ScriptComponents,
    ) -> Result<(), EbiError> {
        let lines: Vec<&str> = node.text.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Extract comments
            if trimmed.starts_with('#') {
                components.add_comment(trimmed.to_string());
            }

            // Extract string literals
            self.extract_string_literals_python(line, components);

            // Extract function definitions
            if trimmed.starts_with("def ") {
                let func_name = self.extract_function_name_python(trimmed);
                if let Some(name) = func_name {
                    components.add_function_definition(name, i + 1);
                }
            }

            // Extract class definitions
            if trimmed.starts_with("class ") {
                let class_name = self.extract_class_name_python(trimmed);
                if let Some(name) = class_name {
                    components.add_class_definition(name, i + 1);
                }
            }

            // Extract imports
            if trimmed.starts_with("import ") || trimmed.starts_with("from ") {
                components.add_import_statement(trimmed.to_string(), i + 1);
            }
        }

        // Set the cleaned code body (remove comments and empty lines)
        let code_body = lines
            .iter()
            .filter(|line| !line.trim().is_empty() && !line.trim().starts_with('#'))
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        components.code_body = code_body;

        Ok(())
    }

    fn extract_string_literals_bash(&self, line: &str, components: &mut ScriptComponents) {
        // Basic string literal extraction for bash
        let mut in_single_quote = false;
        let mut in_double_quote = false;
        let mut current_string = String::new();
        let mut chars = line.chars().peekable();

        while let Some(ch) = chars.next() {
            match ch {
                '\'' if !in_double_quote => {
                    if in_single_quote {
                        components.add_string_literal(format!("'{}'", current_string));
                        current_string.clear();
                    }
                    in_single_quote = !in_single_quote;
                }
                '"' if !in_single_quote => {
                    if in_double_quote {
                        components.add_string_literal(format!("\"{}\"", current_string));
                        current_string.clear();
                    }
                    in_double_quote = !in_double_quote;
                }
                _ if in_single_quote || in_double_quote => {
                    current_string.push(ch);
                }
                _ => {}
            }
        }
    }

    fn extract_string_literals_python(&self, line: &str, components: &mut ScriptComponents) {
        // Basic string literal extraction for python
        let patterns = [
            ("\"\"\"", "\"\"\""), // Triple double quotes
            ("'''", "'''"),       // Triple single quotes
            ("\"", "\""),         // Double quotes
            ("'", "'"),           // Single quotes
        ];

        for (start, end) in &patterns {
            if let Some(start_pos) = line.find(start) {
                if let Some(end_pos) = line[start_pos + start.len()..].find(end) {
                    let full_end = start_pos + start.len() + end_pos + end.len();
                    let string_literal = &line[start_pos..full_end];
                    components.add_string_literal(string_literal.to_string());
                }
            }
        }
    }

    fn extract_function_name_bash(&self, line: &str) -> Option<String> {
        if line.starts_with("function ") {
            // function name() { ... }
            let after_function = &line[9..];
            if let Some(paren_pos) = after_function.find('(') {
                Some(after_function[..paren_pos].trim().to_string())
            } else if let Some(space_pos) = after_function.find(' ') {
                Some(after_function[..space_pos].trim().to_string())
            } else {
                None
            }
        } else if let Some(paren_pos) = line.find("() {") {
            // name() { ... }
            Some(line[..paren_pos].trim().to_string())
        } else {
            None
        }
    }

    fn extract_function_name_python(&self, line: &str) -> Option<String> {
        // def function_name(args):
        let after_def = &line[4..]; // Skip "def "
        if let Some(paren_pos) = after_def.find('(') {
            Some(after_def[..paren_pos].trim().to_string())
        } else {
            None
        }
    }

    fn extract_class_name_python(&self, line: &str) -> Option<String> {
        // class ClassName(base):
        let after_class = &line[6..]; // Skip "class "
        if let Some(paren_pos) = after_class.find('(') {
            Some(after_class[..paren_pos].trim().to_string())
        } else if let Some(colon_pos) = after_class.find(':') {
            Some(after_class[..colon_pos].trim().to_string())
        } else {
            None
        }
    }
}

// Factory function to create parsers
pub fn create_parser(language: Language) -> Result<TreeSitterParser, EbiError> {
    TreeSitterParser::new(language)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bash_parser_creation() {
        let parser = TreeSitterParser::new(Language::Bash);
        assert!(parser.is_ok());
    }

    #[test]
    fn test_python_parser_creation() {
        let parser = TreeSitterParser::new(Language::Python);
        assert!(parser.is_ok());
    }

    #[test]
    fn test_unknown_language_error() {
        let parser = TreeSitterParser::new(Language::Unknown);
        assert!(parser.is_err());
    }

    #[test]
    fn test_bash_parsing() {
        let parser = TreeSitterParser::new(Language::Bash).unwrap();
        let code = "#!/bin/bash\n# This is a comment\necho \"Hello World\"";
        let parse_tree = parser.parse(code).unwrap();

        assert_eq!(parse_tree.language, Language::Bash);
        assert!(parse_tree.total_nodes > 0);
    }

    #[test]
    fn test_component_extraction() {
        let parser = TreeSitterParser::new(Language::Bash).unwrap();
        let code = "#!/bin/bash\n# Comment\nVAR=\"value\"\necho $VAR";
        let parse_tree = parser.parse(code).unwrap();
        let components = parser.extract_components(&parse_tree).unwrap();

        assert!(!components.comments.is_empty());
        assert!(!components.string_literals.is_empty());
    }
}
