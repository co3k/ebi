// Parser module - handles AST parsing and component extraction

pub mod language;
pub mod shebang;
pub mod tree_sitter;
pub mod extractor;
pub mod classifier;

pub use language::LanguageDetector;
pub use shebang::{ShebangParser, ShebangInfo};
pub use tree_sitter::{TreeSitterParser, create_parser};
pub use extractor::ComponentExtractor;
pub use classifier::SecurityClassifier;