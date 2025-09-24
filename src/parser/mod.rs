// Parser module - handles AST parsing and component extraction

pub mod classifier;
pub mod extractor;
pub mod language;
pub mod shebang;
pub mod tree_sitter;

pub use classifier::SecurityClassifier;
pub use extractor::ComponentExtractor;
pub use language::LanguageDetector;
pub use shebang::{ShebangInfo, ShebangParser};
pub use tree_sitter::{create_parser, TreeSitterParser};
