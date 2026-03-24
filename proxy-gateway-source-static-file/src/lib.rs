//! Static-file proxy source.
//!
//! Loads a list of `host:port[:user:pass]` entries from a plain-text file at
//! startup and serves them via least-used selection with random tie-breaking.

mod config;
mod parse;
mod source;

pub use config::StaticFileConfig;
pub use parse::load_proxies;
pub use source::{build_source, StaticFileSource};
