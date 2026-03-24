//! Proxy source dispatch.
//!
//! This module re-exports the core trait and types, and provides the factory
//! function that maps a `source_type` string to the appropriate source crate.
//!
//! Adding a new source type requires:
//! 1. A new source crate implementing [`ProxySource`].
//! 2. A new arm in [`ProxySourceConfig::from_type_and_table`] and [`build_source`].

use anyhow::Result;
use std::path::Path;

// Re-export core types so the rest of the gateway crate can use them unchanged.
pub use proxy_gateway_core::{AffinityParams, CountingPool, ProxySource, SourceProxy};

// ---------------------------------------------------------------------------
// Configuration enum (dispatches to source crates)
// ---------------------------------------------------------------------------

/// Discriminated union of all supported proxy source configurations.
///
/// The discriminant (`source_type` field) lives on the parent `[[proxy_set]]`
/// table; the `[proxy_set.source]` sub-table carries only the type-specific
/// parameters:
///
/// ```toml
/// [[proxy_set]]
/// name = "residential"
/// source_type = "static_file"
///
/// [proxy_set.source]
/// proxies_file = "residential.txt"
/// ```
#[derive(Debug, Clone)]
pub enum ProxySourceConfig {
    /// Load proxies from a plain-text file at startup.
    StaticFile(proxy_gateway_source_static_file::StaticFileConfig),
}

impl ProxySourceConfig {
    /// Construct from the `type` string and the raw TOML source table.
    ///
    /// This is the single dispatch point that maps a type name to the
    /// appropriate config struct.
    pub fn from_type_and_table(source_type: &str, table: &toml::Table) -> anyhow::Result<Self> {
        match source_type {
            "static_file" => {
                let cfg: proxy_gateway_source_static_file::StaticFileConfig = table
                    .clone()
                    .try_into()
                    .map_err(|e| anyhow::anyhow!("invalid static_file source config: {e}"))?;
                Ok(Self::StaticFile(cfg))
            }
            other => anyhow::bail!(
                "unknown source type '{}'. Supported types: static_file",
                other
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Construct a boxed [`ProxySource`] from a config value.
///
/// `config_dir` is used to resolve relative file paths.
pub fn build_source(cfg: &ProxySourceConfig, config_dir: &Path) -> Result<Box<dyn ProxySource>> {
    match cfg {
        ProxySourceConfig::StaticFile(sc) => {
            proxy_gateway_source_static_file::build_source(sc, config_dir)
        }
    }
}
