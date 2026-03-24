use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

use crate::source::{build_source, ProxySource, ProxySourceConfig};

// Re-export from core so existing users of `config::SourceProxy` keep working.
pub use proxy_gateway_core::SourceProxy;

/// Top-level configuration file (TOML).
#[derive(Debug, Deserialize)]
pub struct Config {
    /// Address to bind the proxy listener to.
    /// Default: "127.0.0.1:8100"
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,

    /// Log level / filter string.
    /// Default: "info"
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Proxy sets.
    #[serde(rename = "proxy_set")]
    pub proxy_sets: Vec<ProxySetConfig>,
}

/// Configuration for a single proxy set.
///
/// The `source_type` field selects the source kind; the `source` table carries
/// the source-specific parameters (different fields per type).
///
/// ```toml
/// [[proxy_set]]
/// name = "residential"
/// source_type = "static_file"
///
/// [proxy_set.source]
/// proxies_file = "residential.txt"
/// ```
#[derive(Debug, Deserialize)]
pub struct ProxySetConfig {
    /// Name of this proxy set (used as the proxy username to select it).
    pub name: String,

    /// Source type discriminant (e.g. `"static_file"`).
    pub source_type: String,

    /// Source-specific configuration table. The expected keys depend on
    /// `source_type`.
    #[serde(default)]
    pub source: toml::Table,
}

fn default_bind_addr() -> String {
    "127.0.0.1:8100".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

/// A fully-initialised proxy set ready for use by the [`crate::rotator::Rotator`].
///
/// The `source` field is a type-erased [`ProxySource`] that the rotator calls
/// on every request to obtain the next upstream endpoint. All source-specific
/// logic (file I/O, API calls, address generation) is encapsulated inside the
/// source implementation.
pub struct ProxySet {
    pub name: String,
    pub source: Box<dyn ProxySource>,
}

impl std::fmt::Debug for ProxySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxySet")
            .field("name", &self.name)
            .field("source", &self.source.describe())
            .finish()
    }
}

impl Config {
    /// Load config from a TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let content =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let config: Config =
            toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
        Ok(config)
    }
}

/// Build all proxy sets from config by constructing the appropriate source for
/// each set.
///
/// `config_dir` is the directory that contains the config file; it is used to
/// resolve relative paths inside source configurations.
pub fn build_proxy_sets(config: &Config, config_dir: &Path) -> Result<Vec<ProxySet>> {
    let mut sets = Vec::new();
    for ps in &config.proxy_sets {
        let source_config = ProxySourceConfig::from_type_and_table(&ps.source_type, &ps.source)
            .with_context(|| {
                format!(
                    "parsing source config for proxy set '{}' (type '{}')",
                    ps.name, ps.source_type
                )
            })?;
        let source = build_source(&source_config, config_dir)
            .with_context(|| format!("initialising source for proxy set '{}'", ps.name))?;

        tracing::info!("Loaded proxy set '{}': {}", ps.name, source.describe(),);

        sets.push(ProxySet {
            name: ps.name.clone(),
            source,
        });
    }
    Ok(sets)
}
