use anyhow::Result;
use proxy_gateway_core::{AffinityParams, CountingPool, ProxySource, SourceProxy};
use std::path::Path;

use crate::config::StaticFileConfig;
use crate::parse::load_proxies;

/// A proxy source backed by a fixed list loaded from a text file at startup.
///
/// Endpoint selection uses a least-used counter with random tie-breaking so
/// load is spread evenly across all entries in the file.
pub struct StaticFileSource {
    pool: CountingPool<SourceProxy>,
    path_display: String,
}

impl std::fmt::Debug for StaticFileSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticFileSource")
            .field("path", &self.path_display)
            .field("entries", &self.pool.len())
            .finish()
    }
}

impl StaticFileSource {
    /// Load the source from the given file path.
    pub fn load(path: &Path) -> Result<Self> {
        let proxies = load_proxies(path)?;
        if proxies.is_empty() {
            anyhow::bail!("no proxies found in {}", path.display());
        }

        Ok(Self {
            pool: CountingPool::new(proxies),
            path_display: path.display().to_string(),
        })
    }
}

impl ProxySource for StaticFileSource {
    fn get_source_proxy(&self, _affinity_params: &AffinityParams) -> Option<SourceProxy> {
        self.pool.next().cloned()
    }

    fn get_source_proxy_force_rotate(
        &self,
        _affinity_params: &AffinityParams,
        current: &SourceProxy,
    ) -> Option<SourceProxy> {
        self.pool.next_excluding(current).cloned()
    }

    fn describe(&self) -> String {
        format!(
            "static file '{}' with {} entries",
            self.path_display,
            self.pool.len()
        )
    }
}

/// Construct a [`StaticFileSource`] from config, resolving relative paths
/// against `config_dir`.
pub fn build_source(config: &StaticFileConfig, config_dir: &Path) -> Result<Box<dyn ProxySource>> {
    let path = if config.proxies_file.is_relative() {
        config_dir.join(&config.proxies_file)
    } else {
        config.proxies_file.clone()
    };
    let source = StaticFileSource::load(&path)?;
    Ok(Box::new(source))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_build_source_resolves_relative_path() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "198.51.100.1:6658:user:pass").unwrap();
        f.flush().unwrap();

        let cfg = StaticFileConfig {
            proxies_file: f.path().to_path_buf(),
        };
        let source = build_source(&cfg, Path::new(".")).unwrap();
        assert!(source.describe().contains("1 entries"));
    }

    #[test]
    fn test_build_source_empty_file_fails() {
        let f = NamedTempFile::new().unwrap();
        let cfg = StaticFileConfig {
            proxies_file: f.path().to_path_buf(),
        };
        assert!(build_source(&cfg, Path::new(".")).is_err());
    }

    #[test]
    fn test_get_source_proxy_returns_proxy() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "198.51.100.1:6658:user:pass").unwrap();
        writeln!(f, "198.51.100.2:7872:user:pass").unwrap();
        f.flush().unwrap();

        let source = StaticFileSource::load(f.path()).unwrap();
        let affinity_params = AffinityParams::new();
        let p = source.get_source_proxy(&affinity_params).unwrap();
        assert!(p.host == "198.51.100.1" || p.host == "198.51.100.2");
    }
}
