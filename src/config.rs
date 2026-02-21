use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

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

    /// Proxy sets, keyed by name.
    #[serde(rename = "proxy_set")]
    pub proxy_sets: Vec<ProxySetConfig>,
}

/// Configuration for a single proxy set.
#[derive(Debug, Deserialize)]
pub struct ProxySetConfig {
    /// Name of this proxy set (used as the proxy username to select it).
    pub name: String,

    /// Path to the proxies.txt file (one proxy per line: host:port).
    pub proxies_file: PathBuf,

    /// Session affinity duration in seconds.
    /// When set, the same client IP will be routed to the same upstream proxy
    /// for this duration. 0 = no affinity (pure round-robin).
    #[serde(default)]
    pub session_affinity_secs: u64,

    /// Optional username to send to upstream proxies.
    #[serde(default)]
    pub upstream_username: Option<String>,

    /// Optional password to send to upstream proxies.
    #[serde(default)]
    pub upstream_password: Option<String>,
}

fn default_bind_addr() -> String {
    "127.0.0.1:8100".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

/// A parsed upstream proxy entry.
#[derive(Debug, Clone)]
pub struct UpstreamProxy {
    pub host: String,
    pub port: u16,
}

/// A fully-loaded proxy set ready for use.
#[derive(Debug)]
pub struct ProxySet {
    pub name: String,
    pub proxies: Vec<UpstreamProxy>,
    pub session_affinity_secs: u64,
    pub upstream_username: Option<String>,
    pub upstream_password: Option<String>,
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

/// Parse a proxies.txt file. Each line is `host:port` (comments with # and blanks are skipped).
pub fn load_proxies(path: &Path) -> Result<Vec<UpstreamProxy>> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut proxies = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (host, port) = parse_host_port(line)
            .with_context(|| format!("{}:{}: invalid proxy entry '{}'", path.display(), i + 1, line))?;
        proxies.push(UpstreamProxy { host, port });
    }
    Ok(proxies)
}

fn parse_host_port(s: &str) -> Result<(String, u16)> {
    // Handle IPv6 [host]:port
    if let Some(bracket_end) = s.find(']') {
        let host = &s[1..bracket_end];
        let port_str = s.get(bracket_end + 2..).unwrap_or("80");
        let port: u16 = port_str.parse().context("invalid port")?;
        return Ok((host.to_string(), port));
    }

    match s.rsplit_once(':') {
        Some((host, port_str)) => {
            let port: u16 = port_str.parse().context("invalid port")?;
            Ok((host.to_string(), port))
        }
        None => anyhow::bail!("expected host:port, got '{}'", s),
    }
}

/// Load all proxy sets from config.
pub fn load_proxy_sets(config: &Config, config_dir: &Path) -> Result<Vec<ProxySet>> {
    let mut sets = Vec::new();
    for ps in &config.proxy_sets {
        let proxies_path = if ps.proxies_file.is_relative() {
            config_dir.join(&ps.proxies_file)
        } else {
            ps.proxies_file.clone()
        };
        let proxies = load_proxies(&proxies_path)?;
        if proxies.is_empty() {
            anyhow::bail!(
                "proxy set '{}': no proxies found in {}",
                ps.name,
                proxies_path.display()
            );
        }
        tracing::info!(
            "Loaded proxy set '{}': {} proxies from {}",
            ps.name,
            proxies.len(),
            proxies_path.display()
        );
        sets.push(ProxySet {
            name: ps.name.clone(),
            proxies,
            session_affinity_secs: ps.session_affinity_secs,
            upstream_username: ps.upstream_username.clone(),
            upstream_password: ps.upstream_password.clone(),
        });
    }
    Ok(sets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_host_port() {
        let (h, p) = parse_host_port("proxy.example.com:8080").unwrap();
        assert_eq!(h, "proxy.example.com");
        assert_eq!(p, 8080);
    }

    #[test]
    fn test_parse_host_port_ipv6() {
        let (h, p) = parse_host_port("[::1]:3128").unwrap();
        assert_eq!(h, "::1");
        assert_eq!(p, 3128);
    }

    #[test]
    fn test_load_proxies() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "# comment").unwrap();
        writeln!(f, "proxy1.example.com:8080").unwrap();
        writeln!(f, "").unwrap();
        writeln!(f, "proxy2.example.com:3128").unwrap();
        f.flush().unwrap();

        let proxies = load_proxies(f.path()).unwrap();
        assert_eq!(proxies.len(), 2);
        assert_eq!(proxies[0].host, "proxy1.example.com");
        assert_eq!(proxies[0].port, 8080);
        assert_eq!(proxies[1].host, "proxy2.example.com");
        assert_eq!(proxies[1].port, 3128);
    }
}
