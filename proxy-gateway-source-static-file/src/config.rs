/// Configuration for a static-file proxy source.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct StaticFileConfig {
    /// Path to the proxies file (one proxy per line).
    ///
    /// Relative paths are resolved against the directory that contains the
    /// main `config.toml` file.
    ///
    /// Format per line: `host:port:username:password` or `host:port`.
    /// Lines starting with `#` and blank lines are ignored.
    pub proxies_file: std::path::PathBuf,
}
