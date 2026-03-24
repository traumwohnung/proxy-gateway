use crate::AffinityParams;
use crate::SourceProxy;

/// Abstraction over "give me the next upstream proxy endpoint".
///
/// Implementations are `Send + Sync` so they can live inside an `Arc` shared
/// across Tokio tasks.
pub trait ProxySource: Send + Sync + std::fmt::Debug {
    /// Return an upstream proxy to use for the next request.
    ///
    /// `affinity_params` carries the decoded JSON metadata from the
    /// proxy-authorization username that some sources may use to influence
    /// which endpoint they return.  Static sources ignore it.
    ///
    /// Returns `None` if the source is temporarily unable to provide an
    /// endpoint (e.g. an empty pool or a failed API call); the caller should
    /// treat this as a configuration / connectivity error.
    fn get_source_proxy(&self, affinity_params: &AffinityParams) -> Option<SourceProxy>;

    /// Return a *different* upstream proxy for force-rotation.
    ///
    /// `current` is the proxy the session is currently pinned to.  Sources
    /// should make a best-effort attempt to return a different endpoint, but
    /// may fall back to `current` if no alternatives exist (e.g. a
    /// single-entry pool).
    ///
    /// The default implementation simply delegates to [`get_source_proxy`](Self::get_source_proxy).
    fn get_source_proxy_force_rotate(
        &self,
        affinity_params: &AffinityParams,
        current: &SourceProxy,
    ) -> Option<SourceProxy> {
        let _ = current;
        self.get_source_proxy(affinity_params)
    }

    /// Human-readable description used in log messages (e.g. "static file
    /// /etc/proxies/residential.txt with 120 entries").
    fn describe(&self) -> String;
}
