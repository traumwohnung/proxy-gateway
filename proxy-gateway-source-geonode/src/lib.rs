//! Geonode API-based proxy source.
//!
//! Fetches upstream proxy endpoints dynamically from the geonode REST API
//! (`GET https://api.geonode.com/proxies`) on every `get_source_proxy` call.
//! Supports filtering by country, type (residential/datacenter/mobile), and
//! protocol. The same credentials used for the API call are embedded as the
//! upstream proxy auth.

mod api;
mod config;
mod source;

pub use config::GeonodeConfig;
pub use source::{build_source, GeonodeSource};
