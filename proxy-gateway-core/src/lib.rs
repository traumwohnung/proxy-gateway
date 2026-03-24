//! Core types and traits shared by the proxy gateway and its source crates.
//!
//! This crate defines:
//!
//! - [`SourceProxy`] — the common "endpoint" currency type.
//! - [`AffinityParams`] — validated affinity parameters from the username.
//! - [`ProxySource`] — the trait that source crates implement.
//! - [`CountingPool`] — a generic least-used selection pool.

mod affinity_params;
mod counting_pool;
mod proxy_source;
mod source_proxy;

pub use affinity_params::AffinityParams;
pub use counting_pool::CountingPool;
pub use proxy_source::ProxySource;
pub use source_proxy::SourceProxy;
