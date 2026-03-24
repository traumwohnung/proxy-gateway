//! Core types and traits shared by the proxy gateway and its source crates.
//!
//! This crate defines:
//!
//! - [`SourceProxy`] — the common "endpoint" currency type.
//! - [`AffinityParams`] — validated affinity parameters from the username.
//! - [`ProxySource`] — the trait that source crates implement.
//! - [`ProxyFormat`] / [`parse_proxy_line`] — proxy line format parsing.
//! - [`CountingPool`] — a generic least-used selection pool.
//! - [`cheap_random`] — fast thread-local xorshift64 for non-cryptographic use.

mod affinity_params;
mod cheap_random;
mod country;
mod counting_pool;
mod proxy_format;
mod proxy_source;
mod source_proxy;

pub use affinity_params::AffinityParams;
pub use cheap_random::cheap_random;
pub use country::Country;
pub use counting_pool::CountingPool;
pub use proxy_format::{parse_proxy_line, ProxyFormat};
pub use proxy_source::ProxySource;
pub use source_proxy::SourceProxy;
