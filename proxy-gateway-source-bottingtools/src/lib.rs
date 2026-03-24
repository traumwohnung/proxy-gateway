//! Bottingtools proxy source.
//!
//! Dynamically generates upstream proxy credentials using the bottingtools
//! username format, encoding affinity parameters (country, city, session time,
//! fast mode) into the upstream proxy username.

mod config;
mod source;
mod username;

pub use config::BottingtoolsConfig;
pub use source::{build_source, BottingtoolsSource};
