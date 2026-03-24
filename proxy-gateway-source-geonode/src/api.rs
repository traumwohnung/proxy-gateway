//! Geonode REST API client.

use anyhow::{Context, Result};

use crate::config::GeonodeConfig;

const API_URL: &str = "https://api.geonode.com/proxies";

/// A single proxy entry as returned by `GET /proxies`.
#[derive(Debug, serde::Deserialize)]
pub struct ApiProxy {
    pub host: String,
    /// The API returns port as a string.
    pub port: String,
}

/// Wire format of `GET /proxies`.
#[derive(Debug, serde::Deserialize)]
struct ApiResponse {
    success: bool,
    data: Option<Vec<ApiProxy>>,
    error: Option<String>,
}

/// Fetch proxy candidates from the geonode API.
///
/// Returns the `data` array on success, or an error if the API signals failure
/// or returns an empty list.
pub async fn fetch_proxies(
    client: &reqwest::Client,
    cfg: &GeonodeConfig,
    password: &str,
) -> Result<Vec<ApiProxy>> {
    let mut req = client
        .get(API_URL)
        .basic_auth(&cfg.username, Some(password))
        .query(&[("limit", cfg.limit.to_string())]);

    if let Some(ref country) = cfg.country {
        req = req.query(&[("country", country.as_str())]);
    }
    if let Some(ref proxy_type) = cfg.proxy_type {
        req = req.query(&[("type", proxy_type.as_str())]);
    }
    if let Some(ref protocol) = cfg.protocol {
        req = req.query(&[("protocol", protocol.as_str())]);
    }

    let resp: ApiResponse = req
        .send()
        .await
        .context("geonode API request failed")?
        .error_for_status()
        .context("geonode API returned HTTP error")?
        .json()
        .await
        .context("geonode API response is not valid JSON")?;

    if !resp.success {
        anyhow::bail!(
            "geonode API error: {}",
            resp.error.as_deref().unwrap_or("unknown error")
        );
    }

    let data = resp.data.unwrap_or_default();
    if data.is_empty() {
        anyhow::bail!("geonode API returned no proxies for the requested filters");
    }

    Ok(data)
}
