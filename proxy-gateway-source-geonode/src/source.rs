use anyhow::Context;
use proxy_gateway_core::{cheap_random, AffinityParams, ProxySource, SourceProxy};

use crate::api::fetch_proxies;
use crate::config::GeonodeConfig;

#[derive(Debug)]
pub struct GeonodeSource {
    config: GeonodeConfig,
    password: String,
    client: reqwest::Client,
}

impl GeonodeSource {
    pub fn from_config(cfg: &GeonodeConfig) -> anyhow::Result<Self> {
        let password = std::env::var(&cfg.password_env).with_context(|| {
            format!(
                "geonode: env var '{}' (password_env) is not set",
                cfg.password_env
            )
        })?;

        let client = reqwest::Client::new();

        Ok(Self {
            config: cfg.clone(),
            password,
            client,
        })
    }
}

impl ProxySource for GeonodeSource {
    fn get_source_proxy(&self, _affinity_params: &AffinityParams) -> Option<SourceProxy> {
        // ProxySource is sync; block on the async API call.
        let proxies = match tokio::runtime::Handle::try_current() {
            Ok(handle) => tokio::task::block_in_place(|| {
                handle.block_on(fetch_proxies(&self.client, &self.config, &self.password))
            }),
            Err(_) => tokio::runtime::Runtime::new()
                .expect("failed to create tokio runtime")
                .block_on(fetch_proxies(&self.client, &self.config, &self.password)),
        };

        let proxies = match proxies {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("geonode API call failed: {e:#}");
                return None;
            }
        };

        let idx = cheap_random() as usize % proxies.len();
        let proxy = &proxies[idx];

        let port: u16 = match proxy.port.parse() {
            Ok(p) => p,
            Err(_) => {
                tracing::error!("geonode API returned invalid port '{}'", proxy.port);
                return None;
            }
        };

        Some(SourceProxy {
            host: proxy.host.clone(),
            port,
            username: Some(self.config.username.clone()),
            password: Some(self.password.clone()),
        })
    }

    fn describe(&self) -> String {
        let mut parts = vec!["geonode".to_string()];
        if let Some(ref t) = self.config.proxy_type {
            parts.push(t.clone());
        }
        if let Some(ref c) = self.config.country {
            parts.push(c.clone());
        }
        parts.push(format!("{}@api.geonode.com", self.config.username));
        parts.join(" ")
    }
}

/// Construct a [`GeonodeSource`] from config.
pub fn build_source(config: &GeonodeConfig) -> anyhow::Result<Box<dyn ProxySource>> {
    Ok(Box::new(GeonodeSource::from_config(config)?))
}
