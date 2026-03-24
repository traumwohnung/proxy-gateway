use anyhow::Result;
use proxy_gateway_core::{AffinityParams, ProxySource, SourceProxy};

use crate::config::{BottingtoolsConfig, ProductConfig};
use crate::username::{build_username, rotate_session_id};

/// A proxy source that dynamically generates upstream proxy credentials
/// using the bottingtools username format.
///
/// Each call to [`get_source_proxy`](ProxySource::get_source_proxy) builds a
/// fresh username with a random session ID, encoding the affinity parameters
/// (country, city, sesstime, fastmode) into the upstream proxy username
/// according to the configured product type.
pub struct BottingtoolsSource {
    account_user: String,
    password: String,
    host: String,
    product: ProductConfig,
}

impl std::fmt::Debug for BottingtoolsSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BottingtoolsSource")
            .field("account_user", &self.account_user)
            .field("product", &self.product)
            .field("host", &self.host)
            .finish()
    }
}

impl BottingtoolsSource {
    /// Create a new source from config, resolving the password from the
    /// environment variable specified by `password_env`.
    pub fn from_config(config: &BottingtoolsConfig) -> Result<Self> {
        let password = std::env::var(&config.password_env).map_err(|_| {
            anyhow::anyhow!(
                "environment variable '{}' not set (required for bottingtools password)",
                config.password_env
            )
        })?;

        if password.is_empty() {
            anyhow::bail!("environment variable '{}' is empty", config.password_env);
        }

        Ok(Self {
            account_user: config.username.clone(),
            password,
            host: config.host.clone(),
            product: config.product.clone(),
        })
    }

    fn make_proxy(&self, username: String) -> SourceProxy {
        SourceProxy {
            host: self.host.clone(),
            port: 1337,
            username: Some(username),
            password: Some(self.password.clone()),
        }
    }
}

#[async_trait::async_trait]
impl ProxySource for BottingtoolsSource {
    async fn get_source_proxy(&self, affinity_params: &AffinityParams) -> Option<SourceProxy> {
        let username = build_username(&self.account_user, &self.product, affinity_params);
        Some(self.make_proxy(username))
    }

    async fn get_source_proxy_force_rotate(
        &self,
        _affinity_params: &AffinityParams,
        current: &SourceProxy,
    ) -> Option<SourceProxy> {
        // Re-use the existing upstream username but swap the session ID.
        // For products without a session segment (datacenter), this is a no-op.
        let new_username = current
            .username
            .as_deref()
            .map(rotate_session_id)
            .unwrap_or_else(|| {
                build_username(&self.account_user, &self.product, &AffinityParams::new())
            });
        Some(self.make_proxy(new_username))
    }

    fn describe(&self) -> String {
        let product = match &self.product {
            ProductConfig::Residential(cfg) => {
                format!("residential({})", cfg.quality.as_type_str())
            }
            ProductConfig::Isp(_) => "isp".to_string(),
            ProductConfig::Datacenter(_) => "datacenter".to_string(),
        };
        format!("bottingtools {} {}@{}", product, self.account_user, self.host)
    }
}

/// Construct a [`BottingtoolsSource`] from config.
pub fn build_source(config: &BottingtoolsConfig) -> Result<Box<dyn ProxySource>> {
    if let ProductConfig::Residential(ref cfg) = config.product {
        cfg.validate()?;
    }
    let source = BottingtoolsSource::from_config(config)?;
    Ok(Box::new(source))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DatacenterConfig, IspConfig, ResidentialConfig, ResidentialQuality};

    fn make_source(product: ProductConfig) -> BottingtoolsSource {
        std::env::set_var("TEST_BT_PASS", "XpmTeTdYy8hT");
        BottingtoolsSource::from_config(&BottingtoolsConfig {
            username: "exampleuser".to_string(),
            password_env: "TEST_BT_PASS".to_string(),
            host: "proxy.bottingtools.com".to_string(),
            product,
        })
        .unwrap()
    }

    fn residential() -> ProductConfig {
        ProductConfig::Residential(ResidentialConfig {
            quality: ResidentialQuality::High,
            countries: vec![],
            city: None,
        })
    }

    fn isp() -> ProductConfig {
        ProductConfig::Isp(IspConfig { countries: vec![] })
    }

    fn datacenter() -> ProductConfig {
        ProductConfig::Datacenter(DatacenterConfig { countries: vec![] })
    }

    fn params(pairs: &[(&str, &str)]) -> AffinityParams {
        let mut map = serde_json::Map::new();
        for (k, v) in pairs {
            map.insert(k.to_string(), serde_json::Value::String(v.to_string()));
        }
        AffinityParams::parse(map).unwrap()
    }

    #[tokio::test]
    async fn test_residential_proxy() {
        let source = make_source(residential());
        let proxy = source
            .get_source_proxy(&AffinityParams::new())
            .await
            .unwrap();
        assert_eq!(proxy.host, "proxy.bottingtools.com");
        assert_eq!(proxy.password.as_deref(), Some("XpmTeTdYy8hT"));
        assert!(proxy
            .username
            .unwrap()
            .starts_with("exampleuser_pool-custom_type-high_"));
    }

    #[tokio::test]
    async fn test_isp_proxy() {
        let source = make_source(isp());
        let proxy = source
            .get_source_proxy(&AffinityParams::new())
            .await
            .unwrap();
        assert!(proxy.username.unwrap().contains("_pool-isp_"));
    }

    #[tokio::test]
    async fn test_datacenter_proxy() {
        let source = make_source(ProductConfig::Datacenter(DatacenterConfig {
            countries: vec![proxy_gateway_core::Country::DE],
        }));
        let proxy = source
            .get_source_proxy(&AffinityParams::new())
            .await
            .unwrap();
        assert_eq!(
            proxy.username.as_deref(),
            Some("exampleuser_pool-dc_country-de")
        );
    }

    #[tokio::test]
    async fn test_each_call_has_different_session() {
        let source = make_source(residential());
        let p1 = source
            .get_source_proxy(&AffinityParams::new())
            .await
            .unwrap();
        let p2 = source
            .get_source_proxy(&AffinityParams::new())
            .await
            .unwrap();
        assert_ne!(p1.username, p2.username);
    }

    #[tokio::test]
    async fn test_force_rotate_changes_only_session_id() {
        let source = make_source(ProductConfig::Residential(ResidentialConfig {
            quality: ResidentialQuality::High,
            countries: vec![proxy_gateway_core::Country::US],
            city: None,
        }));
        let ap = params(&[("sesstime", "10")]);
        let original = source.get_source_proxy(&ap).await.unwrap();
        let rotated = source
            .get_source_proxy_force_rotate(&ap, &original)
            .await
            .unwrap();
        let orig_user = original.username.unwrap();
        let rot_user = rotated.username.unwrap();
        assert!(rot_user.contains("_country-US_"));
        assert!(rot_user.contains("_sesstime-10"));
        let orig_sess = orig_user
            .split('_')
            .find(|s| s.starts_with("session-"))
            .unwrap();
        let rot_sess = rot_user
            .split('_')
            .find(|s| s.starts_with("session-"))
            .unwrap();
        assert_ne!(orig_sess, rot_sess);
    }

    #[test]
    fn test_describe_residential() {
        let source = make_source(residential());
        assert_eq!(
            source.describe(),
            "bottingtools residential(high) exampleuser@proxy.bottingtools.com"
        );
    }

    #[test]
    fn test_describe_isp() {
        let source = make_source(isp());
        assert_eq!(
            source.describe(),
            "bottingtools isp exampleuser@proxy.bottingtools.com"
        );
    }

    #[test]
    fn test_describe_datacenter() {
        let source = make_source(datacenter());
        assert_eq!(
            source.describe(),
            "bottingtools datacenter exampleuser@proxy.bottingtools.com"
        );
    }

    #[test]
    fn test_city_with_single_country_ok() {
        std::env::set_var("TEST_BT_PASS", "XpmTeTdYy8hT");
        let config = BottingtoolsConfig {
            username: "exampleuser".to_string(),
            password_env: "TEST_BT_PASS".to_string(),
            host: "proxy.bottingtools.com".to_string(),
            product: ProductConfig::Residential(ResidentialConfig {
                quality: ResidentialQuality::High,
                countries: vec![proxy_gateway_core::Country::NL],
                city: Some("amsterdam".to_string()),
            }),
        };
        assert!(build_source(&config).is_ok());
    }

    #[test]
    fn test_city_with_multiple_countries_fails() {
        std::env::set_var("TEST_BT_PASS", "XpmTeTdYy8hT");
        let config = BottingtoolsConfig {
            username: "exampleuser".to_string(),
            password_env: "TEST_BT_PASS".to_string(),
            host: "proxy.bottingtools.com".to_string(),
            product: ProductConfig::Residential(ResidentialConfig {
                quality: ResidentialQuality::High,
                countries: vec![proxy_gateway_core::Country::NL, proxy_gateway_core::Country::DE],
                city: Some("amsterdam".to_string()),
            }),
        };
        assert!(build_source(&config).is_err());
    }

    #[test]
    fn test_city_with_no_country_fails() {
        std::env::set_var("TEST_BT_PASS", "XpmTeTdYy8hT");
        let config = BottingtoolsConfig {
            username: "exampleuser".to_string(),
            password_env: "TEST_BT_PASS".to_string(),
            host: "proxy.bottingtools.com".to_string(),
            product: ProductConfig::Residential(ResidentialConfig {
                quality: ResidentialQuality::High,
                countries: vec![],
                city: Some("amsterdam".to_string()),
            }),
        };
        assert!(build_source(&config).is_err());
    }

    #[test]
    fn test_missing_env_var_fails() {
        std::env::remove_var("NONEXISTENT_VAR_FOR_TEST");
        let config = BottingtoolsConfig {
            username: "user".to_string(),
            password_env: "NONEXISTENT_VAR_FOR_TEST".to_string(),
            host: "host.com".to_string(),
            product: residential(),
        };
        assert!(BottingtoolsSource::from_config(&config).is_err());
    }
}
