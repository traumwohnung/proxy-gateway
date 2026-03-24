use proxy_gateway_core::Country;

/// Configuration for the bottingtools proxy source.
///
/// The `product` sub-table selects the product type and carries only the
/// parameters relevant to that product.
///
/// **Residential:**
/// ```toml
/// [[proxy_set]]
/// name = "residential"
/// source_type = "bottingtools"
///
/// [proxy_set.source]
/// username = "exampleuser"
/// password_env = "BOTTINGTOOLS_PASSWORD"
/// host = "proxy.bottingtools.com"
///
/// [proxy_set.source.product]
/// type = "residential"
/// quality = "high"          # "low" | "high"
/// countries = ["US", "DE"]  # optional, multi-select
/// city = "amsterdam"        # optional, NL only
/// ```
///
/// **ISP:**
/// ```toml
/// [proxy_set.source.product]
/// type = "isp"
/// countries = ["US"]  # optional, multi-select
/// ```
///
/// **Datacenter:**
/// ```toml
/// [proxy_set.source.product]
/// type = "datacenter"
/// countries = ["DE"]  # optional, multi-select
/// ```
#[derive(Debug, Clone, serde::Deserialize)]
pub struct BottingtoolsConfig {
    /// Account username (e.g. `"exampleuser"`).
    pub username: String,

    /// Environment variable name that holds the proxy password.
    pub password_env: String,

    /// Proxy server hostname (e.g. `"proxy.bottingtools.com"`).
    pub host: String,

    /// Product-specific configuration.
    pub product: ProductConfig,
}

/// Product type — each variant carries only the parameters relevant to it.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProductConfig {
    /// Residential proxies via the `custom` pool.
    /// Supports: countries (multi-select), city (NL only), sesstime, fastmode.
    Residential(ResidentialConfig),

    /// ISP proxies via the `isp` pool.
    /// Supports: countries (multi-select), sesstime.
    Isp(IspConfig),

    /// Datacenter proxies via the `dc` pool.
    /// Supports: countries (multi-select).
    Datacenter(DatacenterConfig),
}

/// Configuration specific to the residential product.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ResidentialConfig {
    /// Quality tier.
    #[serde(default)]
    pub quality: ResidentialQuality,

    /// Target countries (multi-select). One is picked randomly per request.
    /// If empty, no country targeting is applied.
    /// Must be exactly one entry when `city` is set.
    #[serde(default)]
    pub countries: Vec<Country>,

    /// Target city (e.g. `"amsterdam"`).
    /// Only valid when `countries` contains exactly one entry.
    pub city: Option<String>,
}

impl ResidentialConfig {
    /// Validate the config, returning an error if constraints are violated.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.city.is_some() && self.countries.len() != 1 {
            anyhow::bail!(
                "residential `city` requires exactly one country, but {} {} configured",
                self.countries.len(),
                if self.countries.len() == 1 { "is" } else { "are" }
            );
        }
        Ok(())
    }
}

/// Configuration specific to the ISP product.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct IspConfig {
    /// Target countries (multi-select). One is picked randomly per request.
    #[serde(default)]
    pub countries: Vec<Country>,
}

/// Configuration specific to the datacenter product.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct DatacenterConfig {
    /// Target countries (multi-select). One is picked randomly per request.
    #[serde(default)]
    pub countries: Vec<Country>,
}

/// Residential proxy quality tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResidentialQuality {
    /// `residential_basic` → encoded as `type-low` in the upstream username.
    Low,
    /// `residential_premium` → encoded as `type-high` in the upstream username.
    High,
}

impl Default for ResidentialQuality {
    fn default() -> Self {
        Self::High
    }
}

impl ResidentialQuality {
    /// The string used in the upstream username (`type-{value}`).
    pub fn as_type_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::High => "high",
        }
    }
}
