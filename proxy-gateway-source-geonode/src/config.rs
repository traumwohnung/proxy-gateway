use proxy_gateway_core::Country;

/// Configuration for the geonode proxy source.
///
/// Geonode encodes targeting and session parameters directly into the upstream
/// proxy username — no external API call is needed at request time.
///
/// **Rotating (default)**
/// ```toml
/// [[proxy_set]]
/// name = "geonode-residential"
/// source_type = "geonode"
///
/// [proxy_set.source]
/// username     = "geonode-exampleuser"
/// password_env = "GEONODE_PASSWORD"
/// gateway      = "us"             # "fr" | "us" | "sg"
/// countries    = ["US", "DE"]     # optional, one picked randomly per request
/// ```
///
/// **Sticky session**
/// ```toml
/// [proxy_set.source]
/// username     = "geonode-exampleuser"
/// password_env = "GEONODE_PASSWORD"
/// gateway      = "us"
/// countries    = ["US"]
///
/// [proxy_set.source.session]
/// type      = "sticky"
/// sess_time = 10  # minutes
/// ```
#[derive(Debug, Clone, serde::Deserialize)]
pub struct GeonodeConfig {
    /// Account username (e.g. `"geonode-exampleuser"`).
    pub username: String,

    /// Environment variable name that holds the proxy password.
    pub password_env: String,

    /// Which geonode gateway to connect through.
    pub gateway: GeonodeGateway,

    /// Protocol to use (default: http).
    #[serde(default)]
    pub protocol: GeonodeProtocol,

    /// Target countries (multi-select). One is picked randomly per request.
    /// If empty, no country targeting is applied.
    #[serde(default)]
    pub countries: Vec<Country>,

    /// Session configuration. If absent, rotating sessions are used.
    #[serde(default)]
    pub session: SessionConfig,
}

impl GeonodeConfig {
    /// The upstream proxy host derived from the gateway.
    pub fn host(&self) -> &'static str {
        self.gateway.host()
    }

    /// The upstream proxy port derived from protocol and session type.
    pub fn port(&self) -> u16 {
        match (&self.protocol, &self.session) {
            (GeonodeProtocol::Http, SessionConfig::Rotating) => 9000,
            (GeonodeProtocol::Http, SessionConfig::Sticky(_)) => 10000,
            (GeonodeProtocol::Socks5, SessionConfig::Rotating) => 11000,
            (GeonodeProtocol::Socks5, SessionConfig::Sticky(_)) => 12000,
        }
    }
}

/// Geonode gateway location.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeonodeGateway {
    /// France — `proxy.geonode.io`
    Fr,
    /// United States — `us.premium-residential.geonode.com`
    Us,
    /// Singapore — `sg.premium-residential.geonode.com`
    Sg,
}

impl GeonodeGateway {
    pub fn host(self) -> &'static str {
        match self {
            Self::Fr => "proxy.geonode.io",
            Self::Us => "us.premium-residential.geonode.com",
            Self::Sg => "sg.premium-residential.geonode.com",
        }
    }
}

/// Protocol to use when connecting through the geonode gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GeonodeProtocol {
    #[default]
    Http,
    Socks5,
}

/// Session behaviour for the upstream proxy.
#[derive(Debug, Clone, serde::Deserialize, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionConfig {
    /// A new IP is assigned for every request (default).
    #[default]
    Rotating,

    /// The same IP is reused for `sess_time` minutes.
    Sticky(StickyConfig),
}

/// Configuration for sticky sessions.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct StickyConfig {
    /// How long (in minutes) the assigned IP should remain active.
    pub sess_time: u32,
}
