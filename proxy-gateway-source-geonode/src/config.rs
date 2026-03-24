/// Configuration for the geonode proxy source.
///
/// Geonode is an API-based source: each call to `get_source_proxy` fetches a
/// proxy from the geonode REST API and returns it as the upstream.
///
/// The API credentials (`username` / `password_env`) are used **both** for
/// authenticating the management API call and as the credentials embedded in
/// the returned `SourceProxy` (i.e. what goes on the CONNECT tunnel).
///
/// ```toml
/// [[proxy_set]]
/// name = "geonode-residential-us"
/// source_type = "geonode"
///
/// [proxy_set.source]
/// username    = "geonode-exampleuser"
/// password_env = "GEONODE_PASSWORD"
///
/// # All fields below are optional.
/// country  = "US"            # ISO 2-letter code
/// type     = "residential"   # "residential" | "datacenter" | "mobile"
/// protocol = "http"          # "http" | "https" | "socks5"
/// limit    = 5               # how many candidates to fetch (picks one randomly)
/// ```
#[derive(Debug, Clone, serde::Deserialize)]
pub struct GeonodeConfig {
    /// Account username (e.g. `"geonode-exampleuser"`).
    pub username: String,

    /// Environment variable name that holds the API / proxy password.
    pub password_env: String,

    /// ISO 2-letter country code filter (e.g. `"US"`, `"DE"`).
    pub country: Option<String>,

    /// Proxy type filter: `"residential"`, `"datacenter"`, or `"mobile"`.
    #[serde(rename = "type")]
    pub proxy_type: Option<String>,

    /// Protocol filter: `"http"`, `"https"`, or `"socks5"`.
    pub protocol: Option<String>,

    /// How many candidates to fetch from the API per request (default: 5).
    /// One is picked randomly from the returned list.
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 {
    5
}
