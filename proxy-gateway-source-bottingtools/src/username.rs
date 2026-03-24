//! Bottingtools upstream proxy username encoding.
//!
//! Each product has its own username structure:
//!
//! **Residential** (`pool-custom`):
//! ```text
//! {user}_pool-custom_type-{low|high}[_country-{cc}][_city-{city}]_session-{hex16}[_sesstime-{min}][_fastmode-true]
//! ```
//!
//! **ISP** (`pool-isp`):
//! ```text
//! {user}_pool-isp[_country-{cc}]_session-{hex16}[_sesstime-{min}]
//! ```
//!
//! **Datacenter** (`pool-dc`):
//! ```text
//! {user}_pool-dc[_country-{cc}]
//! ```

use proxy_gateway_core::{cheap_random, AffinityParams};

use crate::config::{DatacenterConfig, IspConfig, ProductConfig, ResidentialConfig};
use crate::location::Country;

/// Build the upstream proxy username for the given product and affinity params.
///
/// Country and city come from the typed product config.
/// Session-related params (sesstime, fastmode) come from the per-request affinity params.
pub fn build_username(
    account_user: &str,
    product: &ProductConfig,
    affinity_params: &AffinityParams,
) -> String {
    match product {
        ProductConfig::Residential(cfg) => build_residential(account_user, cfg, affinity_params),
        ProductConfig::Isp(cfg) => build_isp(account_user, cfg, affinity_params),
        ProductConfig::Datacenter(cfg) => build_datacenter(account_user, cfg),
    }
}

// ---------------------------------------------------------------------------
// Per-product builders
// ---------------------------------------------------------------------------

fn build_residential(
    account_user: &str,
    cfg: &ResidentialConfig,
    params: &AffinityParams,
) -> String {
    let mut parts = vec![format!(
        "{}_pool-custom_type-{}",
        account_user,
        cfg.quality.as_type_str()
    )];

    if let Some(country) = pick_country(&cfg.countries) {
        // Residential encodes country in uppercase (e.g. `country-US`).
        parts.push(format!("country-{}", country.as_param_str().to_ascii_uppercase()));
    }
    if let Some(city) = &cfg.city {
        parts.push(format!("city-{}", city));
    }

    parts.push(format!("session-{}", random_session_id()));

    if let Some(val) = sesstime_str(params) {
        parts.push(format!("sesstime-{}", val));
    }
    if params.get("fastmode").and_then(|v| v.as_str()) == Some("true") {
        parts.push("fastmode-true".to_string());
    }

    parts.join("_")
}

fn build_isp(account_user: &str, cfg: &IspConfig, params: &AffinityParams) -> String {
    let mut parts = vec![format!("{}_pool-isp", account_user)];

    if let Some(country) = pick_country(&cfg.countries) {
        parts.push(format!("country-{}", country.as_param_str()));
    }

    parts.push(format!("session-{}", random_session_id()));

    if let Some(val) = sesstime_str(params) {
        parts.push(format!("sesstime-{}", val));
    }

    parts.join("_")
}

fn build_datacenter(account_user: &str, cfg: &DatacenterConfig) -> String {
    let mut parts = vec![format!("{}_pool-dc", account_user)];

    if let Some(country) = pick_country(&cfg.countries) {
        parts.push(format!("country-{}", country.as_param_str()));
    }

    parts.join("_")
}

// ---------------------------------------------------------------------------
// Force-rotation: replace only the session-XXXX segment
// ---------------------------------------------------------------------------

/// Replace the `session-XXXX` segment in an existing bottingtools username
/// with a fresh random session ID, preserving everything else.
///
/// If the username contains no `session-` segment (e.g. datacenter) it is
/// returned unchanged.
pub fn rotate_session_id(username: &str) -> String {
    let new_id = random_session_id();
    let mut result = String::with_capacity(username.len());
    let mut replaced = false;

    for part in username.split('_') {
        if !result.is_empty() {
            result.push('_');
        }
        if !replaced && part.starts_with("session-") {
            result.push_str("session-");
            result.push_str(&new_id);
            replaced = true;
        } else {
            result.push_str(part);
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Pick a country from a multi-select list using cheap random.
/// Returns `None` if the list is empty (no country targeting).
fn pick_country(countries: &[Country]) -> Option<Country> {
    if countries.is_empty() {
        return None;
    }
    let idx = cheap_random() as usize % countries.len();
    Some(countries[idx])
}

fn sesstime_str(params: &AffinityParams) -> Option<String> {
    match params.get("sesstime")? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Generate a random 16-hex-character session ID.
pub(crate) fn random_session_id() -> String {
    let a = cheap_random();
    let b = cheap_random();
    format!("{:016x}", a ^ (b.wrapping_shl(32)))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DatacenterConfig, IspConfig, ResidentialConfig, ResidentialQuality};
    use crate::location::Country;

    fn no_params() -> AffinityParams {
        AffinityParams::new()
    }

    fn params(pairs: &[(&str, &str)]) -> AffinityParams {
        let mut map = serde_json::Map::new();
        for (k, v) in pairs {
            map.insert(k.to_string(), serde_json::Value::String(v.to_string()));
        }
        AffinityParams::parse(map).unwrap()
    }

    fn residential(quality: ResidentialQuality, countries: Vec<Country>, city: Option<&str>) -> ProductConfig {
        ProductConfig::Residential(ResidentialConfig {
            quality,
            countries,
            city: city.map(str::to_string),
        })
    }

    // -- Residential --

    #[test]
    fn test_residential_no_location() {
        let product = residential(ResidentialQuality::High, vec![], None);
        let u = build_username("exampleuser", &product, &no_params());
        assert!(u.starts_with("exampleuser_pool-custom_type-high_session-"));
        assert!(!u.contains("country"));
        assert!(!u.contains("city"));
    }

    #[test]
    fn test_residential_low_quality() {
        let product = residential(ResidentialQuality::Low, vec![], None);
        let u = build_username("exampleuser", &product, &no_params());
        assert!(u.contains("_type-low_"));
    }

    #[test]
    fn test_residential_with_single_country() {
        let product = residential(ResidentialQuality::High, vec![Country::DE], None);
        let u = build_username("exampleuser", &product, &no_params());
        assert!(u.contains("_country-DE_"));
    }

    #[test]
    fn test_residential_with_city() {
        let product = residential(ResidentialQuality::High, vec![Country::NL], Some("amsterdam"));
        let u = build_username("exampleuser", &product, &no_params());
        assert!(u.contains("_country-NL_"));
        assert!(u.contains("_city-amsterdam_"));
    }

    #[test]
    fn test_residential_multi_country_picks_one() {
        let product = residential(ResidentialQuality::High, vec![Country::DE, Country::US, Country::NL], None);
        for _ in 0..20 {
            let u = build_username("exampleuser", &product, &no_params());
            let has_country = u.contains("_country-DE_")
                || u.contains("_country-US_")
                || u.contains("_country-NL_");
            assert!(has_country);
        }
    }

    #[test]
    fn test_residential_sesstime_and_fastmode_from_params() {
        let product = residential(ResidentialQuality::High, vec![], None);
        let p = params(&[("sesstime", "10"), ("fastmode", "true")]);
        let u = build_username("exampleuser", &product, &p);
        assert!(u.contains("_sesstime-10"));
        assert!(u.ends_with("_fastmode-true"));
    }

    // -- ISP --

    #[test]
    fn test_isp_no_country() {
        let product = ProductConfig::Isp(IspConfig { countries: vec![] });
        let u = build_username("exampleuser", &product, &no_params());
        assert!(u.starts_with("exampleuser_pool-isp_session-"));
        assert!(!u.contains("country"));
    }

    #[test]
    fn test_isp_with_country() {
        let product = ProductConfig::Isp(IspConfig { countries: vec![Country::US] });
        let u = build_username("exampleuser", &product, &params(&[("sesstime", "10")]));
        assert!(u.contains("_country-us_"));
        assert!(u.contains("_sesstime-10"));
    }

    // -- Datacenter --

    #[test]
    fn test_datacenter_no_country() {
        let product = ProductConfig::Datacenter(DatacenterConfig { countries: vec![] });
        let u = build_username("exampleuser", &product, &no_params());
        assert_eq!(u, "exampleuser_pool-dc");
    }

    #[test]
    fn test_datacenter_with_country() {
        let product = ProductConfig::Datacenter(DatacenterConfig { countries: vec![Country::DE] });
        let u = build_username("exampleuser", &product, &no_params());
        assert_eq!(u, "exampleuser_pool-dc_country-de");
    }

    #[test]
    fn test_datacenter_multi_country() {
        let product = ProductConfig::Datacenter(DatacenterConfig {
            countries: vec![Country::DE, Country::FR],
        });
        for _ in 0..20 {
            let u = build_username("exampleuser", &product, &no_params());
            assert!(u.contains("_country-de") || u.contains("_country-fr"));
        }
    }

    // -- rotate_session_id --

    #[test]
    fn test_rotate_changes_only_session() {
        let original = "exampleuser_pool-custom_type-high_country-US_session-aabbccddee112233_sesstime-10";
        let rotated = rotate_session_id(original);
        assert!(rotated.starts_with("exampleuser_pool-custom_type-high_country-US_session-"));
        assert!(rotated.ends_with("_sesstime-10"));
        let old = original.split('_').find(|s| s.starts_with("session-")).unwrap();
        let new = rotated.split('_').find(|s| s.starts_with("session-")).unwrap();
        assert_ne!(old, new);
    }

    #[test]
    fn test_rotate_no_session_unchanged() {
        let u = "exampleuser_pool-dc_country-de";
        assert_eq!(rotate_session_id(u), u);
    }

    // -- session ID properties --

    #[test]
    fn test_session_ids_unique() {
        let product = residential(ResidentialQuality::High, vec![], None);
        let u1 = build_username("exampleuser", &product, &no_params());
        let u2 = build_username("exampleuser", &product, &no_params());
        assert_ne!(u1, u2);
    }

    #[test]
    fn test_session_id_16_hex_chars() {
        let product = residential(ResidentialQuality::High, vec![], None);
        let u = build_username("exampleuser", &product, &no_params());
        let part = u.split('_').find(|s| s.starts_with("session-")).unwrap();
        let hex = part.strip_prefix("session-").unwrap();
        assert_eq!(hex.len(), 16);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
