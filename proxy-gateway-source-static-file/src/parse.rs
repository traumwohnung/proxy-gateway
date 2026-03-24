use anyhow::{Context, Result};
use proxy_gateway_core::SourceProxy;
use std::path::Path;

/// Parse a proxies file.  Each line is one of:
///   host:port:username:password
///   host:port
/// Comments with `#` and blank lines are skipped.
pub fn load_proxies(path: &Path) -> Result<Vec<SourceProxy>> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut proxies = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let proxy = parse_proxy_line(line).with_context(|| {
            format!(
                "{}:{}: invalid proxy entry '{}'",
                path.display(),
                i + 1,
                line
            )
        })?;
        proxies.push(proxy);
    }
    Ok(proxies)
}

/// Parse a single proxy line.
/// Supports:
///   host:port:username:password
///   host:port
///   [ipv6]:port:username:password
///   [ipv6]:port
pub(crate) fn parse_proxy_line(s: &str) -> Result<SourceProxy> {
    if s.starts_with('[') {
        let bracket_end = s
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("unclosed bracket in '{s}'"))?;
        let host = s[1..bracket_end].to_string();
        let rest = &s[bracket_end + 1..];
        let rest = rest
            .strip_prefix(':')
            .ok_or_else(|| anyhow::anyhow!("expected ':' after ']' in '{s}'"))?;
        return parse_port_and_creds(&host, rest);
    }

    let parts: Vec<&str> = s.splitn(4, ':').collect();
    match parts.len() {
        2 => {
            let port: u16 = parts[1].parse().context("invalid port")?;
            Ok(SourceProxy {
                host: parts[0].to_string(),
                port,
                username: None,
                password: None,
            })
        }
        4 => {
            let port: u16 = parts[1].parse().context("invalid port")?;
            Ok(SourceProxy {
                host: parts[0].to_string(),
                port,
                username: Some(parts[2].to_string()),
                password: Some(parts[3].to_string()),
            })
        }
        _ => anyhow::bail!("expected host:port or host:port:user:pass, got '{s}'"),
    }
}

fn parse_port_and_creds(host: &str, rest: &str) -> Result<SourceProxy> {
    let parts: Vec<&str> = rest.splitn(3, ':').collect();
    match parts.len() {
        1 => {
            let port: u16 = parts[0].parse().context("invalid port")?;
            Ok(SourceProxy {
                host: host.to_string(),
                port,
                username: None,
                password: None,
            })
        }
        3 => {
            let port: u16 = parts[0].parse().context("invalid port")?;
            Ok(SourceProxy {
                host: host.to_string(),
                port,
                username: Some(parts[1].to_string()),
                password: Some(parts[2].to_string()),
            })
        }
        _ => anyhow::bail!("expected port or port:user:pass after host, got '{rest}'"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_host_port_only() {
        let p = parse_proxy_line("proxy.example.com:8080").unwrap();
        assert_eq!(p.host, "proxy.example.com");
        assert_eq!(p.port, 8080);
        assert!(p.username.is_none());
        assert!(p.password.is_none());
    }

    #[test]
    fn test_parse_host_port_user_pass() {
        let p = parse_proxy_line("198.51.100.1:6658:myuser:mypass123").unwrap();
        assert_eq!(p.host, "198.51.100.1");
        assert_eq!(p.port, 6658);
        assert_eq!(p.username.as_deref(), Some("myuser"));
        assert_eq!(p.password.as_deref(), Some("mypass123"));
    }

    #[test]
    fn test_parse_ipv6() {
        let p = parse_proxy_line("[::1]:3128").unwrap();
        assert_eq!(p.host, "::1");
        assert_eq!(p.port, 3128);
        assert!(p.username.is_none());
    }

    #[test]
    fn test_parse_ipv6_with_creds() {
        let p = parse_proxy_line("[2001:db8::1]:8080:user:pass").unwrap();
        assert_eq!(p.host, "2001:db8::1");
        assert_eq!(p.port, 8080);
        assert_eq!(p.username.as_deref(), Some("user"));
        assert_eq!(p.password.as_deref(), Some("pass"));
    }

    #[test]
    fn test_parse_bad_format() {
        assert!(parse_proxy_line("host:port:only_three").is_err());
        assert!(parse_proxy_line("justhost").is_err());
    }

    #[test]
    fn test_load_proxies_mixed() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "# comment").unwrap();
        writeln!(f, "198.51.100.1:6658:myuser:mypass").unwrap();
        writeln!(f, "").unwrap();
        writeln!(f, "198.51.100.2:7872:myuser:mypass").unwrap();
        writeln!(f, "plain.proxy.com:3128").unwrap();
        f.flush().unwrap();

        let proxies = load_proxies(f.path()).unwrap();
        assert_eq!(proxies.len(), 3);
        assert_eq!(proxies[0].host, "198.51.100.1");
        assert_eq!(proxies[0].port, 6658);
        assert_eq!(proxies[0].username.as_deref(), Some("myuser"));
        assert_eq!(proxies[1].username.as_deref(), Some("myuser"));
        assert_eq!(proxies[2].host, "plain.proxy.com");
        assert!(proxies[2].username.is_none());
    }
}
