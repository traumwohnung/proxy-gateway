/// A parsed upstream proxy entry with optional credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceProxy {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}
