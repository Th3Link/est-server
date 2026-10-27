//! DNS names: validation and allowlist patterns.

/// Whether `name` is a host name the server issues for: dot-separated
/// labels of letters, digits and hyphens (no leading or trailing hyphen),
/// each 1–63 characters, 253 characters in all. A single label (a bare
/// host name) is allowed; a wildcard label is not.
pub fn is_valid_dns_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// An allowlist pattern. `*.example.com` matches exactly one label in
/// front of `example.com`, `**.example.com` one or more, anything else
/// only itself. Matching ignores case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamePattern {
    Exact(String),
    OneLabel(String),
    AnyDepth(String),
}

impl NamePattern {
    pub fn parse(pattern: &str) -> Result<Self, String> {
        let p = pattern.trim().to_ascii_lowercase();
        let (ctor, base): (fn(String) -> Self, &str) = if let Some(base) = p.strip_prefix("**.") {
            (NamePattern::AnyDepth, base)
        } else if let Some(base) = p.strip_prefix("*.") {
            (NamePattern::OneLabel, base)
        } else {
            (NamePattern::Exact, p.as_str())
        };
        if !is_valid_dns_name(base) {
            return Err(format!("invalid name pattern {pattern:?}"));
        }
        Ok(ctor(base.to_string()))
    }

    pub fn matches(&self, name: &str) -> bool {
        let name = name.to_ascii_lowercase();
        match self {
            NamePattern::Exact(n) => name == *n,
            NamePattern::OneLabel(base) | NamePattern::AnyDepth(base) => {
                let Some(prefix) = name
                    .strip_suffix(base.as_str())
                    .and_then(|p| p.strip_suffix('.'))
                else {
                    return false;
                };
                !prefix.is_empty()
                    && (matches!(self, NamePattern::AnyDepth(_)) || !prefix.contains('.'))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_host_names() {
        assert!(is_valid_dns_name("gw1.home.example.com"));
        assert!(is_valid_dns_name("gateway"));
        assert!(!is_valid_dns_name("*.example.com"));
        assert!(!is_valid_dns_name("-a.example.com"));
        assert!(!is_valid_dns_name("a..example.com"));
        assert!(!is_valid_dns_name(&"a".repeat(64)));
        assert!(!is_valid_dns_name("a_b.example.com"));
    }

    #[test]
    fn patterns() {
        let one = NamePattern::parse("*.Home.example.com").unwrap();
        assert!(one.matches("gw1.home.example.com"));
        assert!(!one.matches("home.example.com"));
        assert!(!one.matches("a.gw1.home.example.com"));
        assert!(!one.matches("gw1.xhome.example.com"));

        let deep = NamePattern::parse("**.home.example.com").unwrap();
        assert!(deep.matches("a.gw1.home.example.com"));
        assert!(!deep.matches("home.example.com"));

        let exact = NamePattern::parse("est.example.com").unwrap();
        assert!(exact.matches("EST.example.com"));
        assert!(!exact.matches("x.est.example.com"));

        assert!(NamePattern::parse("*.*.example.com").is_err());
    }
}
