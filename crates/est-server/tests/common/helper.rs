use std::path::Path;

/// `module::function` of the calling test; needs `#[named]` on it.
#[macro_export]
macro_rules! function_path {
    () => {
        concat!(module_path!(), "::", function_name!())
    };
}

/// Lowercase letters and digits, usable in DNS and Kubernetes names.
pub fn random_string(len: usize) -> String {
    use ring::rand::SecureRandom;
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut bytes = vec![0u8; len];
    ring::rand::SystemRandom::new().fill(&mut bytes).unwrap();
    bytes
        .iter()
        .map(|b| CHARS[*b as usize % CHARS.len()] as char)
        .collect()
}

/// A port that is free on IPv6 and IPv4 (`[::]` is dual-stack).
pub fn find_free_port() -> std::io::Result<u16> {
    Ok(std::net::TcpListener::bind("[::]:0")?.local_addr()?.port())
}

/// Copy `source` to `target`, replacing each `(from, to)`.
pub fn replace_in_file(
    source: &Path,
    target: &Path,
    replace: &[(&str, &str)],
) -> std::io::Result<()> {
    let mut text = std::fs::read_to_string(source)?;
    for (from, to) in replace {
        text = text.replace(from, to);
    }
    write(target, &text)
}

pub fn write(path: &Path, data: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(path.parent().unwrap())?;
    std::fs::write(path, data)
}
