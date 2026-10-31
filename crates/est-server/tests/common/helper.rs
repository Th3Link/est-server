use std::path::Path;

/// `module::function` of the calling test; needs `#[named]` on it.
/// One test per backend for a scenario `fn(Backend, &'static str)` in
/// the calling module: `<scenario>::local_ca` and
/// `<scenario>::cert_manager`, the latter `#[ignore]`d (it needs a cluster).
#[macro_export]
macro_rules! for_each_backend {
    ($($scenario:ident),* $(,)?) => {$(
        mod $scenario {
            use function_name::named;

            #[named]
            #[tokio::test]
            async fn local_ca() -> anyhow::Result<()> {
                super::$scenario(super::Backend::LocalCa, $crate::function_path!()).await
            }

            #[named]
            #[tokio::test]
            #[ignore = "needs a cluster with cert-manager: EST_E2E_KUBECONFIG"]
            async fn cert_manager() -> anyhow::Result<()> {
                super::$scenario(super::Backend::CertManager, $crate::function_path!()).await
            }
        }
    )*};
}

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
