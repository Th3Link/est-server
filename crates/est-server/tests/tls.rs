//! What the server offers on the wire, independent of the signer.

mod common;

use anyhow::Result;
use common::est::{Est, Ip};
use common::setup::{Backend, Setup};
use function_name::named;
use rustls::crypto::ring::cipher_suite as cs;

#[named]
#[tokio::test]
async fn only_aes_gcm_suites() -> Result<()> {
    let mut setup = Setup::new(Backend::LocalCa, function_path!()).await;
    let est = Est::new(&setup);

    for suite in [
        cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        cs::TLS13_AES_128_GCM_SHA256,
        cs::TLS13_AES_256_GCM_SHA384,
    ] {
        let resp = est.suites(vec![suite]).cacerts().await;
        assert!(resp.is_ok(), "{suite:?} must work: {resp:?}");
    }
    for suite in [
        cs::TLS13_CHACHA20_POLY1305_SHA256,
        cs::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    ] {
        let resp = est.suites(vec![suite]).cacerts().await;
        assert!(resp.is_err(), "{suite:?} must not be offered");
    }

    setup.teardown().await;
    Ok(())
}

#[named]
#[tokio::test]
async fn dual_stack_and_health() -> Result<()> {
    let mut setup = Setup::new(Backend::LocalCa, function_path!()).await;
    let est = Est::new(&setup);

    assert_eq!(
        est.over(Ip::V4).cacerts().await?,
        est.over(Ip::V6).cacerts().await?
    );
    for host in ["127.0.0.1", "[::1]"] {
        for path in ["healthz", "readyz"] {
            let url = format!("http://{host}:{}/{path}", setup.health_port);
            assert_eq!(reqwest::get(&url).await?.status(), 200, "{url}");
        }
    }

    setup.teardown().await;
    Ok(())
}

#[named]
#[tokio::test]
async fn stops_on_teardown() -> Result<()> {
    let mut setup = Setup::new(Backend::LocalCa, function_path!()).await;
    let est = Est::new(&setup);
    est.cacerts().await?;

    setup.teardown().await;
    assert!(est.cacerts().await.is_err(), "listener closed");
    Ok(())
}
