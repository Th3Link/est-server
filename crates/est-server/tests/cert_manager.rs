//! What only the cert-manager backend does: the `CertificateRequest`s it
//! leaves in the cluster, and its guard against cert-manager's built-in
//! approver. Needs a cluster (`EST_E2E_KUBECONFIG`, see
//! scripts/e2e-cluster.sh); run with `cargo test -- --ignored`.

mod common;

use std::time::Duration;

use anyhow::Result;
use common::est::{Answer, Auth, Device, Est, Ip};
use common::setup::{Backend, Setup};
use function_name::named;
use reqwest::StatusCode;

#[named]
#[tokio::test]
#[ignore = "needs a cluster with cert-manager: EST_E2E_KUBECONFIG"]
async fn requests_carry_who_asked_and_why() -> Result<()> {
    let mut setup = Setup::new(Backend::CertManager, function_path!()).await;
    let cluster = setup.cluster.as_ref().unwrap();
    let est = Est::new(&setup);

    let mut auto = Device::new("a.auto.test");
    auto.install(est.over(Ip::V6).enroll(&auto, Auth::None).await?.issued());
    let r = cluster.request_for(&["a.auto.test"]).await?;
    assert_eq!(r.operation, "simpleenroll");
    assert!(r.client.starts_with("[::1]:"), "{}", r.client);
    assert!(
        r.conditions
            .contains(&("Approved".into(), "est-server".into()))
    );
    assert!(r.conditions.iter().any(|(t, _)| t == "Ready"));

    // The renewal finds the finished request for the same key and names
    // and answers from it, within the reuse window.
    auto.install(est.reenroll(&auto).await?.issued());
    assert_eq!(cluster.requests().await?.len(), 1);

    // A request that waits is left unapproved for the administrator.
    let gw = Device::new("gw1.home.test");
    assert_eq!(est.enroll(&gw, Auth::None).await?, Answer::Pending(120));
    let r = cluster.request_for(&["gw1.home.test"]).await?;
    assert!(r.conditions.iter().all(|(t, _)| t != "Approved"));

    setup.teardown().await;
    Ok(())
}

/// cert-manager's built-in approver approves everything. If it is left
/// on, a request that needs approval must not get a certificate.
#[named]
#[tokio::test]
#[ignore = "needs a cluster with cert-manager: EST_E2E_KUBECONFIG"]
async fn default_approver_does_not_count() -> Result<()> {
    let mut setup = Setup::new(Backend::CertManager, function_path!()).await;
    let cluster = setup.cluster.as_ref().unwrap();
    let est = Est::new(&setup);
    let gw = Device::new("gw1.home.test");

    assert_eq!(est.enroll(&gw, Auth::None).await?, Answer::Pending(120));
    let r = cluster.request_for(&["gw1.home.test"]).await?;
    cluster
        .set_condition(&r.name, "Approved", "cert-manager.io")
        .await?;
    assert_eq!(
        est.enroll_until_decided(&gw, Duration::from_secs(30))
            .await?,
        Answer::Refused(StatusCode::FORBIDDEN)
    );
    assert!(setup.issued_log().is_empty());

    setup.teardown().await;
    Ok(())
}

/// Servers for different tests share the cluster but not their requests.
#[named]
#[tokio::test]
#[ignore = "needs a cluster with cert-manager: EST_E2E_KUBECONFIG"]
async fn parallel_servers_are_isolated() -> Result<()> {
    let mut one = Setup::new(Backend::CertManager, function_path!()).await;
    let mut two = Setup::new(Backend::CertManager, function_path!()).await;
    assert_ne!(one.est_port, two.est_port);

    let gw = Device::new("gw1.home.test");
    assert_eq!(
        Est::new(&one).enroll(&gw, Auth::None).await?,
        Answer::Pending(120)
    );
    assert_eq!(one.waiting().await?.len(), 1);
    assert!(two.waiting().await?.is_empty());

    one.teardown().await;
    two.teardown().await;
    Ok(())
}
