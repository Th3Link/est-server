//! Enrollment end to end, once per backend: the same scenario against a
//! local CA and against a real cert-manager. The cert-manager variants
//! need a cluster (`EST_E2E_KUBECONFIG`, see scripts/e2e-cluster.sh) and
//! are `#[ignore]`d; run them with `cargo test -- --ignored`.

mod common;

use std::time::Duration;

use anyhow::Result;
use common::est::{Answer, Auth, Credential, Device, Est, Ip};
use common::setup::{Backend, Setup};
use reqwest::StatusCode;

/// Time a cert-manager CA issuer gets to sign an approved request.
const ISSUE_TIMEOUT: Duration = Duration::from_secs(30);

for_each_backend!(
    approval_then_renewal,
    denied_request,
    allowlist_identity_and_strict_label,
    protocol_errors_and_cacerts,
);

/// The gateway's life: no identity, so the first enrollment waits for an
/// administrator; then renewals with the issued certificate and the same
/// key, over the other address family.
async fn approval_then_renewal(backend: Backend, test_name: &'static str) -> Result<()> {
    let mut setup = Setup::new(backend, test_name).await;
    let est = Est::new(&setup);
    let mut gw = Device::new("gw1.home.test");

    assert_eq!(est.enroll(&gw, Auth::None).await?, Answer::Pending(120));
    let waiting = setup.waiting().await?;
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].names, vec!["gw1.home.test"]);
    assert!(
        waiting[0].client.starts_with("127.0.0.1:"),
        "IPv4-mapped address normalised: {}",
        waiting[0].client
    );

    // Asking again while it waits doesn't make a second request.
    assert_eq!(est.enroll(&gw, Auth::None).await?, Answer::Pending(120));
    assert_eq!(setup.waiting().await?.len(), 1);

    setup.approve(&["gw1.home.test"]).await?;
    let chain = est.enroll_until_decided(&gw, ISSUE_TIMEOUT).await?.issued();
    assert_eq!(
        chain.len(),
        1,
        "the self-signed root stays out of the answer"
    );
    let first = gw.install(chain);

    let renewed = est.over(Ip::V6).reenroll(&gw).await?.issued();
    let second = gw.install(renewed);
    // And once more with the renewed certificate, back over IPv4.
    let third = gw.install(est.reenroll(&gw).await?.issued());
    match backend {
        Backend::LocalCa => assert!(first != second && second != third),
        // Same key and names within `reuse_window`: cert-manager's
        // finished request answers again instead of a new one.
        Backend::CertManager => assert!(first == second && second == third),
    }

    // Renewal for another name, or without a certificate, is refused.
    let resp = est
        .post(
            "simplereenroll",
            "application/pkcs10",
            gw.csr_for("gw2.home.test"),
            Auth::Current(&gw),
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let anonymous = Device {
        chain: vec![],
        ..Device::new("gw1.home.test")
    };
    assert_eq!(
        est.reenroll(&anonymous).await?,
        Answer::Refused(StatusCode::UNAUTHORIZED)
    );

    let log = setup.issued_log();
    assert_eq!(log.len(), 3);
    assert_eq!(log[1]["reason"], "renewal");

    setup.teardown().await;
    Ok(())
}

async fn denied_request(backend: Backend, test_name: &'static str) -> Result<()> {
    let mut setup = Setup::new(backend, test_name).await;
    let est = Est::new(&setup);
    let gw = Device::new("intruder.home.test");

    assert_eq!(est.enroll(&gw, Auth::None).await?, Answer::Pending(120));
    setup.deny(&["intruder.home.test"]).await?;
    assert_eq!(
        est.enroll_until_decided(&gw, ISSUE_TIMEOUT).await?,
        Answer::Refused(StatusCode::FORBIDDEN)
    );
    assert!(setup.issued_log().is_empty());

    setup.teardown().await;
    Ok(())
}

async fn allowlist_identity_and_strict_label(
    backend: Backend,
    test_name: &'static str,
) -> Result<()> {
    let mut setup = Setup::new(backend, test_name).await;
    let est = Est::new(&setup);

    // Allowlisted name: issued at once, over IPv6 this time.
    let mut auto = Device::new("x.auto.test");
    auto.install(est.over(Ip::V6).enroll(&auto, Auth::None).await?.issued());

    // Device identity for the requested name: issued at once.
    let mut gw = Device::new("gw9.home.test");
    let identity = Credential::issued_by(&setup.identity, &["gw9.home.test"]);
    gw.install(est.enroll(&gw, Auth::Custom(&identity)).await?.issued());

    // An identity for another name doesn't count.
    let other = Device::new("gw10.home.test");
    assert_eq!(
        est.enroll(&other, Auth::Custom(&identity)).await?,
        Answer::Pending(120)
    );

    // A certificate from an unknown CA doesn't break the handshake; the
    // request is treated as anonymous and waits.
    let stranger = Credential::issued_by(&setup.stranger, &["gw11.home.test"]);
    let gw11 = Device::new("gw11.home.test");
    assert_eq!(
        est.enroll(&gw11, Auth::Custom(&stranger)).await?,
        Answer::Pending(120)
    );

    // A label without allowlist and approval refuses.
    assert_eq!(
        est.label("strict")
            .enroll(&Device::new("y.auto.test"), Auth::None)
            .await?,
        Answer::Refused(StatusCode::FORBIDDEN)
    );

    let reasons: Vec<_> = setup
        .issued_log()
        .iter()
        .map(|l| l["reason"].clone())
        .collect();
    assert_eq!(reasons, ["allowlist", "identity"]);

    setup.teardown().await;
    Ok(())
}

async fn protocol_errors_and_cacerts(backend: Backend, test_name: &'static str) -> Result<()> {
    let mut setup = Setup::new(backend, test_name).await;
    let est = Est::new(&setup);

    let resp = est
        .post("simpleenroll", "text/plain", "x".into(), Auth::None)
        .await?;
    assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let resp = est
        .post(
            "simpleenroll",
            "application/pkcs10",
            "!!".into(),
            Auth::None,
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        est.get("csrattrs", Auth::None).await?.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        est.label("nope").get("cacerts", Auth::None).await?.status(),
        StatusCode::NOT_FOUND
    );

    assert_eq!(est.cacerts().await?, vec![setup.ca_der.clone()]);
    assert_eq!(
        est.label("strict").cacerts().await?,
        vec![setup.ca_der.clone()]
    );

    setup.teardown().await;
    Ok(())
}
