//! Registered clients end to end (`registered = "required"` on the label
//! `registered`), once per backend: from `clients.d` with a local CA, from
//! `EstClient` objects with cert-manager. The cert-manager variants need a
//! cluster (`EST_E2E_KUBECONFIG`) with the CRD, see scripts/e2e-cluster.sh.

mod common;

use std::time::Duration;

use anyhow::{Result, bail};
use common::est::{Answer, Auth, Credential, Device, Est, answer};
use common::setup::{Backend, Setup};
use reqwest::StatusCode;

/// Time a cert-manager CA issuer gets to sign.
const ISSUE_TIMEOUT: Duration = Duration::from_secs(30);

for_each_backend!(
    registered_key_enrolls_and_renews,
    unregistered_keys_and_names_are_refused,
    key_change_and_p384,
    registration_takes_effect_without_restart,
);

/// Enroll on the `registered` label until the answer isn't `202` (the
/// cert-manager issuer may take longer than `wait`).
async fn enroll(est: &Est, device: &Device) -> Result<Answer> {
    est.enroll_until_decided(device, ISSUE_TIMEOUT).await
}

/// A registered gateway gets its certificate without approval and renews
/// with it. Without `cacerts`, cert-manager's CA is learned from the
/// first issue.
async fn registered_key_enrolls_and_renews(
    backend: Backend,
    test_name: &'static str,
) -> Result<()> {
    let mut setup = Setup::new(backend, test_name).await;
    let est = Est::new(&setup).label("registered");
    let mut gw = Device::new("gw1.example.test");

    if backend == Backend::CertManager {
        let resp = est.get("cacerts", Auth::None).await?;
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "nothing learned yet"
        );
    }

    setup
        .register("gw1", &["gw1.example.test"], &[gw.pin()])
        .await?;
    let first = gw.install(enroll(&est, &gw).await?.issued());
    let second = gw.install(est.reenroll(&gw).await?.issued());
    if backend == Backend::LocalCa {
        assert_ne!(first, second);
    }

    // /cacerts: the CA that signed, configured or learned.
    assert_eq!(est.cacerts().await?, vec![setup.ca_der.clone()]);

    let log = setup.issued_log();
    let reasons: Vec<_> = log.iter().map(|l| l["reason"].clone()).collect();
    assert_eq!(reasons, ["registered", "renewal"]);
    assert!(log[0]["client_id"].as_str().unwrap().ends_with("gw1"));

    if let Some(cluster) = &setup.cluster {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            match cluster.last_issued("gw1").await? {
                Some(last) if last.operation == "simplereenroll" => {
                    assert_eq!(last.label, "registered");
                    break;
                }
                _ if tokio::time::Instant::now() > deadline => {
                    bail!("status.lastIssued not recorded")
                }
                _ => tokio::time::sleep(Duration::from_millis(200)).await,
            }
        }
    }

    setup.teardown().await;
    Ok(())
}

async fn unregistered_keys_and_names_are_refused(
    backend: Backend,
    test_name: &'static str,
) -> Result<()> {
    let mut setup = Setup::new(backend, test_name).await;
    let est = Est::new(&setup).label("registered");
    let mut gw = Device::new("gw1.example.test");
    setup
        .register("gw1", &["gw1.example.test"], &[gw.pin()])
        .await?;

    // Another key for the registered name.
    let imposter = Device::new("gw1.example.test");
    assert_eq!(
        est.enroll(&imposter, Auth::None).await?,
        Answer::Refused(StatusCode::FORBIDDEN)
    );
    // The registered key for another name.
    let resp = est
        .post(
            "simpleenroll",
            "application/pkcs10",
            gw.csr_for("gw2.example.test"),
            Auth::None,
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // A valid certificate for the name from some CA, as anyone can get
    // from a public CA, with an unregistered key: no renewal.
    let foreign = Device::from_credential(
        "gw1.example.test",
        Credential::issued_by(&setup.stranger, &["gw1.example.test"]),
    );
    assert_eq!(
        est.reenroll(&foreign).await?,
        Answer::Refused(StatusCode::FORBIDDEN)
    );
    // Nor with the registered key in the CSR: the certificate's key must
    // be registered too.
    gw.install(enroll(&est, &gw).await?.issued());
    let resp = est
        .post(
            "simplereenroll",
            "application/pkcs10",
            gw.csr(),
            Auth::Current(&foreign),
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Without a client certificate.
    let anonymous = Device {
        chain: vec![],
        ..Device::new("gw1.example.test")
    };
    assert_eq!(
        est.reenroll(&anonymous).await?,
        Answer::Refused(StatusCode::UNAUTHORIZED)
    );

    assert_eq!(setup.issued_log().len(), 1);
    setup.teardown().await;
    Ok(())
}

/// Two registered keys: renew with the old one's certificate, asking for
/// the new (P-384) key.
async fn key_change_and_p384(backend: Backend, test_name: &'static str) -> Result<()> {
    let mut setup = Setup::new(backend, test_name).await;
    let est = Est::new(&setup).label("registered");
    let mut old = Device::new("gw3.example.test");
    let mut new = Device::with_alg("gw3.example.test", &rcgen::PKCS_ECDSA_P384_SHA384);
    setup
        .register("gw3", &["gw3.example.test"], &[old.pin(), new.pin()])
        .await?;

    old.install(enroll(&est, &old).await?.issued());
    let resp = est
        .post(
            "simplereenroll",
            "application/pkcs10",
            new.csr(),
            Auth::Current(&old),
        )
        .await?;
    new.install(answer(resp).await?.issued());
    // And renew with the P-384 certificate.
    new.install(est.reenroll(&new).await?.issued());

    setup.teardown().await;
    Ok(())
}

async fn registration_takes_effect_without_restart(
    backend: Backend,
    test_name: &'static str,
) -> Result<()> {
    let mut setup = Setup::new(backend, test_name).await;
    let est = Est::new(&setup).label("registered");
    let mut gw = Device::new("gw4.example.test");

    assert_eq!(
        est.enroll(&gw, Auth::None).await?,
        Answer::Refused(StatusCode::FORBIDDEN)
    );
    setup
        .register("gw4", &["gw4.example.test"], &[gw.pin()])
        .await?;
    gw.install(enroll(&est, &gw).await?.issued());

    setup.teardown().await;
    Ok(())
}
