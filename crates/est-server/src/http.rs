//! The EST endpoints.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Extension, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use est_proto::csr::Csr;
use est_proto::{CONTENT_TYPE_CERTS_ONLY, CONTENT_TYPE_PKCS10, cms, wire};
use rustls::pki_types::CertificateDer;

use crate::app::{App, Label};
use crate::audit::Record;
use crate::names::is_valid_dns_name;
use crate::peer::ConnInfo;
use crate::policy::Decision;
use crate::signer::{Outcome, SignRequest, request_id};

/// Largest request body taken: a CSR is well below 8 KiB.
const MAX_BODY: usize = 64 * 1024;
/// Small clients keep the answer in a fixed buffer (12 KiB with
/// headers for the gateway); warn when an answer gets close.
const WARN_BODY: usize = 11 * 1024;

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .fallback(handle)
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(app)
}

async fn handle(
    State(app): State<Arc<App>>,
    Extension(conn): Extension<Arc<ConnInfo>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some((label, op)) = app.route(uri.path()) else {
        return text(StatusCode::NOT_FOUND, "no EST endpoint here");
    };
    let response = match (op, &method) {
        ("cacerts", &Method::GET) => cacerts(label),
        ("simpleenroll" | "simplereenroll", &Method::POST) => {
            enroll(&app, label, op, &conn, &headers, &body).await
        }
        ("cacerts" | "simpleenroll" | "simplereenroll", _) => {
            text(StatusCode::METHOD_NOT_ALLOWED, "wrong method")
        }
        // csrattrs, serverkeygen, fullcmc: not offered (RFC 7030 4.5.2:
        // 404 when there are no CSR attributes).
        _ => text(StatusCode::NOT_FOUND, "operation not supported"),
    };
    tracing::debug!(client = %conn.remote, %method, path = uri.path(), status = response.status().as_u16());
    response
}

fn cacerts(label: &Label) -> Response {
    match cms::encode_certs_only(&ders(label.signer.ca_certs())) {
        Ok(der) => certs_only(wire::encode_body(&der)),
        Err(e) => text(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn enroll(
    app: &App,
    label: &Label,
    op: &str,
    conn: &ConnInfo,
    headers: &HeaderMap,
    body: &[u8],
) -> Response {
    let renew = op == "simplereenroll";
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .eq_ignore_ascii_case(CONTENT_TYPE_PKCS10)
    {
        return text(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "expected Content-Type: application/pkcs10",
        );
    }
    let csr = match wire::decode_body(body).and_then(|der| Csr::parse(&der)) {
        Ok(csr) => csr,
        Err(e) => return refuse(conn, label, op, StatusCode::BAD_REQUEST, &e.to_string()),
    };
    let names = csr.requested_names();
    if names.is_empty() {
        return refuse(
            conn,
            label,
            op,
            StatusCode::BAD_REQUEST,
            "the request names no host (SAN DNS name or CN)",
        );
    }
    if let Some(bad) = names.iter().find(|n| !is_valid_dns_name(n)) {
        return refuse(
            conn,
            label,
            op,
            StatusCode::BAD_REQUEST,
            &format!("{bad:?} is not a host name this server issues for"),
        );
    }

    let decision = if renew {
        label.policy.reenroll(&names, &conn.chain)
    } else {
        label.policy.enroll(&names, &conn.chain)
    };
    let (approved, reason, peer) = match decision {
        Decision::Approved(reason, peer) => (true, reason.as_str(), peer),
        Decision::NeedsApproval(peer) => (false, "manual", peer),
        Decision::Refused(status, why) => return refuse(conn, label, op, status, &why),
    };
    let client_cert = peer.as_ref().map(|p| p.subject.as_str());
    let req = SignRequest {
        id: request_id(&label.name, &names, &csr.spki_der),
        label: &label.name,
        operation: op,
        csr: &csr,
        names: &names,
        client: conn.remote,
        client_cert,
        retry_after: label.retry_after,
    };
    match label.signer.sign(&req, approved).await {
        Ok(Outcome::Issued(chain)) => {
            let response = match cms::encode_certs_only(&ders(&chain)) {
                Ok(der) => wire::encode_body(&der),
                Err(e) => return text(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
            };
            log_issue(app, label, op, reason, &req, &chain, response.len());
            certs_only(response)
        }
        Ok(Outcome::Pending(after)) => {
            tracing::info!(id = %req.id, label = %label.name, names = ?names, client = %conn.remote, "{op}: waiting for approval");
            let mut r = text(StatusCode::ACCEPTED, "request is waiting for approval");
            r.headers_mut().insert(
                header::RETRY_AFTER,
                HeaderValue::from(after.as_secs().max(1)),
            );
            r
        }
        Ok(Outcome::Denied(why)) => refuse(conn, label, op, StatusCode::FORBIDDEN, &why),
        Err(e) => {
            tracing::error!(label = %label.name, names = ?names, client = %conn.remote, "{op}: {e:#}");
            text(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the certificate could not be issued",
            )
        }
    }
}

fn log_issue(
    app: &App,
    label: &Label,
    op: &str,
    reason: &str,
    req: &SignRequest<'_>,
    chain: &[CertificateDer<'static>],
    body_len: usize,
) {
    let (serial, not_after) = x509_parser::parse_x509_certificate(&chain[0])
        .map(|(_, c)| (c.raw_serial_as_string(), c.validity().not_after.timestamp()))
        .unwrap_or_default();
    tracing::info!(
        label = %label.name, names = ?req.names, client = %req.client, reason, serial = %serial,
        "{op}: certificate issued"
    );
    let chain_len: usize = chain.iter().map(|c| c.len()).sum();
    if body_len > WARN_BODY || chain.len() > 5 || chain_len > 6 * 1024 {
        tracing::warn!(
            label = %label.name, certificates = chain.len(), chain_bytes = chain_len, body_bytes = body_len,
            "answer is larger than small clients take (5 certificates, 6 KiB chain, 12 KiB answer)"
        );
    }
    app.audit.write(&Record {
        time: crate::pending::now(),
        label: &label.name,
        operation: op,
        reason,
        names: req.names,
        serial,
        not_after,
        client: req.client.to_string(),
        client_cert: req.client_cert,
        signer: label.signer.kind(),
    });
}

fn refuse(conn: &ConnInfo, label: &Label, op: &str, status: StatusCode, why: &str) -> Response {
    tracing::info!(client = %conn.remote, label = %label.name, status = status.as_u16(), "{op} refused: {why}");
    text(status, why)
}

fn ders(certs: &[CertificateDer<'static>]) -> Vec<Vec<u8>> {
    certs.iter().map(|c| c.to_vec()).collect()
}

fn certs_only(body: String) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, CONTENT_TYPE_CERTS_ONLY),
            (
                header::HeaderName::from_static("content-transfer-encoding"),
                "base64",
            ),
        ],
        body,
    )
        .into_response()
}

fn text(status: StatusCode, msg: &str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("{msg}\n"),
    )
        .into_response()
}

/// `/healthz` (alive) and `/readyz` (serving) on the plain HTTP port.
pub fn health_router(ready: Arc<std::sync::atomic::AtomicBool>) -> Router {
    use axum::routing::get;
    use std::sync::atomic::Ordering;
    Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .route(
            "/readyz",
            get(move || {
                let ready = ready.load(Ordering::Relaxed);
                async move {
                    if ready {
                        (StatusCode::OK, "ready\n")
                    } else {
                        (StatusCode::SERVICE_UNAVAILABLE, "starting\n")
                    }
                }
            }),
        )
}
