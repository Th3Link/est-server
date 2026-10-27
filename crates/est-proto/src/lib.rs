//! The EST (RFC 7030) wire format as the `est-server` speaks it.
//!
//! - [`wire`]: base64 transfer encoding of request and response bodies
//!   (RFC 7030 3.2.4, RFC 8951) and PEM helpers.
//! - [`csr`]: parsing and checking PKCS#10 requests.
//! - [`cms`]: certs-only CMS `SignedData` (the "degenerate PKCS#7") that
//!   carries certificates back to the client.
//!
//! Nothing here does I/O or holds keys; policy and signing live in the
//! server crate.

pub mod cms;
pub mod csr;
mod error;
pub mod wire;

pub use error::{Error, Result};

/// `Content-Type` of a `simpleenroll` / `simplereenroll` request.
pub const CONTENT_TYPE_PKCS10: &str = "application/pkcs10";
/// `Content-Type` of an enrollment answer and of `/cacerts`.
pub const CONTENT_TYPE_CERTS_ONLY: &str = "application/pkcs7-mime; smime-type=certs-only";
/// Path prefix of the EST endpoints (RFC 7030 3.2.2).
pub const WELL_KNOWN_PREFIX: &str = "/.well-known/est";
