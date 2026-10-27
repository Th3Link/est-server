use thiserror::Error;

/// Errors from decoding or encoding EST messages.
#[derive(Debug, Error)]
pub enum Error {
    /// The body is neither valid base64 nor DER.
    #[error("body is not base64: {0}")]
    Base64(String),
    /// The PKCS#10 request doesn't parse.
    #[error("malformed PKCS#10 request: {0}")]
    MalformedCsr(String),
    /// The request's signature doesn't verify with its own key.
    #[error("PKCS#10 signature does not verify: {0}")]
    CsrSignature(String),
    /// The request asks for something the server never issues.
    #[error("unsupported PKCS#10 request: {0}")]
    UnsupportedCsr(String),
    /// Building or reading a certs-only CMS structure failed.
    #[error("cms: {0}")]
    Cms(String),
}

/// `Result` with this crate's [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;
