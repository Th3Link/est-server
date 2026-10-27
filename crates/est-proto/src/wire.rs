//! Transfer encoding of EST bodies.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::error::{Error, Result};

/// Decode a request body: base64 with any ASCII whitespace (line breaks)
/// in between, as RFC 7030 3.2.4 / RFC 8951 asks. A body that isn't
/// base64 but looks like DER (starts with a SEQUENCE tag) is taken as
/// binary, for clients that skip the transfer encoding.
pub fn decode_body(body: &[u8]) -> Result<Vec<u8>> {
    let compact: Vec<u8> = body
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    match STANDARD.decode(&compact) {
        Ok(der) => Ok(der),
        Err(_) if body.first() == Some(&0x30) => Ok(body.to_vec()),
        Err(e) => Err(Error::Base64(e.to_string())),
    }
}

/// Encode a response body: base64 in lines of 64 characters, each ended
/// by LF (as libest and OpenSSL write it; some decoders refuse CR).
pub fn encode_body(der: &[u8]) -> String {
    wrap64(&STANDARD.encode(der), "\n")
}

/// Encode DER as PEM with the given label (`CERTIFICATE`,
/// `CERTIFICATE REQUEST`, …).
pub fn to_pem(label: &str, der: &[u8]) -> String {
    format!(
        "-----BEGIN {label}-----\n{}-----END {label}-----\n",
        wrap64(&STANDARD.encode(der), "\n")
    )
}

fn wrap64(b64: &str, eol: &str) -> String {
    let mut out = String::with_capacity(b64.len() + b64.len() / 64 * eol.len() + eol.len());
    for chunk in b64.as_bytes().chunks(64) {
        // base64 output is ASCII, so every chunk is valid UTF-8.
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push_str(eol);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_wrapped_base64_and_raw_der() {
        let der = vec![0x30, 0x03, 0x02, 0x01, 0x05];
        let wrapped = encode_body(&der);
        assert_eq!(decode_body(wrapped.as_bytes()).unwrap(), der);
        assert_eq!(decode_body(&der).unwrap(), der);
        assert!(decode_body(b"not base64 !").is_err());
    }

    #[test]
    fn lines_are_64_characters() {
        let body = encode_body(&[0u8; 200]);
        let lines: Vec<&str> = body.lines().collect();
        assert!(lines[..lines.len() - 1].iter().all(|l| l.len() == 64));
        assert!(body.ends_with('\n') && !body.contains('\r'));
    }
}
