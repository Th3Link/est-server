//! Certs-only CMS `SignedData` (RFC 5652 5.1, "degenerate PKCS#7"): no
//! content, no signers, the certificates in the `certificates` set. EST
//! answers `simpleenroll`, `simplereenroll` and `cacerts` with it.
//!
//! Derived from est-ca 0.2.0 by Patrick Moore (Apache-2.0 OR MIT), see
//! NOTICE.

use ::cms::cert::CertificateChoices;
use ::cms::content_info::{CmsVersion, ContentInfo};
use ::cms::signed_data::{CertificateSet, EncapsulatedContentInfo, SignedData, SignerInfos};
use const_oid::db::rfc5911::{ID_DATA, ID_SIGNED_DATA};
use der::asn1::SetOfVec;
use der::{Decode, Encode};
use x509_cert::Certificate;

use crate::error::{Error, Result};

/// Wrap DER certificates in a certs-only `SignedData`. The order of a
/// DER `SET OF` is fixed by the encoding, not by `certs`; clients build
/// the chain by issuer and subject.
pub fn encode_certs_only(certs_der: &[Vec<u8>]) -> Result<Vec<u8>> {
    if certs_der.is_empty() {
        return Err(Error::Cms("no certificates to wrap".into()));
    }
    let mut choices = Vec::with_capacity(certs_der.len());
    for bytes in certs_der {
        let cert = Certificate::from_der(bytes)
            .map_err(|e| Error::Cms(format!("parse certificate: {e}")))?;
        choices.push(CertificateChoices::Certificate(cert));
    }
    let set =
        SetOfVec::try_from(choices).map_err(|e| Error::Cms(format!("certificate set: {e}")))?;

    let signed = SignedData {
        version: CmsVersion::V1,
        digest_algorithms: Default::default(),
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: ID_DATA,
            econtent: None,
        },
        certificates: Some(CertificateSet(set)),
        crls: None,
        signer_infos: SignerInfos(Default::default()),
    };
    let content = der::Any::encode_from(&signed)
        .map_err(|e| Error::Cms(format!("encode SignedData: {e}")))?;
    ContentInfo {
        content_type: ID_SIGNED_DATA,
        content,
    }
    .to_der()
    .map_err(|e| Error::Cms(format!("encode ContentInfo: {e}")))
}

/// All certificates (DER) of a certs-only `SignedData`.
pub fn decode_certs_only(body_der: &[u8]) -> Result<Vec<Vec<u8>>> {
    let info = ContentInfo::from_der(body_der)
        .map_err(|e| Error::Cms(format!("parse ContentInfo: {e}")))?;
    if info.content_type != ID_SIGNED_DATA {
        return Err(Error::Cms(format!(
            "expected SignedData, got {}",
            info.content_type
        )));
    }
    let signed: SignedData = info
        .content
        .decode_as()
        .map_err(|e| Error::Cms(format!("decode SignedData: {e}")))?;
    let set = signed
        .certificates
        .ok_or_else(|| Error::Cms("SignedData has no certificates".into()))?;
    set.0
        .iter()
        .map(|choice| match choice {
            CertificateChoices::Certificate(c) => c
                .to_der()
                .map_err(|e| Error::Cms(format!("re-encode: {e}"))),
            _ => Err(Error::Cms(
                "certificate choice is not an X.509 certificate".into(),
            )),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn self_signed(name: &str) -> Vec<u8> {
        let params = rcgen::CertificateParams::new(vec![name.into()]).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().to_vec()
    }

    #[test]
    fn roundtrip_keeps_every_certificate() {
        let a = self_signed("a.test");
        let b = self_signed("b.test");
        let wrapped = encode_certs_only(&[a.clone(), b.clone()]).unwrap();
        let mut back = decode_certs_only(&wrapped).unwrap();
        back.sort();
        let mut want = vec![a, b];
        want.sort();
        assert_eq!(back, want);
    }

    #[test]
    fn empty_list_is_refused() {
        assert!(encode_certs_only(&[]).is_err());
    }
}
