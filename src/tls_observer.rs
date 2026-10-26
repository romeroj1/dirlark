//! Captures peer certificates while delegating every trust decision to rustls WebPKI.
use rustls::{
    DigitallySignedStruct, Error, RootCertStore, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, Default)]
pub struct Capture {
    pub chain: Vec<Vec<u8>>,
    pub failure: Option<&'static str>,
    pub protocol: Option<&'static str>,
    pub endpoint_host: String,
    pub trust_source: String,
}
pub type Slot = Arc<Mutex<Capture>>;

#[derive(Debug)]
struct ObservingVerifier {
    delegate: Arc<WebPkiServerVerifier>,
    slot: Slot,
}
fn captured_chain(end: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>]) -> Vec<Vec<u8>> {
    if end.as_ref().len() > 64 * 1024 {
        return Vec::new();
    }
    let mut chain = Vec::new();
    chain.push(end.as_ref().to_vec());
    for cert in intermediates.iter().take(9) {
        if cert.as_ref().len() > 64 * 1024 {
            break;
        }
        chain.push(cert.as_ref().to_vec());
    }
    chain
}
impl ServerCertVerifier for ObservingVerifier {
    fn verify_server_cert(
        &self,
        end: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // Record only bounded DER bytes. The delegate remains the sole source of trust decisions.
        if let Ok(mut state) = self.slot.lock() {
            state.chain = captured_chain(end, intermediates);
            state.failure = None;
            state.protocol = None;
        }
        let result = self
            .delegate
            .verify_server_cert(end, intermediates, name, ocsp, now);
        if let Ok(mut state) = self.slot.lock() {
            state.failure = result.as_ref().err().map(failure_reason);
        }
        result
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        if let Ok(mut state) = self.slot.lock() {
            state.protocol = Some("TLS 1.2");
        }
        let result = self.delegate.verify_tls12_signature(message, cert, dss);
        if let Err(error) = &result
            && let Ok(mut state) = self.slot.lock()
        {
            state.failure = Some(failure_reason(error));
        }
        result
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        if let Ok(mut state) = self.slot.lock() {
            state.protocol = Some("TLS 1.3");
        }
        let result = self.delegate.verify_tls13_signature(message, cert, dss);
        if let Err(error) = &result
            && let Ok(mut state) = self.slot.lock()
        {
            state.failure = Some(failure_reason(error));
        }
        result
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.delegate.supported_verify_schemes()
    }
    fn requires_raw_public_keys(&self) -> bool {
        self.delegate.requires_raw_public_keys()
    }
}

fn failure_reason(error: &Error) -> &'static str {
    match error {
        Error::InvalidCertificate(error) => match error {
            rustls::CertificateError::UnknownIssuer => "Untrusted issuer",
            rustls::CertificateError::NotValidForName
            | rustls::CertificateError::NotValidForNameContext { .. } => "Hostname mismatch",
            rustls::CertificateError::Expired | rustls::CertificateError::ExpiredContext { .. } => {
                "Expired"
            }
            rustls::CertificateError::NotValidYet
            | rustls::CertificateError::NotValidYetContext { .. } => "Not yet valid",
            _ => "Other verification failure",
        },
        _ => "Other verification failure",
    }
}

pub fn verifier(
    roots: RootCertStore,
    slot: Slot,
) -> Result<Arc<dyn ServerCertVerifier>, &'static str> {
    let delegate = WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .map_err(|_| "TLS verifier setup failed")?;
    Ok(Arc::new(ObservingVerifier { delegate, slot }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn captured_chain_caps_certificate_count_and_der_size() {
        let end = CertificateDer::from(vec![0x30, 0]);
        let intermediates = (0..12)
            .map(|n| CertificateDer::from(vec![n as u8; if n == 4 { 64 * 1024 + 1 } else { 2 }]))
            .collect::<Vec<_>>();
        let chain = captured_chain(&end, &intermediates);
        assert_eq!(chain.len(), 5);
        assert!(chain.iter().all(|der| der.len() <= 64 * 1024));
        let oversized_leaf = CertificateDer::from(vec![0; 64 * 1024 + 1]);
        assert!(captured_chain(&oversized_leaf, &intermediates).is_empty());
    }
    #[test]
    fn fixed_reason_uses_typed_rustls_error_not_presented_name_text() {
        use rustls::CertificateError;
        assert_eq!(
            failure_reason(&Error::InvalidCertificate(CertificateError::UnknownIssuer)),
            "Untrusted issuer"
        );
        let expected = ServerName::try_from("localhost").unwrap();
        let hostile_name = Error::InvalidCertificate(CertificateError::NotValidForNameContext {
            expected,
            presented: vec!["unknownissuer.example".into()],
        });
        assert_eq!(failure_reason(&hostile_name), "Hostname mismatch");
        assert_eq!(
            failure_reason(&Error::InvalidCertificate(CertificateError::Expired)),
            "Expired"
        );
        assert_eq!(
            failure_reason(&Error::InvalidCertificate(CertificateError::NotValidYet)),
            "Not yet valid"
        );
        assert_eq!(
            failure_reason(&Error::General("unknownissuer.example".into())),
            "Other verification failure"
        );
    }
}
