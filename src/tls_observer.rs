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
}
pub type Slot = Arc<Mutex<Capture>>;

#[derive(Debug)]
struct ObservingVerifier {
    delegate: Arc<WebPkiServerVerifier>,
    slot: Slot,
}
fn captured_chain(end: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>]) -> Vec<Vec<u8>> {
    let mut chain = Vec::new();
    if end.as_ref().len() <= 64 * 1024 {
        chain.push(end.as_ref().to_vec());
    }
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
        self.delegate.verify_tls12_signature(message, cert, dss)
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
        self.delegate.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.delegate.supported_verify_schemes()
    }
    fn requires_raw_public_keys(&self) -> bool {
        self.delegate.requires_raw_public_keys()
    }
}

fn failure_reason(error: &Error) -> &'static str {
    let text = format!("{error:?}").to_ascii_lowercase();
    if text.contains("unknownissuer") || text.contains("unknown issuer") {
        "Untrusted issuer"
    } else if text.contains("notvalidforname") || text.contains("not valid for") {
        "Hostname mismatch"
    } else if text.contains("expired") {
        "Expired"
    } else if text.contains("notvalidyet") || text.contains("not valid yet") {
        "Not yet valid"
    } else {
        "Other verification failure"
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
    }
}
