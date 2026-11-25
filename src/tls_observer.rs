//! Captures peer certificates and delegates chain/signature decisions to rustls WebPKI.
//! Hostname matching is skipped only for an explicit profile opt-in with a dedicated CA bundle.
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
    roots: RootCertStore,
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
    skip_hostname: bool,
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
        // Record only bounded DER bytes. Both paths use WebPKI chain verification; one also checks the name.
        if let Ok(mut state) = self.slot.lock() {
            state.chain = captured_chain(end, intermediates);
            state.failure = None;
            state.protocol = None;
        }
        let result = if self.skip_hostname {
            // This helper does not check revocation/OCSP or hostname. The bypass is therefore
            // paired with a CA-bundle-only trust store; TLS handshake signatures are still delegated.
            let cert = rustls::server::ParsedCertificate::try_from(end)?;
            rustls::client::verify_server_cert_signed_by_trust_anchor(
                &cert,
                &self.roots,
                intermediates,
                now,
                self.supported.all,
            )
            .map(|()| ServerCertVerified::assertion())
        } else {
            self.delegate
                .verify_server_cert(end, intermediates, name, ocsp, now)
        };
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
        Error::InvalidCertificate(error) => {
            match error {
                rustls::CertificateError::UnknownIssuer
                | rustls::CertificateError::BadSignature => "Untrusted issuer",
                rustls::CertificateError::NotValidForName
                | rustls::CertificateError::NotValidForNameContext { .. } => "Hostname mismatch",
                rustls::CertificateError::Expired
                | rustls::CertificateError::ExpiredContext { .. } => "Expired",
                rustls::CertificateError::NotValidYet
                | rustls::CertificateError::NotValidYetContext { .. } => "Not yet valid",
                _ => "Other verification failure",
            }
        }
        _ => "Other verification failure",
    }
}

pub fn verifier(
    roots: RootCertStore,
    slot: Slot,
    skip_hostname: bool,
) -> Result<Arc<dyn ServerCertVerifier>, &'static str> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let delegate =
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots.clone()), provider.clone())
            .build()
            .map_err(|_| "TLS verifier setup failed")?;
    Ok(Arc::new(ObservingVerifier {
        delegate,
        roots,
        supported: provider.signature_verification_algorithms,
        skip_hostname,
        slot,
    }))
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

    #[test]
    fn hostname_bypass_still_requires_a_trusted_valid_certificate_chain() {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
        use rustls::pki_types::CertificateDer;

        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);
        let leaf_params = CertificateParams::new(vec!["directory.example.org".into()]).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();

        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(ca.der().to_vec())).unwrap();
        let skip_verifier =
            verifier(roots, Arc::new(Mutex::new(Capture::default())), true).unwrap();
        let name = ServerName::try_from("replica.example.org").unwrap();
        assert!(
            skip_verifier
                .verify_server_cert(
                    &CertificateDer::from(leaf.der().to_vec()),
                    &[],
                    &name,
                    &[],
                    UnixTime::now()
                )
                .is_ok()
        );

        let mut untrusted = RootCertStore::empty();
        let other_ca = CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .self_signed(&KeyPair::generate().unwrap())
            .unwrap();
        untrusted
            .add(CertificateDer::from(other_ca.der().to_vec()))
            .unwrap();
        let verifier = verifier(untrusted, Arc::new(Mutex::new(Capture::default())), true).unwrap();
        assert!(
            verifier
                .verify_server_cert(
                    &CertificateDer::from(leaf.der().to_vec()),
                    &[],
                    &name,
                    &[],
                    UnixTime::now()
                )
                .is_err()
        );
    }
}
