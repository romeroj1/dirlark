#[path = "../examples/support/certificates.rs"]
mod fixtures;
use dirlark::certificates::{self, Kind};
const NOW: i64 = 1_800_000_000;
fn field<'a>(cert: &'a certificates::Certificate, key: &str) -> &'a str {
    &cert.fields.iter().find(|(name, _)| name == key).unwrap().1
}
#[test]
fn generated_certificate_fields_match_input_and_fingerprints_match_der() {
    let der = fixtures::sample(false, false);
    let result = certificates::inspect(&der, Kind::Certificate, NOW).unwrap();
    let cert = result[0].certificate.as_ref().unwrap();
    assert!(field(cert, "Subject").contains("Synthetic Directory Certificate"));
    assert!(field(cert, "Issuer").contains("Synthetic Example CA"));
    assert_eq!(field(cert, "Serial number"), "2a");
    assert!(field(cert, "Public key algorithm").contains("ecPublicKey"));
    assert_eq!(field(cert, "Public key size"), "256 bits");
    assert!(field(cert, "Not before").starts_with("2024-01-01"));
    assert!(field(cert, "Not after").starts_with("2030-01-01"));
    assert!(field(cert, "Validity status").starts_with("Expires in "));
    assert_eq!(field(cert, "SAN 1"), "DNS: directory.example.test");
    assert_eq!(field(cert, "SAN 2"), "Email: operator@example.test");
    assert_eq!(field(cert, "SAN 3"), "IP: 192.0.2.5");
    assert!(field(cert, "Key usage").contains("Digital Signature"));
    assert_eq!(
        field(cert, "Extended key usage"),
        "TLS client, Email protection"
    );
    assert!(
        field(cert, "Basic constraints").contains("CA: false")
            || field(cert, "Basic constraints") == "Not present"
    );
    assert_ne!(field(cert, "Authority key identifier"), "Not present");
    for (label, algorithm) in [
        ("SHA-256 fingerprint", &ring::digest::SHA256),
        (
            "SHA-1 fingerprint (legacy)",
            &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        ),
    ] {
        let actual = ring::digest::digest(algorithm, &der)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(field(cert, label), actual);
    }
    use base64::Engine;
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(&cert.der_base64)
            .unwrap(),
        der
    );
    assert!(cert.pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
    assert!(!cert.pem.contains("PRIVATE"));
}
#[test]
fn expired_not_yet_valid_and_ca_are_explicit() {
    let expired =
        certificates::inspect(&fixtures::sample(true, false), Kind::Certificate, NOW).unwrap();
    assert_eq!(
        field(expired[0].certificate.as_ref().unwrap(), "Validity status"),
        "Expired"
    );
    let future =
        certificates::inspect(&fixtures::sample(false, true), Kind::Certificate, 0).unwrap();
    assert_eq!(
        field(future[0].certificate.as_ref().unwrap(), "Validity status"),
        "Not yet valid"
    );
    assert_eq!(
        field(future[0].certificate.as_ref().unwrap(), "Basic constraints"),
        "CA: true · path length: 0"
    );
    assert_ne!(
        field(
            future[0].certificate.as_ref().unwrap(),
            "Subject key identifier"
        ),
        "Not present"
    );
}
#[test]
fn pair_and_smime_preserve_independent_certificates() {
    let a = fixtures::sample(false, false);
    let b = fixtures::sample(true, true);
    for (bytes, kind) in [
        (fixtures::pair(&a, &b), Kind::Pair),
        (fixtures::smime(&[a.clone(), b]), Kind::Smime),
    ] {
        let parts = certificates::inspect(&bytes, kind, NOW).unwrap();
        assert_eq!(parts.len(), 2);
        assert_ne!(
            parts[0].certificate.as_ref().unwrap().der_base64,
            parts[1].certificate.as_ref().unwrap().der_base64
        );
        assert_eq!(
            field(parts[1].certificate.as_ref().unwrap(), "Validity status"),
            "Expired"
        );
    }
    let partial = fixtures::pair(&a, &[0x30, 0]);
    let parts = certificates::inspect(&partial, Kind::Pair, NOW).unwrap();
    assert!(parts[0].certificate.is_ok());
    assert!(parts[1].certificate.is_err());
    assert!(
        certificates::inspect(
            &fixtures::tlv(
                0x30,
                &[fixtures::tlv(0xa0, &a), fixtures::tlv(0xa0, &a)].concat()
            ),
            Kind::Pair,
            NOW
        )
        .is_err()
    );
}
#[test]
fn options_aliases_and_multiple_attributes_count_without_parsing() {
    use dirlark::model::Entry;
    let entry = Entry {
        dn: "cn=synthetic".into(),
        attrs: [
            ("userCertificate;binary".into(), vec![vec![], vec![]]),
            ("USERCERTIFICATE;lang-en".into(), vec![vec![]]),
            ("2.5.4.36".into(), vec![vec![]]),
            ("cACertificate".into(), vec![vec![]]),
        ]
        .into(),
    };
    assert_eq!(certificates::user_certificate_count(&entry), 4);
    assert_eq!(
        certificates::kind("CrossCertificatePAIR;binary"),
        Some(Kind::Pair)
    );
    assert_eq!(certificates::kind("userPKCS12"), None);
    assert_eq!(certificates::kind("userCertificateSECRET"), None);
}
#[test]
fn malformed_truncated_trailing_huge_and_nested_inputs_are_bounded() {
    let der = fixtures::sample(false, false);
    for n in 0..der.len() {
        assert!(
            certificates::inspect(&der[..n], Kind::Certificate, NOW).is_err()
                || certificates::inspect(&der[..n], Kind::Certificate, NOW).unwrap()[0]
                    .certificate
                    .is_err()
        );
    }
    let mut trailing = der.clone();
    trailing.extend([0x30, 0]);
    assert!(
        certificates::inspect(&trailing, Kind::Certificate, NOW).unwrap()[0]
            .certificate
            .is_err()
    );
    assert!(
        certificates::inspect(
            &vec![0; certificates::MAX_VALUE + 1],
            Kind::Certificate,
            NOW
        )
        .is_err()
    );
    let mut nested = fixtures::tlv(5, &[]);
    for _ in 0..30 {
        nested = fixtures::tlv(0x30, &nested);
    }
    assert!(certificates::inspect(&nested, Kind::Certificate, NOW).is_err());
    assert!(certificates::inspect(&fixtures::smime(&vec![der; 33]), Kind::Smime, NOW).is_err());
    // Deterministic malformed byte corpus exercises all container entry points, no catch_unwind.
    let mut seed = 7_u32;
    for len in 0..512 {
        let bytes = (0..len)
            .map(|_| {
                seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                (seed >> 24) as u8
            })
            .collect::<Vec<_>>();
        for kind in [Kind::Certificate, Kind::Pair, Kind::Smime] {
            let _ = certificates::inspect(&bytes, kind, NOW);
        }
    }
}

#[test]
fn rsa_modulus_bits_and_generated_p384_ed25519_are_reported_exactly() {
    use rcgen::{CertificateParams, Issuer, KeyPair, PublicKeyData, SignatureAlgorithm};
    struct PublicRsa(Vec<u8>);
    impl PublicKeyData for PublicRsa {
        fn der_bytes(&self) -> &[u8] {
            &self.0
        }
        fn algorithm(&self) -> &'static SignatureAlgorithm {
            &rcgen::PKCS_RSA_SHA256
        }
    }
    let issuer = Issuer::new(CertificateParams::default(), KeyPair::generate().unwrap());
    for (first, bits) in [(0x80, 2048), (0x40, 2047)] {
        let mut modulus = vec![0x35; 256];
        modulus[0] = first;
        if first == 0x80 {
            modulus.insert(0, 0);
        }
        let key = PublicRsa(fixtures::tlv(
            0x30,
            &[fixtures::tlv(2, &modulus), fixtures::tlv(2, &[1, 0, 1])].concat(),
        ));
        let der = CertificateParams::default()
            .signed_by(&key, &issuer)
            .unwrap();
        let parts = certificates::inspect(der.der(), Kind::Certificate, NOW).unwrap();
        assert_eq!(
            field(parts[0].certificate.as_ref().unwrap(), "Public key size"),
            format!("{bits} bits")
        );
    }
    for (algorithm, size) in [
        (&rcgen::PKCS_ECDSA_P384_SHA384, "384 bits"),
        (&rcgen::PKCS_ED25519, "256 bits"),
    ] {
        let der = CertificateParams::default()
            .signed_by(&KeyPair::generate_for(algorithm).unwrap(), &issuer)
            .unwrap();
        let parts = certificates::inspect(der.der(), Kind::Certificate, NOW).unwrap();
        assert_eq!(
            field(parts[0].certificate.as_ref().unwrap(), "Public key size"),
            size
        );
    }
}
#[test]
fn nested_extension_is_capped_before_deep_extension_decoding() {
    let mut nested = fixtures::tlv(5, &[]);
    for _ in 0..30 {
        nested = fixtures::tlv(0x30, &nested);
    }
    let mut params = rcgen::CertificateParams::default();
    params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(
            &[2, 5, 29, 17],
            nested,
        ));
    let der = params
        .self_signed(&rcgen::KeyPair::generate().unwrap())
        .unwrap();
    let parts = certificates::inspect(der.der(), Kind::Certificate, NOW).unwrap();
    assert!(
        parts[0]
            .certificate
            .as_ref()
            .unwrap_err()
            .contains("complexity limit")
    );
}
