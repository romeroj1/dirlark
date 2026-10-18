//! Synthetic public certificates created in memory. No private key is serialized.
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};

pub fn sample(expired: bool, ca: bool) -> Vec<u8> {
    let mut root = CertificateParams::new(vec!["ca.example.test".into()]).unwrap();
    root.distinguished_name
        .push(DnType::CommonName, "Synthetic Example CA");
    root.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    let issuer = Issuer::new(root, KeyPair::generate().unwrap());
    let mut leaf = CertificateParams::new(vec!["directory.example.test".into()]).unwrap();
    leaf.distinguished_name
        .push(DnType::CommonName, "Synthetic Directory Certificate");
    leaf.distinguished_name
        .push(DnType::OrganizationName, "Example Test Fixtures");
    leaf.not_before = rcgen::date_time_ymd(2024, 1, 1);
    leaf.not_after = rcgen::date_time_ymd(if expired { 2025 } else { 2030 }, 1, 1);
    leaf.serial_number = Some(42_u64.into());
    leaf.use_authority_key_identifier_extension = true;
    leaf.subject_alt_names.push(SanType::Rfc822Name(
        "operator@example.test".try_into().unwrap(),
    ));
    leaf.subject_alt_names
        .push(SanType::IpAddress("192.0.2.5".parse().unwrap()));
    leaf.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyAgreement,
    ];
    leaf.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::EmailProtection,
    ];
    if ca {
        leaf.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    }
    leaf.signed_by(&KeyPair::generate().unwrap(), &issuer)
        .unwrap()
        .der()
        .to_vec()
}

pub fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if value.len() < 128 {
        out.push(value.len() as u8);
    } else {
        let bytes = value.len().to_be_bytes();
        let start = bytes.iter().position(|b| *b != 0).unwrap();
        out.push(0x80 | (bytes.len() - start) as u8);
        out.extend_from_slice(&bytes[start..]);
    }
    out.extend_from_slice(value);
    out
}

pub fn pair(first: &[u8], second: &[u8]) -> Vec<u8> {
    tlv(0x30, &[tlv(0xa0, first), tlv(0xa1, second)].concat())
}

pub fn smime(certs: &[Vec<u8>]) -> Vec<u8> {
    let signed = tlv(
        0x30,
        &[
            tlv(2, &[1]),
            tlv(0x31, &[]),
            tlv(
                0x30,
                &tlv(6, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 1]),
            ),
            tlv(0xa0, &certs.concat()),
            tlv(0x31, &[]),
        ]
        .concat(),
    );
    tlv(
        0x30,
        &[
            tlv(6, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 2]),
            tlv(0xa0, &signed),
        ]
        .concat(),
    )
}
