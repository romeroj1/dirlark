//! Bounded, offline inspection of public certificate attributes. No trust evaluation.
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::digest;
use x509_parser::nom::Parser;
use x509_parser::{
    certificate::X509CertificateParser,
    extensions::{GeneralName, ParsedExtension},
    prelude::*,
    public_key::PublicKey,
};

pub const MAX_VALUE: usize = 1024 * 1024;
const MAX_CERT: usize = 64 * 1024;
const INVALID: &str = "Could not decode this certificate value. The raw value is still available.";
const LIMIT: &str = "Certificate value exceeds the viewer's size or complexity limit. The raw value is still available.";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Certificate,
    Pair,
    Smime,
}
pub fn kind(name: &str) -> Option<Kind> {
    match name.split(';').next()?.to_ascii_lowercase().as_str() {
        "usercertificate" | "2.5.4.36" | "cacertificate" | "2.5.4.37" => Some(Kind::Certificate),
        "crosscertificatepair" | "2.5.4.40" => Some(Kind::Pair),
        "usersmimecertificate" | "2.16.840.1.113730.3.1.40" => Some(Kind::Smime),
        _ => None,
    }
}
pub fn user_certificate_count(entry: &crate::model::Entry) -> usize {
    entry
        .attrs
        .iter()
        .filter(|(name, _)| {
            matches!(
                name.split(';')
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .as_str(),
                "usercertificate" | "2.5.4.36"
            )
        })
        .map(|(_, values)| values.len())
        .sum()
}
#[derive(Clone, Debug)]
pub struct Certificate {
    pub fields: Vec<(String, String)>,
    pub pem: String,
    pub der_base64: String,
}
#[derive(Clone, Debug)]
pub struct Part {
    pub label: String,
    pub certificate: Result<Certificate, &'static str>,
}

// Definite-length DER framing, checked before the general-purpose ASN.1 parser.
// No recursive calls, indefinite lengths, oversized lengths, or high-tag numbers.
fn take(input: &[u8]) -> Result<(u8, &[u8], &[u8]), &'static str> {
    if input.len() < 2 || input[0] & 31 == 31 {
        return Err(INVALID);
    }
    let (len, header) = if input[1] < 128 {
        (usize::from(input[1]), 2)
    } else {
        let n = usize::from(input[1] & 127);
        if n == 0 || n > 4 || input.len() < 2 + n || input[2] == 0 {
            return Err(INVALID);
        }
        let len = input[2..2 + n]
            .iter()
            .fold(0usize, |a, b| (a << 8) | usize::from(*b));
        if len < 128 {
            return Err(INVALID);
        }
        (len, 2 + n)
    };
    if len > input.len() - header {
        return Err(INVALID);
    }
    Ok((
        input[0],
        &input[header..header + len],
        &input[header + len..],
    ))
}
fn whole(input: &[u8], tag: u8) -> Result<&[u8], &'static str> {
    let (actual, value, rest) = take(input)?;
    if actual != tag || !rest.is_empty() {
        return Err(INVALID);
    }
    Ok(value)
}
fn bounded_der(input: &[u8]) -> Result<(), &'static str> {
    let mut stack = vec![(input, 0usize)];
    let mut nodes = 0;
    while let Some((mut bytes, depth)) = stack.pop() {
        if depth > 24 {
            return Err(LIMIT);
        }
        while !bytes.is_empty() {
            nodes += 1;
            if nodes > 4096 {
                return Err(LIMIT);
            }
            let (tag, content, rest) = take(bytes)?;
            bytes = rest;
            if tag & 32 != 0 {
                stack.push((content, depth + 1));
            }
        }
    }
    Ok(())
}
pub fn inspect(value: &[u8], kind: Kind, now: i64) -> Result<Vec<Part>, &'static str> {
    if value.len() > MAX_VALUE {
        return Err(LIMIT);
    }
    bounded_der(value)?;
    let mut parts: Vec<(String, &[u8])> = vec![];
    match kind {
        Kind::Certificate => parts.push(("Certificate".into(), value)),
        Kind::Pair => {
            let mut bytes = whole(value, 0x30)?;
            let mut seen = 0u8;
            while !bytes.is_empty() {
                let (tag, der, rest) = take(bytes)?;
                bytes = rest;
                let (bit, label) = match tag {
                    0xa0 => (1, "Forward certificate"),
                    0xa1 => (2, "Reverse certificate"),
                    _ => return Err(INVALID),
                };
                if seen & bit != 0 {
                    return Err(INVALID);
                }
                seen |= bit;
                parts.push((label.into(), der));
            }
            if parts.is_empty() {
                return Err(INVALID);
            }
        }
        Kind::Smime => {
            // RFC 2798: certs-only SignedData. Also accept a standalone certificate.
            let seq = whole(value, 0x30)?;
            let (tag, oid, rest) = take(seq)?;
            if tag != 6 {
                parts.push(("Certificate".into(), value));
            } else {
                if oid != [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 2] {
                    return Err(INVALID);
                }
                let mut signed = whole(whole(rest, 0xa0)?, 0x30)?;
                for expected in [2, 0x31, 0x30] {
                    let (t, _, r) = take(signed)?;
                    if t != expected {
                        return Err(INVALID);
                    }
                    signed = r;
                }
                let (tag, certs, rest) = take(signed)?;
                if tag != 0xa0 {
                    return Err(INVALID);
                }
                let mut tail = rest;
                if tail.first() == Some(&0xa1) {
                    tail = take(tail)?.2;
                }
                whole(tail, 0x31)?;
                let mut certs = certs;
                while !certs.is_empty() {
                    if parts.len() >= 32 {
                        return Err(LIMIT);
                    }
                    let (tag, _, rest) = take(certs)?;
                    if tag != 0x30 {
                        return Err(INVALID);
                    }
                    parts.push((
                        format!("Bundle certificate {}", parts.len() + 1),
                        &certs[..certs.len() - rest.len()],
                    ));
                    certs = rest;
                }
                if parts.is_empty() {
                    return Err(INVALID);
                }
            }
        }
    }
    Ok(parts
        .into_iter()
        .map(|(label, der)| Part {
            label,
            certificate: decode(der, now),
        })
        .collect())
}
fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}
fn safe(text: String) -> String {
    let mut result = String::new();
    for c in text.chars() {
        if c.is_control() || matches!(c,'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}') {
            result.push_str(&format!("\\u{{{:04x}}}", u32::from(c)));
        } else {
            result.push(c);
        }
    }
    result
}
fn decode(der: &[u8], now: i64) -> Result<Certificate, &'static str> {
    if der.len() > MAX_CERT {
        return Err(LIMIT);
    }
    bounded_der(der)?;
    let (rest, shallow) = X509CertificateParser::new()
        .with_deep_parse_extensions(false)
        .parse(der)
        .map_err(|_| INVALID)?;
    if !rest.is_empty() {
        return Err(INVALID);
    }
    for ext in shallow.extensions() {
        bounded_der(ext.value)?;
    }
    // Public key parsers also contain nested ASN.1 (inside a BIT STRING).
    if shallow.public_key().algorithm.algorithm.to_id_string() == "1.2.840.113549.1.1.1" {
        bounded_der(&shallow.public_key().subject_public_key.data)?;
    }
    let (rest, cert) = X509Certificate::from_der(der).map_err(|_| INVALID)?;
    if !rest.is_empty() {
        return Err(INVALID);
    }
    let mut fields = Vec::new();
    let mut add = |name: &str, value: String| fields.push((name.into(), safe(value)));
    add("Subject", cert.subject().to_string());
    add("Issuer", cert.issuer().to_string());
    add("Serial number", cert.raw_serial_as_string());
    add(
        "Not before",
        cert.validity().not_before.to_datetime().to_string(),
    );
    add(
        "Not after",
        cert.validity().not_after.to_datetime().to_string(),
    );
    let end = cert.validity().not_after.timestamp();
    let start = cert.validity().not_before.timestamp();
    add(
        "Validity status",
        if now < start {
            "Not yet valid".into()
        } else if now > end {
            "Expired".into()
        } else {
            format!(
                "Expires in {} days",
                (end.saturating_sub(now) as u64).div_ceil(86400)
            )
        },
    );
    let alg = |oid: &x509_parser::der_parser::oid::Oid<'_>| {
        x509_parser::objects::oid2sn(oid, x509_parser::objects::oid_registry())
            .map(str::to_owned)
            .unwrap_or_else(|_| oid.to_id_string())
    };
    add(
        "Signature algorithm",
        alg(&cert.signature_algorithm.algorithm),
    );
    let key = cert.public_key();
    let oid = key.algorithm.algorithm.to_id_string();
    let size = match oid.as_str() {
        "1.2.840.113549.1.1.1" => match key.parsed() {
            Ok(PublicKey::RSA(rsa)) => {
                let m = rsa.modulus;
                let z = m.iter().take_while(|b| **b == 0).count();
                if z == m.len() {
                    None
                } else {
                    Some((m.len() - z) * 8 - m[z].leading_zeros() as usize)
                }
            }
            _ => None,
        },
        "1.2.840.10045.2.1" => key
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.as_oid().ok())
            .and_then(|c| match c.to_id_string().as_str() {
                "1.2.840.10045.3.1.7" | "1.3.132.0.10" => Some(256),
                "1.3.132.0.34" => Some(384),
                "1.3.132.0.35" => Some(521),
                _ => None,
            }),
        "1.3.101.112" => Some(256),
        "1.3.101.113" => Some(448),
        _ => None,
    };
    add("Public key algorithm", alg(&key.algorithm.algorithm));
    add(
        "Public key size",
        size.map(|b| format!("{b} bits"))
            .unwrap_or_else(|| "Unavailable for this algorithm".into()),
    );
    let mut extension_fields = std::collections::BTreeMap::<&str, String>::new();
    let mut seen = std::collections::BTreeSet::new();
    for ext in cert.extensions() {
        if !seen.insert(ext.oid.to_id_string()) {
            return Err(INVALID);
        }
        let item = match ext.parsed_extension() {
            ParsedExtension::ParseError { .. } => return Err(INVALID),
            ParsedExtension::SubjectAlternativeName(san) => {
                if san.general_names.len() > 128 {
                    return Err(LIMIT);
                }
                let values = san
                    .general_names
                    .iter()
                    .map(|v| match v {
                        GeneralName::DNSName(v) => format!("DNS: {v}"),
                        GeneralName::RFC822Name(v) => format!("Email: {v}"),
                        GeneralName::URI(v) => format!("URI: {v}"),
                        GeneralName::IPAddress(v) => match v.len() {
                            4 => format!("IP: {}", std::net::Ipv4Addr::new(v[0], v[1], v[2], v[3])),
                            16 => {
                                let mut a = [0; 16];
                                a.copy_from_slice(v);
                                format!("IP: {}", std::net::Ipv6Addr::from(a))
                            }
                            _ => "Invalid IP encoding".into(),
                        },
                        GeneralName::DirectoryName(v) => format!("DN: {v}"),
                        GeneralName::RegisteredID(v) => format!("Registered ID: {v}"),
                        _ => "Other SAN type (see raw DER)".into(),
                    })
                    .collect::<Vec<_>>();
                for (index, value) in values.into_iter().enumerate() {
                    add(&format!("SAN {}", index + 1), value);
                }
                Some((
                    "Subject alternative names",
                    format!("{} names", san.general_names.len()),
                ))
            }
            ParsedExtension::KeyUsage(v) => Some(("Key usage", v.to_string())),
            ParsedExtension::ExtendedKeyUsage(v) => {
                let mut values = vec![];
                for (flag, label) in [
                    (v.any, "Any"),
                    (v.server_auth, "TLS server"),
                    (v.client_auth, "TLS client"),
                    (v.code_signing, "Code signing"),
                    (v.email_protection, "Email protection"),
                    (v.time_stamping, "Time stamping"),
                    (v.ocsp_signing, "OCSP signing"),
                ] {
                    if flag {
                        values.push(label.into());
                    }
                }
                values.extend(v.other.iter().map(|oid| oid.to_id_string()));
                Some(("Extended key usage", values.join(", ")))
            }
            ParsedExtension::BasicConstraints(v) => Some((
                "Basic constraints",
                format!(
                    "CA: {} · path length: {}",
                    v.ca,
                    v.path_len_constraint
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "not specified".into())
                ),
            )),
            ParsedExtension::AuthorityKeyIdentifier(v) => Some((
                "Authority key identifier",
                v.key_identifier
                    .as_ref()
                    .map(|v| hex(v.0))
                    .unwrap_or_else(|| "Not present".into()),
            )),
            ParsedExtension::SubjectKeyIdentifier(v) => Some(("Subject key identifier", hex(v.0))),
            _ => None,
        };
        if let Some((name, value)) = item {
            extension_fields.insert(name, value);
        }
    }
    for name in [
        "Subject alternative names",
        "Key usage",
        "Extended key usage",
        "Basic constraints",
        "Authority key identifier",
        "Subject key identifier",
    ] {
        add(
            name,
            extension_fields
                .remove(name)
                .unwrap_or_else(|| "Not present".into()),
        );
    }
    add(
        "SHA-256 fingerprint",
        hex(digest::digest(&digest::SHA256, der).as_ref()),
    );
    add(
        "SHA-1 fingerprint (legacy)",
        hex(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, der).as_ref()),
    );
    if let Some(index) = fields
        .iter()
        .position(|(name, _)| name == "Validity status")
    {
        let status = fields.remove(index);
        fields.insert(0, status);
    }
    if fields.iter().any(|(_, value)| value.len() > 16384) {
        return Err(LIMIT);
    }
    let der_base64 = STANDARD.encode(der);
    let lines = der_base64
        .as_bytes()
        .chunks(64)
        .map(|b| std::str::from_utf8(b).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    Ok(Certificate {
        fields,
        pem: format!("-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n"),
        der_base64,
    })
}
