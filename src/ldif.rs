//! RFC 2849 subset. URL values, controls and moddn are deliberately rejected.
use crate::model::{Entry, credential_attribute, valid_attribute};
use base64::{Engine, engine::general_purpose::STANDARD};

#[derive(Clone, PartialEq, Eq)]
pub enum Change {
    Add(Entry),
    Delete(String),
    Modify {
        dn: String,
        changes: Vec<AttributeChange>,
    },
}
#[derive(Clone, PartialEq, Eq)]
pub enum AttributeChange {
    Add(String, Vec<Vec<u8>>),
    Replace(String, Vec<Vec<u8>>),
    Delete(String, Vec<Vec<u8>>),
}
impl Change {
    pub fn dn(&self) -> &str {
        match self {
            Self::Add(e) => &e.dn,
            Self::Delete(dn) | Self::Modify { dn, .. } => dn,
        }
    }
}
fn pair(line: &str) -> Result<(String, Vec<u8>), String> {
    let (name, rest) = line.split_once(':').ok_or("Expected attribute: value")?;
    if !valid_attribute(name) {
        return Err("Invalid attribute description".into());
    }
    if rest.starts_with('<') {
        return Err("URL values are not supported".into());
    }
    let bytes = if let Some(s) = rest.strip_prefix(':') {
        STANDARD
            .decode(s.strip_prefix(' ').unwrap_or(s))
            .map_err(|_| "Invalid base64 value")?
    } else {
        rest.strip_prefix(' ').unwrap_or(rest).as_bytes().to_vec()
    };
    Ok((name.into(), bytes))
}
pub fn parse(input: &str) -> Result<Vec<Change>, String> {
    if input.len() > 16 * 1024 * 1024 {
        return Err("LDIF exceeds 16 MiB limit".into());
    }
    let mut lines: Vec<String> = Vec::new();
    for line in input.lines() {
        if let Some(tail) = line.strip_prefix(' ') {
            let last = lines
                .last_mut()
                .filter(|s| !s.is_empty())
                .ok_or("Continuation without a value")?;
            last.push_str(tail);
        } else {
            lines.push(line.to_string());
        }
    }
    let mut out = Vec::new();
    let mut version_seen = false;
    for chunk in lines.split(|s| s.is_empty()) {
        let mut record: Vec<&str> = chunk
            .iter()
            .map(String::as_str)
            .filter(|s| !s.starts_with('#'))
            .collect();
        if record.first() == Some(&"version: 1") {
            if version_seen || !out.is_empty() {
                return Err("Misplaced LDIF version".into());
            }
            version_seen = true;
            record.remove(0);
        }
        if record.is_empty() {
            continue;
        }
        let (name, dn) = pair(record[0])?;
        if !name.eq_ignore_ascii_case("dn") {
            return Err("Every record must begin with dn".into());
        }
        let dn = String::from_utf8(dn).map_err(|_| "DN is not UTF-8")?;
        if dn.is_empty() {
            return Err("Root DSE writes are not allowed".into());
        }
        let mut pos = 1;
        let kind = if record
            .get(pos)
            .is_some_and(|s| s.starts_with("changetype:"))
        {
            let (_, v) = pair(record[pos])?;
            pos += 1;
            String::from_utf8(v).map_err(|_| "Invalid change type")?
        } else {
            "add".into()
        };
        match kind.as_str() {
            "add" => {
                let mut e = Entry {
                    dn,
                    ..Default::default()
                };
                for line in &record[pos..] {
                    let (k, v) = pair(line)?;
                    if matches!(
                        k.to_ascii_lowercase().as_str(),
                        "control" | "changetype" | "dn"
                    ) {
                        return Err("Unexpected LDIF directive".into());
                    }
                    e.attrs.entry(k.to_ascii_lowercase()).or_default().push(v);
                }
                if e.attrs.is_empty() {
                    return Err("Add record has no attributes".into());
                }
                out.push(Change::Add(e));
            }
            "delete" => {
                if pos != record.len() {
                    return Err("Delete record has unexpected content".into());
                }
                out.push(Change::Delete(dn));
            }
            "modify" => {
                let mut changes = Vec::new();
                while pos < record.len() {
                    let (op, attr) = pair(record[pos])?;
                    pos += 1;
                    let attr =
                        String::from_utf8(attr).map_err(|_| "Invalid modification attribute")?;
                    if !valid_attribute(&attr) {
                        return Err("Invalid modification attribute".into());
                    }
                    let mut values = Vec::new();
                    while pos < record.len() && record[pos] != "-" {
                        let (k, v) = pair(record[pos])?;
                        pos += 1;
                        if !k.eq_ignore_ascii_case(&attr) {
                            return Err("Modification values must match attribute".into());
                        }
                        values.push(v);
                    }
                    if record.get(pos) != Some(&"-") {
                        return Err("Modification requires terminating dash".into());
                    }
                    pos += 1;
                    changes.push(match op.as_str() {
                        "add" if !values.is_empty() => AttributeChange::Add(attr, values),
                        "replace" => AttributeChange::Replace(attr, values),
                        "delete" => AttributeChange::Delete(attr, values),
                        _ => return Err("Unsupported modification".into()),
                    });
                }
                if changes.is_empty() {
                    return Err("Empty modification".into());
                }
                out.push(Change::Modify { dn, changes });
            }
            _ => return Err("Unsupported change type (supports add, modify, delete)".into()),
        }
    }
    Ok(out)
}
fn line(name: &str, value: &[u8], out: &mut String) {
    let safe = std::str::from_utf8(value).is_ok()
        && !value
            .first()
            .is_some_and(|c| matches!(c, b' ' | b':' | b'<'))
        && !value.last().is_some_and(|c| *c == b' ')
        && value.iter().all(|c| (0x20..=0x7e).contains(c));
    if safe {
        out.push_str(&format!("{name}: {}\n", String::from_utf8_lossy(value)));
    } else {
        out.push_str(&format!("{name}:: {}\n", STANDARD.encode(value)));
    }
}
/// Safe default: excludes credential attributes even when the server returned them.
pub fn export(entries: &[Entry]) -> String {
    export_with_credentials(entries, false)
}
/// `include_credentials` requires explicit user opt-in and a visible UI warning.
pub fn export_with_credentials(entries: &[Entry], include_credentials: bool) -> String {
    let mut out = "version: 1\n\n".to_string();
    if include_credentials {
        out.push_str("# WARNING: credential export enabled; passwords, hashes, history and keys may be present.\n\n");
    }
    for e in entries {
        line("dn", e.dn.as_bytes(), &mut out);
        for (k, values) in &e.attrs {
            if credential_attribute(k) && !include_credentials {
                continue;
            }
            for value in values {
                line(k, value, &mut out);
            }
        }
        out.push('\n');
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credential_export_requires_explicit_opt_in() {
        let mut entry = Entry {
            dn: "cn=fixture,dc=example".into(),
            ..Default::default()
        };
        entry.attrs.insert("cn".into(), vec![b"fixture".to_vec()]);
        for name in crate::model::CREDENTIAL_ATTRIBUTES
            .iter()
            .copied()
            .chain(["customPasswordHash", "customSecret"])
        {
            let description = format!("{};binary", name.to_ascii_uppercase());
            assert!(credential_attribute(&description));
            assert!(crate::model::protected_attribute(&description));
            entry
                .attrs
                .insert(description, vec![b"synthetic-fixture-only".to_vec()]);
        }
        let safe = export(std::slice::from_ref(&entry));
        assert!(safe.contains("cn: fixture"));
        assert!(!safe.contains("synthetic-fixture-only"));
        let explicit = export_with_credentials(&[entry], true);
        assert!(explicit.contains("WARNING: credential export enabled"));
        assert_eq!(
            explicit.matches("synthetic-fixture-only").count(),
            crate::model::CREDENTIAL_ATTRIBUTES.len() + 2
        );
        assert!(!credential_attribute("description;lang-en"));
    }
    #[test]
    fn binary_unicode_and_folding() {
        let input = "version: 1\n\ndn: cn=Test,dc=example\ncn: Hel\n lo\ndescription:: 5pel5pys6Kqe\njpegPhoto:: AP8=\n\n";
        let changes = parse(input).unwrap();
        let Change::Add(e) = &changes[0] else {
            panic!()
        };
        assert_eq!(e.values("cn"), vec!["Hello"]);
        assert_eq!(e.values("description"), vec!["日本語"]);
        assert!(parse(&export(std::slice::from_ref(e))).unwrap() == changes);
    }
    #[test]
    fn modification_and_delete() {
        let c=parse("dn: cn=X,dc=example\nchangetype: modify\nreplace: description\ndescription: changed\n-\ndelete: telephoneNumber\n-\n\ndn: cn=Y,dc=example\nchangetype: delete\n").unwrap();
        assert_eq!(c.len(), 2);
        assert!(matches!(&c[0],Change::Modify{changes,..} if changes.len()==2));
    }
    #[test]
    fn rejects_unsafe_or_malformed_records() {
        for s in [
            "dn: cn=x\ncn:< file:///etc/passwd",
            "dn: cn=x\nchangetype: moddn",
            "dn: cn=x\nchangetype: modrdn",
            "dn: cn=x\nchangetype: modify\nreplace: cn\ncn: x",
            "dn: cn=x\ncn:: !invalid",
            "dn:\ncn: x",
            " continuation",
        ] {
            assert!(parse(s).is_err(), "{s}");
        }
    }
}
