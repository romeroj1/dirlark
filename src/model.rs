use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub id: uuid::Uuid,
    pub name: String,
    pub endpoint: String,
    pub base_dn: String,
    pub bind_dn: String,
    pub ca_bundle: String,
    #[serde(default)]
    pub password_saved: bool,
}
impl Default for Profile {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            name: "My directory".into(),
            endpoint: "ldaps://directory.example.org:636".into(),
            base_dn: String::new(),
            bind_dn: String::new(),
            ca_bundle: String::new(),
            password_saved: false,
        }
    }
}
impl Profile {
    pub fn validate(&self) -> Result<(), String> {
        let u = url::Url::parse(&self.endpoint).map_err(|_| "Enter a valid LDAPS endpoint")?;
        if u.scheme() != "ldaps"
            || u.host_str().is_none()
            || !u.username().is_empty()
            || u.password().is_some()
            || !matches!(u.path(), "" | "/")
            || u.query().is_some()
            || u.fragment().is_some()
        {
            return Err(
                "Use ldaps://host:port without credentials, base, query or fragment".into(),
            );
        }
        Ok(())
    }
}
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Entry {
    pub dn: String,
    pub attrs: BTreeMap<String, Vec<Vec<u8>>>,
}
impl Entry {
    pub fn values(&self, name: &str) -> Vec<String> {
        self.attrs
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .flat_map(|(_, v)| v)
            .filter_map(|b| String::from_utf8(b.clone()).ok())
            .collect()
    }
}
pub fn valid_attribute(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b';'))
}
/// Credential-bearing descriptions; LDAP attribute options do not change sensitivity.
pub const CREDENTIAL_ATTRIBUTES: &[&str] = &[
    "userpassword",
    "unicodepwd",
    "ntpassword",
    "sambantpassword",
    "sambalmpassword",
    "pwdhistory",
    "supplementalcredentials",
    "krbprincipalkey",
    "authpassword",
    "olcrootpw",
    "ms-mcs-admpwd",
    "ipanthash",
    "krbextradata",
    "userpkcs12",
    "dbcspassword",
];
pub const CREDENTIAL_FRAGMENTS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "krb",
    "pkcs12",
    "privatekey",
];
pub fn credential_attribute(description: &str) -> bool {
    let base = description
        .split(';')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    CREDENTIAL_FRAGMENTS.iter().any(|part| base.contains(part))
        || CREDENTIAL_ATTRIBUTES.contains(&base.as_str())
}
pub fn protected_attribute(s: &str) -> bool {
    let s = s.to_ascii_lowercase();
    credential_attribute(&s)
        || matches!(
            s.split(';').next().unwrap_or(""),
            "userpassword"
                | "unicodepwd"
                | "authpassword"
                | "createtimestamp"
                | "modifytimestamp"
                | "entryuuid"
                | "entrycsn"
                | "creatorsname"
                | "modifiersname"
                | "structuralobjectclass"
                | "subschemasubentry"
                | "hassubordinates"
        )
}
pub fn equality_filter(attr: &str, value: &str) -> Result<String, String> {
    if !valid_attribute(attr) {
        return Err("Invalid attribute description".into());
    }
    Ok(format!("({attr}={})", ldap3::ldap_escape(value)))
}
/// Bound parser work before ldap3 compiles a user-supplied RFC 4515 filter.
/// Syntax validation remains the LDAP codec's job; this enforces one framed filter.
pub fn bounded_filter(filter: &str) -> bool {
    let bytes = filter.as_bytes();
    if bytes.is_empty() || bytes.len() > 4096 || bytes[0] != b'(' || bytes.contains(&0) {
        return false;
    }
    let mut depth = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                if i + 2 >= bytes.len()
                    || !bytes[i + 1].is_ascii_hexdigit()
                    || !bytes[i + 2].is_ascii_hexdigit()
                {
                    return false;
                }
                i += 2;
            }
            b'(' => {
                depth += 1;
                if depth > 24 {
                    return false;
                }
            }
            b')' => {
                if depth == 0 {
                    return false;
                }
                depth -= 1;
                if depth == 0 && i + 1 != bytes.len() {
                    return false;
                }
            }
            _ => {}
        }
        i += 1;
    }
    depth == 0
}
/// Escaped uid/cn/mail lookup; a deliberate leading '(' stays an advanced filter.
pub fn smart_filter(input: &str) -> Result<String, String> {
    let input = input.trim();
    if input.len() > 4096 {
        return Err("Search text exceeds 4 KiB".into());
    }
    if input.is_empty() {
        return Ok("(objectClass=*)".into());
    }
    if input.starts_with('(') {
        return Ok(input.into());
    }
    let v = ldap3::ldap_escape(input);
    let filter = format!("(|(uid={v})(cn=*{v}*)(mail={v}))");
    if filter.len() > 4096 {
        return Err("Escaped filter exceeds 4 KiB; refine your search".into());
    }
    Ok(filter)
}
pub fn expand_local_path_with_home(
    raw: &str,
    home: Option<&std::path::Path>,
) -> Result<std::path::PathBuf, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(
            "Cannot access file: enter a file path (for example ~/Downloads/entries.ldif)".into(),
        );
    }
    if trimmed == "~" || trimmed == "$HOME" {
        return home.map(std::path::Path::to_path_buf).ok_or_else(|| {
            "Cannot resolve ~: home directory is unavailable; enter a full file path".into()
        });
    }
    if let Some(rest) = trimmed
        .strip_prefix("~/")
        .or_else(|| trimmed.strip_prefix("~\\"))
        .or_else(|| trimmed.strip_prefix("$HOME/"))
        .or_else(|| trimmed.strip_prefix("$HOME\\"))
    {
        let base =
            home.ok_or("Cannot resolve ~: home directory is unavailable; enter a full file path")?;
        return Ok(base.join(rest));
    }
    Ok(std::path::PathBuf::from(trimmed))
}
pub fn expand_local_path(raw: &str) -> Result<std::path::PathBuf, String> {
    let home = directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf());
    expand_local_path_with_home(raw, home.as_deref())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credential_policy_includes_exact_names_patterns_and_options() {
        for name in CREDENTIAL_ATTRIBUTES.iter().copied().chain([
            "customPASSWORD",
            "customSecret;binary",
            "PwdAccountLockedTime",
            "customPasswd",
            "krbExtraData;binary",
            "privateKey;binary",
            "PKCS12",
        ]) {
            assert!(credential_attribute(name));
            assert!(credential_attribute(&format!(
                "{};BINARY",
                name.to_uppercase()
            )));
            assert!(protected_attribute(name));
        }
        for name in [
            "cn",
            "uid",
            "userCertificate;binary",
            "cACertificate",
            "description",
        ] {
            assert!(!credential_attribute(name));
        }
    }
    #[test]
    fn smart_search_escapes_injection_and_preserves_deliberate_raw_filters() {
        assert_eq!(
            smart_filter(" a*)(uid=*) ").unwrap(),
            "(|(uid=a\\2a\\29\\28uid=\\2a\\29)(cn=*a\\2a\\29\\28uid=\\2a\\29*)(mail=a\\2a\\29\\28uid=\\2a\\29))"
        );
        assert_eq!(smart_filter("(uid=example)").unwrap(), "(uid=example)");
        assert_eq!(smart_filter("").unwrap(), "(objectClass=*)");
        assert!(smart_filter(&"a".repeat(4097)).is_err());
    }
    #[test]
    fn filters_are_bounded_before_the_library_parser() {
        for filter in [
            "(cn=example)",
            "(&(cn=example)(uid=*))",
            "(cn=a\\2a\\28b\\29)",
        ] {
            assert!(bounded_filter(filter));
        }
        for filter in [
            "",
            "cn=example",
            "(cn=*)\\",
            "(cn=\\zz)",
            "(cn=*) (uid=*)",
            "(cn=*)\0",
        ] {
            assert!(!bounded_filter(filter));
        }
        let nested = format!("{}(cn=*){}", "(!".repeat(24), ")".repeat(24));
        assert!(!bounded_filter(&nested));
        assert!(!bounded_filter(&format!("(cn={})", "a".repeat(4096))));
        assert!(smart_filter(&"*".repeat(1000)).is_err());
    }
    #[test]
    fn endpoint_policy() {
        for endpoint in [
            "ldap://host",
            "ldaps://user@host",
            "ldaps://host/dc=x",
            "ldaps://host?x",
            "https://host",
        ] {
            assert!(
                Profile {
                    endpoint: endpoint.into(),
                    ..Default::default()
                }
                .validate()
                .is_err()
            );
        }
        assert!(Profile::default().validate().is_ok());
    }
    #[test]
    fn filter_escapes_assertions() {
        assert_eq!(
            equality_filter("cn", "a*)(uid=*)").unwrap(),
            "(cn=a\\2a\\29\\28uid=\\2a\\29)"
        );
    }
    #[test]
    fn profile_has_no_password_field() {
        let data = serde_json::to_value(Profile::default()).unwrap();
        for (key, value) in data.as_object().unwrap() {
            if key.contains("password") {
                assert_eq!(key, "password_saved");
                assert!(
                    value.is_boolean(),
                    "password_saved must be a non-secret boolean flag"
                );
            }
        }
    }
    #[test]
    fn filter_attribute_names_reject_injection_and_non_ascii() {
        for name in [
            "",
            "cn)(uid=*",
            "cn name",
            "cn=",
            "cn_",
            "cn/uid",
            "cñ",
            "cn\0",
        ] {
            assert!(equality_filter(name, "value").is_err(), "{name:?}");
        }
        for name in ["cn", "givenName", "cn;lang-en", "1.2.3"] {
            assert!(equality_filter(name, "value").is_ok(), "{name}");
        }
    }
    #[test]
    fn local_path_expansion_supports_tilde_home_and_rejects_empty() {
        let home = std::path::Path::new("/tmp/dirlark-home");
        assert!(expand_local_path_with_home("   ", Some(home)).is_err());
        assert_eq!(
            expand_local_path_with_home("~/Downloads/export.ldif", Some(home)).unwrap(),
            std::path::PathBuf::from("/tmp/dirlark-home/Downloads/export.ldif")
        );
        assert_eq!(
            expand_local_path_with_home("$HOME/certs/ca.pem", Some(home)).unwrap(),
            std::path::PathBuf::from("/tmp/dirlark-home/certs/ca.pem")
        );
        assert!(expand_local_path_with_home("~/export.ldif", None).is_err());
        assert_eq!(
            expand_local_path_with_home("/var/tmp/entries.ldif", None).unwrap(),
            std::path::PathBuf::from("/var/tmp/entries.ldif")
        );
    }
}
