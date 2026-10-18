//! Bounded LDAP control codecs. Cookies are opaque and never logged or persisted.
use ldap3::controls::RawControl;

pub const PAGED: &str = "1.2.840.113556.1.4.319";
pub const SORT: &str = "1.2.840.113556.1.4.473";
pub const SORT_RESPONSE: &str = "1.2.840.113556.1.4.474";
pub const VLV: &str = "2.16.840.1.113730.3.4.9";
pub const VLV_RESPONSE: &str = "2.16.840.1.113730.3.4.10";
pub const PAGE_BYTES: usize = 2 * 1024 * 1024;
pub const TOKEN_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Capabilities {
    pub paged: bool,
    pub vlv: bool,
}
impl Capabilities {
    pub fn from_controls(controls: &[String]) -> Self {
        Self {
            paged: controls.iter().any(|s| s == PAGED),
            vlv: controls.iter().any(|s| s == VLV) && controls.iter().any(|s| s == SORT),
        }
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct Query {
    pub base: String,
    /// 0 = base, 1 = children, 2 = subtree.
    pub scope: u8,
    pub filter: String,
    pub attrs: Vec<String>,
    pub sort: String,
    pub ordering_rule: String,
}
impl Query {
    pub fn validate(&self, size: u16) -> Result<(), String> {
        if !crate::model::bounded_filter(&self.filter) {
            return Err("Use one valid LDAP filter, at most 4 KiB and 24 nested levels".into());
        }
        if !(25..=500).contains(&size) || self.scope > 2 {
            return Err("Choose a page size from 25 to 500 and a valid scope".into());
        }
        if !crate::model::valid_attribute(&self.sort) || self.sort.len() > 128 {
            return Err("Choose a valid sort attribute".into());
        }
        if !self.ordering_rule.is_empty()
            && (self.ordering_rule.len() > 128
                || !self.ordering_rule.contains('.')
                || self
                    .ordering_rule
                    .split('.')
                    .any(|part| part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit())))
        {
            return Err("Enter a numeric ordering-rule OID, or leave it blank".into());
        }
        if self.base.len() + self.filter.len() + self.attrs.iter().map(String::len).sum::<usize>()
            > 64 * 1024
        {
            return Err("Search definition exceeds 64 KiB".into());
        }
        Ok(())
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Forward,
    Vlv,
    Limited,
}
/// Bound to one live connection and the original query. Never Debug/serialize.
#[derive(Clone)]
pub struct Cursor {
    pub(crate) connection: uuid::Uuid,
    pub(crate) query: Query,
    pub(crate) mode: Mode,
    pub(crate) cookie: Vec<u8>,
    pub(crate) offset: u32,
    pub(crate) total: Option<u32>,
}
pub struct Page {
    pub entries: Vec<crate::model::Entry>,
    pub next: Option<Cursor>,
    pub offset: u32,
    /// Only a nonzero VLV contentCount; RFC 2696 estimates are deliberately ignored.
    pub total: Option<u32>,
    pub mode: Mode,
    pub warning: Option<String>,
}
pub fn entry_bytes(entry: &crate::model::Entry) -> usize {
    // Account for allocation capacity and container overhead, including empty values.
    std::mem::size_of_val(entry)
        + entry.dn.capacity()
        + entry
            .attrs
            .iter()
            .map(|(key, values)| {
                128 + key.capacity()
                    + values.capacity() * std::mem::size_of::<Vec<u8>>()
                    + values.iter().map(Vec::capacity).sum::<usize>()
            })
            .sum::<usize>()
}
pub(crate) fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if value.len() < 128 {
        out.push(value.len() as u8);
    } else {
        let bytes = value.len().to_be_bytes();
        let start = bytes
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(bytes.len() - 1);
        out.push(0x80 | (bytes.len() - start) as u8);
        out.extend_from_slice(&bytes[start..]);
    }
    out.extend_from_slice(value);
    out
}
pub(crate) fn integer(value: u32) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(3);
    let mut data = Vec::new();
    if bytes[start] & 0x80 != 0 {
        data.push(0);
    }
    data.extend_from_slice(&bytes[start..]);
    tlv(2, &data)
}
fn control(oid: &str, value: Vec<u8>) -> RawControl {
    RawControl {
        ctype: oid.into(),
        crit: true,
        val: Some(value),
    }
}
pub(crate) fn paged(size: u16, cookie: &[u8]) -> RawControl {
    control(
        PAGED,
        tlv(0x30, &[integer(u32::from(size)), tlv(4, cookie)].concat()),
    )
}
pub(crate) fn vlv(
    size: u16,
    offset: u32,
    total: Option<u32>,
    context: &[u8],
    sort: &str,
    ordering_rule: &str,
) -> Vec<RawControl> {
    let mut key = tlv(4, sort.as_bytes());
    if !ordering_rule.is_empty() {
        key.extend(tlv(0x80, ordering_rule.as_bytes()));
    }
    let key = tlv(0x30, &key);
    let sort = control(SORT, tlv(0x30, &key));
    let mut value = [
        integer(0),
        integer(u32::from(size - 1)),
        tlv(
            0xa0,
            &[integer(offset), integer(total.unwrap_or(0))].concat(),
        ),
    ]
    .concat();
    if !context.is_empty() {
        value.extend(tlv(4, context));
    }
    vec![sort, control(VLV, tlv(0x30, &value))]
}
/// Minimal strict BER reader: rejects truncated, indefinite, oversized and negative values.
pub(crate) fn take<'a>(input: &mut &'a [u8], tag: u8) -> Result<&'a [u8], String> {
    let invalid = || "Invalid LDAP paging response control".to_string();
    if input.len() < 2 || input[0] != tag {
        return Err(invalid());
    }
    let first = input[1];
    let (len, start) = if first < 128 {
        (usize::from(first), 2)
    } else {
        let n = usize::from(first & 127);
        if n == 0 || n > 4 || input.len() < n + 2 {
            return Err(invalid());
        }
        let len = input[2..2 + n]
            .iter()
            .fold(0usize, |len, b| (len << 8) | usize::from(*b));
        (len, n + 2)
    };
    if len > TOKEN_BYTES + 64 || len > input.len() - start {
        return Err(invalid());
    }
    let value = &input[start..start + len];
    *input = &input[start + len..];
    Ok(value)
}
pub(crate) fn number(input: &mut &[u8], tag: u8) -> Result<u32, String> {
    let value = take(input, tag)?;
    if value.is_empty() || value.len() > 5 || value[0] & 0x80 != 0 {
        return Err("Invalid paging integer".into());
    }
    value.iter().try_fold(0u32, |n, b| {
        n.checked_mul(256)
            .and_then(|n| n.checked_add(u32::from(*b)))
            .ok_or_else(|| "Paging integer overflow".into())
    })
}
pub(crate) fn sequence(value: &[u8]) -> Result<&[u8], String> {
    let mut input = value;
    let seq = take(&mut input, 0x30)?;
    if !input.is_empty() {
        return Err("Trailing paging control bytes".into());
    }
    Ok(seq)
}
pub(crate) fn paged_response(value: &[u8]) -> Result<Vec<u8>, String> {
    let mut value = sequence(value)?;
    let _estimate = number(&mut value, 2)?;
    let cookie = take(&mut value, 4)?.to_vec();
    if !value.is_empty() || cookie.len() > TOKEN_BYTES {
        return Err("Invalid paging cookie".into());
    }
    Ok(cookie)
}
pub(crate) fn vlv_response(value: &[u8]) -> Result<(u32, Option<u32>, Vec<u8>), String> {
    let mut value = sequence(value)?;
    let position = number(&mut value, 2)?;
    let total = number(&mut value, 2)?;
    if number(&mut value, 10)? != 0 {
        return Err("Server declined VLV; use forward-only paging".into());
    }
    let context = if value.is_empty() {
        vec![]
    } else {
        take(&mut value, 4)?.to_vec()
    };
    if !value.is_empty() || context.len() > TOKEN_BYTES {
        return Err("Invalid VLV context".into());
    }
    Ok((position, (total > 0).then_some(total), context))
}
pub(crate) fn sort_response(value: &[u8]) -> Result<(), String> {
    if number(&mut sequence(value)?, 10)? == 0 {
        Ok(())
    } else {
        Err("Server declined the selected sort key".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capabilities_require_both_vlv_and_sort() {
        assert!(!Capabilities::from_controls(&[VLV.into(), PAGED.into()]).vlv);
        assert!(Capabilities::from_controls(&[VLV.into(), SORT.into()]).vlv);
        assert!(!Capabilities::default().paged);
    }
    #[test]
    fn malformed_controls_fail_without_panics_or_total_estimates() {
        for bytes in [
            vec![],
            vec![0x30, 0x80],
            vec![0x30, 0x84, 0xff],
            tlv(0x30, &tlv(2, &[0xff])),
            tlv(
                0x30,
                &[integer(1), tlv(4, &vec![0; TOKEN_BYTES + 1])].concat(),
            ),
        ] {
            assert!(paged_response(&bytes).is_err());
            assert!(vlv_response(&bytes).is_err());
        }
        let value = tlv(0x30, &[integer(1), integer(0), tlv(10, &[0])].concat());
        assert_eq!(vlv_response(&value).unwrap().1, None);
        let value = tlv(0x30, &[integer(1_000_000), tlv(4, b"opaque")].concat());
        assert_eq!(paged_response(&value).unwrap(), b"opaque");
    }
    #[test]
    fn sort_control_encodes_optional_ordering_oid_and_validates_it() {
        let controls = vlv(25, 1, None, &[], "uid", "2.5.13.3");
        let mut list = sequence(controls[0].val.as_ref().unwrap()).unwrap();
        let mut key = take(&mut list, 0x30).unwrap();
        assert_eq!(take(&mut key, 4).unwrap(), b"uid");
        assert_eq!(take(&mut key, 0x80).unwrap(), b"2.5.13.3");
        assert!(key.is_empty() && list.is_empty());
        let mut query = Query {
            base: String::new(),
            scope: 2,
            filter: "(objectClass=*)".into(),
            attrs: vec![],
            sort: "uid".into(),
            ordering_rule: String::new(),
        };
        for rule in [
            "2..5",
            ".2.5",
            "2.5.",
            "2.5);bad",
            "caseIgnoreOrderingMatch",
        ] {
            query.ordering_rule = rule.into();
            assert!(query.validate(25).is_err());
        }
        query.ordering_rule = "2.5.13.3".into();
        assert!(query.validate(25).is_ok());
    }
}
