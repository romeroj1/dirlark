//! UI icons: a 6 KB subset of the Phosphor Icons font (MIT), embedded in the binary.
//!
//! Glyphs are ordinary text in the private-use area, so they follow the theme text colour,
//! stay crisp at any scale and need no image loading or network. Every icon-only control also
//! gets a hover tooltip and an accessibility label, because a glyph is meaningless to a screen reader.
use eframe::egui;
use std::sync::Arc;

const FONT: &[u8] = include_bytes!("../../assets/fonts/phosphor/Phosphor-subset.ttf");
const FONT_NAME: &str = "phosphor-icons";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icon {
    Domain,
    Ou,
    Person,
    Group,
    Device,
    Other,
    Connect,
    Disconnect,
    Search,
    Schema,
    Ldif,
    Certificate,
    Copy,
    KeychainSaved,
    KeychainEmpty,
    TlsVerified,
    Warning,
    Error,
    Info,
    Entry,
}
impl Icon {
    #[cfg(test)]
    pub const ALL: [Icon; 20] = [
        Icon::Domain,
        Icon::Ou,
        Icon::Person,
        Icon::Group,
        Icon::Device,
        Icon::Other,
        Icon::Connect,
        Icon::Disconnect,
        Icon::Search,
        Icon::Schema,
        Icon::Ldif,
        Icon::Certificate,
        Icon::Copy,
        Icon::KeychainSaved,
        Icon::KeychainEmpty,
        Icon::TlsVerified,
        Icon::Warning,
        Icon::Error,
        Icon::Info,
        Icon::Entry,
    ];
    #[cfg(test)]
    /// Phosphor glyph name; `assets/fonts/phosphor/glyphs.json` maps it to the code point.
    pub fn name(self) -> &'static str {
        match self {
            Icon::Domain => "globe-hemisphere-west",
            Icon::Ou => "folder-simple",
            Icon::Person => "user",
            Icon::Group => "users-three",
            Icon::Device => "desktop-tower",
            Icon::Other => "database",
            Icon::Connect => "plugs-connected",
            Icon::Disconnect => "plug",
            Icon::Search => "magnifying-glass",
            Icon::Schema => "tree-structure",
            Icon::Ldif => "file-text",
            Icon::Certificate => "certificate",
            Icon::Copy => "copy",
            Icon::KeychainSaved => "lock-key",
            Icon::KeychainEmpty => "lock-simple-open",
            Icon::TlsVerified => "shield-check",
            Icon::Warning => "warning",
            Icon::Error => "x-circle",
            Icon::Info => "info",
            Icon::Entry => "identification-card",
        }
    }
    pub fn glyph(self) -> char {
        match self {
            Icon::Domain => '\u{e28c}',
            Icon::Ou => '\u{e25a}',
            Icon::Person => '\u{e4c2}',
            Icon::Group => '\u{e68e}',
            Icon::Device => '\u{e562}',
            Icon::Other => '\u{e1de}',
            Icon::Connect => '\u{eb5a}',
            Icon::Disconnect => '\u{e946}',
            Icon::Search => '\u{e30c}',
            Icon::Schema => '\u{e67c}',
            Icon::Ldif => '\u{e23a}',
            Icon::Certificate => '\u{e766}',
            Icon::Copy => '\u{e1ca}',
            Icon::KeychainSaved => '\u{e2fe}',
            Icon::KeychainEmpty => '\u{e30a}',
            Icon::TlsVerified => '\u{e40c}',
            Icon::Warning => '\u{e4e0}',
            Icon::Error => '\u{e4f8}',
            Icon::Info => '\u{e2ce}',
            Icon::Entry => '\u{e2c8}',
        }
    }
    /// Icon followed by a visible text label, for buttons, tabs and status lines.
    pub fn text(self, label: &str) -> String {
        format!("{}  {label}", self.glyph())
    }
}

/// Adds the icon font as a fallback of the built-in families so glyphs work inside any text.
pub fn install_font(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        FONT_NAME.into(),
        Arc::new(egui::FontData::from_static(FONT)),
    );
    for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        fonts
            .families
            .entry(family)
            .or_default()
            .push(FONT_NAME.into());
    }
    ctx.set_fonts(fonts);
}

/// Button with a leading icon. The accessible name is the plain label, not the glyph.
pub fn button(ui: &mut egui::Ui, icon: Icon, label: &str, enabled: bool) -> egui::Response {
    let response = ui.add_enabled(enabled, egui::Button::new(icon.text(label)));
    let name = label.to_string();
    response.widget_info(move || egui::WidgetInfo::labeled(egui::Role::Button, enabled, &name));
    response
}

/// Compact icon-only button; `label` is both the tooltip and the accessible name.
pub fn compact(ui: &mut egui::Ui, icon: Icon, label: &str) -> egui::Response {
    let response = ui
        .add(egui::Button::new(egui::RichText::new(icon.glyph().to_string()).size(14.0)).small())
        .on_hover_text(label);
    let name = label.to_string();
    response.widget_info(move || egui::WidgetInfo::labeled(egui::Role::Button, true, &name));
    response
}

/// Tree icon for a directory entry from its objectClass values, falling back to the first RDN.
pub fn node_icon(object_classes: &[String], dn: &str) -> Icon {
    let has = |names: &[&str]| {
        object_classes
            .iter()
            .any(|class| names.iter().any(|name| class.eq_ignore_ascii_case(name)))
    };
    // Order matters: an AD `computer` is also a `user`, a posixGroup is not a person.
    if has(&["device", "ipHost", "computer", "ieee802Device", "printer"]) {
        Icon::Device
    } else if has(&[
        "groupOfNames",
        "groupOfUniqueNames",
        "posixGroup",
        "group",
        "groupOfURLs",
    ]) {
        Icon::Group
    } else if has(&[
        "person",
        "inetOrgPerson",
        "organizationalPerson",
        "posixAccount",
        "user",
    ]) {
        Icon::Person
    } else if has(&["organizationalUnit", "container", "nsContainer"]) {
        Icon::Ou
    } else if has(&["domain", "dcObject", "organization", "country", "domainDNS"]) {
        Icon::Domain
    } else {
        match dn
            .split(',')
            .next()
            .and_then(|rdn| rdn.split_once('='))
            .map(|(attribute, _)| attribute.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("dc" | "o" | "c") => Icon::Domain,
            Some("ou") => Icon::Ou,
            _ => Icon::Other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn classes(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }
    #[test]
    fn glyph_table_matches_the_embedded_font_manifest() {
        let manifest: serde_json::Value =
            serde_json::from_str(include_str!("../../assets/fonts/phosphor/glyphs.json")).unwrap();
        let glyphs = manifest["glyphs"].as_object().unwrap();
        for icon in Icon::ALL {
            let code = glyphs
                .get(icon.name())
                .unwrap_or_else(|| panic!("{} missing from glyphs.json", icon.name()))
                .as_str()
                .unwrap();
            assert_eq!(
                u32::from_str_radix(code, 16).unwrap(),
                icon.glyph() as u32,
                "{}",
                icon.name()
            );
        }
        assert_eq!(manifest["license"], "MIT");
    }
    #[test]
    fn every_icon_is_a_distinct_private_use_glyph() {
        let mut seen = std::collections::BTreeSet::new();
        for icon in Icon::ALL {
            assert!(('\u{e000}'..='\u{f8ff}').contains(&icon.glyph()));
            assert!(seen.insert(icon.glyph()), "duplicate glyph {icon:?}");
        }
    }
    #[test]
    fn node_icons_follow_object_class_then_rdn() {
        assert_eq!(
            node_icon(&classes(&["top", "inetOrgPerson"]), "uid=a,dc=x"),
            Icon::Person
        );
        assert_eq!(
            node_icon(&classes(&["groupOfNames"]), "cn=g,dc=x"),
            Icon::Group
        );
        assert_eq!(
            node_icon(&classes(&["organizationalUnit"]), "ou=p,dc=x"),
            Icon::Ou
        );
        assert_eq!(
            node_icon(&classes(&["dcObject", "organization"]), "dc=x"),
            Icon::Domain
        );
        assert_eq!(
            node_icon(&classes(&["ipHost", "device"]), "cn=h,dc=x"),
            Icon::Device
        );
        // An AD computer is also a user: the device icon wins.
        assert_eq!(
            node_icon(&classes(&["user", "computer"]), "cn=pc,dc=x"),
            Icon::Device
        );
        assert_eq!(
            node_icon(&classes(&["POSIXGROUP"]), "cn=g,dc=x"),
            Icon::Group
        );
        // No objectClass data (naming contexts, unreadable entries): fall back to the RDN.
        assert_eq!(node_icon(&[], "dc=example,dc=test"), Icon::Domain);
        assert_eq!(node_icon(&[], "ou=People,dc=x"), Icon::Ou);
        assert_eq!(node_icon(&[], "cn=config"), Icon::Other);
        assert_eq!(node_icon(&classes(&["weirdClass"]), ""), Icon::Other);
    }
    #[test]
    fn text_keeps_the_plain_label_after_the_glyph() {
        let text = Icon::Connect.text("Connect");
        assert!(text.starts_with(Icon::Connect.glyph()));
        assert!(text.ends_with("Connect"));
    }
}
