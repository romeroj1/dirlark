//! Debug-only visual fixtures. No user configuration, credential lookup or LDAP dispatch.
use super::*;
use std::collections::BTreeMap;

pub const SCENES: &[&str] = &[
    "about",
    "selection-empty",
    "selection-loading",
    "selection-credentials",
    "connection",
    "keychain-unavailable",
    "browse",
    "search",
    "limit",
    "empty-results",
    "editor",
    "preview",
    "delete-preview",
    "tls-error",
    "tls-healthy",
    "tls-expiring",
    "tls-failed",
    "busy",
    "ldif",
];
fn person(n: usize) -> Entry {
    Entry {
        dn: format!("uid=person{n:07},ou=Engineering,dc=example,dc=test"),
        attrs: BTreeMap::from([
            (
                "cn".into(),
                vec![format!("Alex Morgan {n:04}").into_bytes()],
            ),
            ("uid".into(), vec![format!("person{n:07}").into_bytes()]),
            (
                "mail".into(),
                vec![format!("person{n}@example.test").into_bytes()],
            ),
            ("objectClass".into(), vec![b"inetOrgPerson".to_vec()]),
            (
                "description".into(),
                vec![b"Engineering directory account for synthetic visual evidence".to_vec()],
            ),
            (
                "userPassword".into(),
                vec![b"synthetic-hidden-value".to_vec()],
            ),
        ]),
    }
}
pub fn workspace(ctx: egui::Context, scene: &str, path: PathBuf) -> Workspace {
    assert!(SCENES.contains(&scene));
    let mut app = Workspace::from_path(ctx, None, None, false);
    app.evidence_readonly = true;
    app.smoke = Some(crate::smoke::SmokeCapture::for_scene(path, scene));
    app.profile = Profile {
        name: "Engineering directory".into(),
        endpoint: "ldaps://directory.example.test:636".into(),
        base_dn: "dc=example,dc=test".into(),
        ..Default::default()
    };
    app.profiles = vec![
        app.profile.clone(),
        Profile {
            name: "Research directory".into(),
            endpoint: "ldaps://research.example.test:636".into(),
            ..app.profile.clone()
        },
    ];
    app.base = "ou=Engineering,dc=example,dc=test".into();
    app.status = "Choose a profile and connect over verified LDAPS".into();
    if scene == "about" {
        app.about_open = true;
        return app;
    }
    if scene == "keychain-unavailable" {
        app.credential_storage = Err(crate::profiles::CREDENTIALS_UNAVAILABLE.into());
    }
    if scene == "connection" || scene == "keychain-unavailable" {
        return app;
    }
    if scene == "tls-error" {
        app.note("TLS certificate could not be verified: the issuer is not trusted. Check the selected CA bundle and the endpoint hostname; TLS verification remains mandatory.".into());
        return app;
    }
    app.connected = true;
    app.roots = vec!["dc=example,dc=test".into()];
    app.status = "Connected · TLS certificate and hostname verified".into();
    let query = Query {
        base: app.base.clone(),
        scope: 2,
        filter: "(objectClass=inetOrgPerson)".into(),
        attrs: vec!["cn".into(), "uid".into(), "mail".into()],
        sort: "uid".into(),
        ordering_rule: String::new(),
    };
    app.filter = query.filter.clone();
    app.attrs = "cn,uid,mail".into();
    let next = || Cursor {
        connection: uuid::Uuid::nil(),
        query: query.clone(),
        mode: Mode::Forward,
        cookie: vec![],
        offset: 101,
        total: None,
    };
    let page = |limit: bool| crate::paging::Page {
        entries: (1..=100).map(person).collect(),
        next: (!limit).then(next),
        offset: 1,
        total: None,
        mode: Mode::Forward,
        warning: limit.then(|| {
            "Server size limit reached. Refine your search; results are incomplete.".into()
        }),
    };
    app.pages.insert(
        Key::Children("dc=example,dc=test".into()),
        query.clone(),
        100,
        crate::paging::Page {
            entries: ["Engineering", "Operations", "Research", "Sales", "Support"]
                .into_iter()
                .map(|ou| Entry {
                    dn: format!("ou={ou},dc=example,dc=test"),
                    attrs: BTreeMap::from([(
                        "numSubordinates".into(),
                        vec![if scene.starts_with("selection-") && ou == "Engineering" {
                            b"0".to_vec()
                        } else {
                            b"200000".to_vec()
                        }],
                    )]),
                })
                .collect(),
            next: None,
            offset: 1,
            total: None,
            mode: Mode::Forward,
            warning: None,
        },
        true,
    );
    app.pages.insert(
        Key::Children(app.base.clone()),
        query.clone(),
        100,
        if scene.starts_with("selection-") {
            let mut empty = page(false);
            empty.entries.clear();
            empty.next = None;
            empty
        } else {
            page(false)
        },
        true,
    );
    if matches!(scene, "search" | "limit" | "busy" | "empty-results") {
        app.tab = 1;
        let mut result = page(scene == "limit");
        if scene == "empty-results" {
            result.entries.clear();
            result.next = None;
        }
        app.pages.insert(Key::Search, query, 100, result, true);
        if scene == "limit" {
            app.note(
                "Server size limit reached. Refine your search; results are incomplete.".into(),
            );
        }
        if scene == "busy" {
            app.busy = true;
            app.active_page = Some((Key::Search, Arc::new(AtomicBool::new(false))));
            app.status = "Loading the next page…".into();
        }
    } else {
        app.selected = Some(person(42));
        if scene.starts_with("selection-") {
            let dn = "ou=Engineering,dc=example,dc=test".to_string();
            app.selected = Some(Entry {
                dn: dn.clone(),
                attrs: BTreeMap::new(),
            });
            if scene == "selection-loading" {
                app.pending_read = Some(dn);
                app.busy = true;
            }
            if scene == "selection-credentials" {
                app.selected.as_mut().unwrap().attrs.insert(
                    "userPassword".into(),
                    vec![b"synthetic-hidden-value".to_vec()],
                );
            }
        }
        app.attribute = "description".into();
        app.value = "Updated engineering account description".into();
        if matches!(scene, "preview" | "delete-preview") {
            app.pending = vec![if scene == "delete-preview" {
                Change::Delete(person(42).dn)
            } else {
                Change::Modify {
                    dn: person(42).dn,
                    changes: vec![AttributeChange::Replace(
                        "description".into(),
                        vec![app.value.as_bytes().to_vec()],
                    )],
                }
            }];
            app.expected = app.selected.clone();
            app.preview = true;
        }
        if scene == "ldif" {
            app.tab = 3;
            app.transfer = ldif::export(&[person(42)]);
        }
    }
    if scene.starts_with("selection-") {
        app.attribute.clear();
        app.value.clear();
    }
    app
}
/// Inject only synthetic entry data; no worker request is sent.
pub fn certificate_scene(mut app: Workspace, mut entry: Entry, scene: &str) -> Workspace {
    app.tab = 0;
    app.attribute.clear();
    app.value.clear();
    app.pending.clear();
    if scene == "malformed" {
        entry
            .attrs
            .insert("userCertificate;binary".into(), vec![vec![0x30, 3, 1]]);
    }
    if scene == "resized" {
        app.attributes_height = 430.0;
    }
    let choice = match scene {
        "valid" | "extensions" | "encodings" | "raw" | "compact" => {
            Some(("userCertificate;binary", 0))
        }
        "expired" => Some(("userCertificate;binary", 1)),
        "pair" => Some(("crossCertificatePair;binary", 0)),
        "smime" => Some(("userSMIMECertificate;binary", 0)),
        "malformed" => Some(("userCertificate;binary", 0)),
        _ => None,
    };
    if let Some((name, index)) = choice {
        app.certificate_viewer = certificate_view::Viewer::new(&entry, name, index);
        if let Some(viewer) = &mut app.certificate_viewer {
            viewer.tab = match scene {
                "extensions" => 1,
                "encodings" => 2,
                "raw" => 3,
                _ => 0,
            };
        }
    }
    app.selected = Some(entry);
    app
}
/// Security-panel evidence uses only supplied synthetic DER and never dispatches network work.
pub fn connection_security_scene(mut app: Workspace, der: Vec<u8>, scene: &str) -> Workspace {
    assert!(matches!(
        scene,
        "tls-healthy" | "tls-expiring" | "tls-failed"
    ));
    app.tls_capture = Some(crate::tls_observer::Capture {
        chain: vec![der],
        failure: (scene == "tls-failed").then_some("Hostname mismatch"),
        protocol: Some("TLS 1.3"),
    });
    app.connected = scene != "tls-failed";
    app.tls_panel_open = true;
    app.status = if scene == "tls-failed" {
        "TLS certificate hostname mismatch"
    } else {
        "Connected · TLS certificate and hostname verified"
    }
    .into();
    app
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixtures_never_dispatch_and_never_load_local_profiles() {
        let mut app = workspace(
            egui::Context::default(),
            "editor",
            PathBuf::from("unused.png"),
        );
        assert!(app.path.is_none());
        assert!(app.password.is_empty());
        app.send(Request::Read("dc=example,dc=test".into()));
        assert!(!app.busy);
        assert!(app.worker.receiver.try_recv().is_err());
    }
    #[test]
    fn security_fixtures_are_offline_and_carry_only_supplied_synthetic_der() {
        for scene in ["tls-healthy", "tls-expiring", "tls-failed"] {
            let app = workspace(
                egui::Context::default(),
                "editor",
                PathBuf::from("unused.png"),
            );
            let app = connection_security_scene(app, vec![0x30, 0], scene);
            assert!(app.path.is_none());
            assert!(app.password.is_empty());
            assert!(app.tls_panel_open);
            assert_eq!(app.tls_capture.as_ref().unwrap().chain, vec![vec![0x30, 0]]);
            assert!(app.worker.receiver.try_recv().is_err());
            assert_eq!(app.connected, scene != "tls-failed");
        }
    }
}
