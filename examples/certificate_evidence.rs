//! Synthetic certificate UX captures only; no directory connection or user configuration.
#[cfg(debug_assertions)]
#[path = "support/certificates.rs"]
mod certificates;
#[cfg(debug_assertions)]
fn main() -> eframe::Result {
    use dirlark::{model::Entry, ui::evidence};
    use eframe::egui;
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(
        args.len(),
        5,
        "certificate_evidence SCENE dark|light OUTPUT ZOOM"
    );
    let scene = args[1].clone();
    let dimensions = if scene == "compact" {
        [900.0, 700.0]
    } else {
        [1280.0, 900.0]
    };
    let dark = args[2] == "dark";
    let path = std::path::PathBuf::from(&args[3]);
    let zoom: f32 = args[4].parse().unwrap();
    let first = certificates::sample(false, false);
    let expired = certificates::sample(true, false);
    let ca = certificates::sample(false, true);
    let entry = Entry {
        dn: "uid=certificate-demo,ou=People,dc=example,dc=test".into(),
        attrs: [
            ("cn".into(), vec![b"Synthetic Certificate Demo".to_vec()]),
            (
                "userCertificate;binary".into(),
                vec![first.clone(), expired.clone()],
            ),
            ("USERCERTIFICATE;lang-en;binary".into(), vec![ca.clone()]),
            ("cACertificate;binary".into(), vec![ca.clone()]),
            (
                "crossCertificatePair;binary".into(),
                vec![certificates::pair(&first, &ca)],
            ),
            (
                "userSMIMECertificate;binary".into(),
                vec![certificates::smime(&[first, ca])],
            ),
        ]
        .into(),
    };
    eframe::run_native(
        "DIRLARK · synthetic certificate evidence",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size(dimensions),
            ..Default::default()
        },
        Box::new(move |cc| {
            cc.egui_ctx.set_theme(if dark {
                egui::Theme::Dark
            } else {
                egui::Theme::Light
            });
            cc.egui_ctx.set_zoom_factor(zoom);
            let app = evidence::workspace(cc.egui_ctx.clone(), "editor", path);
            Ok(Box::new(evidence::certificate_scene(app, entry, &scene)))
        }),
    )
}
#[cfg(not(debug_assertions))]
fn main() {
    eprintln!("Synthetic evidence requires debug assertions");
    std::process::exit(2);
}
