//! Local build identity; opening this dialog performs no requests or credential access.
use super::{egui, output};
pub fn show(ctx: &egui::Context) -> bool {
    let mut close = false;
    let response = egui::Modal::new(egui::Id::unique("about-dirlark")).show(ctx, |ui| {
        ui.set_width((ctx.content_rect().width() - 64.0).clamp(240.0, 520.0));
        ui.heading("About DIRLARK");
        ui.label("A native LDAP directory workbench");
        egui::ScrollArea::vertical().max_height((ctx.content_rect().height() - 180.0).max(120.0)).show(ui, |ui| {
            let build = crate::build_info::current();
            output::show(ui, "Version", build.version);
            output::show(ui, "Commit", build.commit);
            output::show(ui, "Build date (UTC)", build.built);
            output::show(ui, "Licence", "Apache-2.0");
            output::show(ui, "Build information", &build.text());
            ui.hyperlink_to("Source repository", "https://github.com/romeroj1/dirlark");
            ui.hyperlink_to("Notices", "https://github.com/romeroj1/dirlark/blob/main/NOTICE");
            ui.hyperlink_to("Apache-2.0 licence", "https://github.com/romeroj1/dirlark/blob/main/LICENSE");
            ui.separator();
            ui.label("Verified LDAPS only. Directory writes require preview and explicit Apply.");
            ui.label("Credential attributes are hidden and excluded from LDIF export by default. Password persistence is opt-in through your OS credential store; there is no plaintext fallback.");
            ui.label("Certificate inspection is display only: signature, chain, revocation and hostname are not validated.");
        });
        if ui.button("Close About").clicked() { close = true; }
    });
    !(close || response.should_close())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn about_renders_build_fields_and_individual_copy_controls() {
        fn text(shape: &egui::epaint::Shape, out: &mut String) {
            match shape {
                egui::epaint::Shape::Text(t) => {
                    out.push_str(t.galley.text());
                    out.push('\n');
                }
                egui::epaint::Shape::Vec(v) => {
                    for s in v {
                        text(s, out)
                    }
                }
                _ => {}
            }
        }
        let ctx = egui::Context::default();
        for _ in 0..3 {
            let mut out = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1000.0, 1000.0),
                    )),
                    ..Default::default()
                },
                |ui| {
                    let _ = show(ui.ctx());
                },
            );
            out.textures_delta.clear();
            let mut labels = String::new();
            for s in out.shapes {
                text(&s.shape, &mut labels)
            }
            if labels.contains("About DIRLARK") {
                assert!(labels.contains("Version"));
                assert!(labels.matches("Copy").count() >= 5);
                return;
            }
        }
        panic!("About did not render");
    }
}
