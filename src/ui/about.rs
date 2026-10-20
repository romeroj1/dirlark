//! Local build identity; opening this dialog performs no requests or credential access.
use super::{egui, output};
pub fn show(ctx: &egui::Context) -> bool {
    let mut close = false;
    let response = egui::Modal::new(egui::Id::unique("about-dirlark")).show(ctx, |ui| {
        ui.set_width((ctx.content_rect().width() - 64.0).clamp(260.0, 640.0));
        ui.heading("About DIRLARK");
        ui.label("A native LDAP directory workbench");
        egui::ScrollArea::vertical()
            .id_salt("about-scroll")
            .max_height((ctx.content_rect().height() - 140.0).max(200.0))
            .show(ui, |ui| {
                let build = crate::build_info::current();
                ui.columns(2, |cols| {
                    output::show(&mut cols[0], "Version", build.version);
                    output::show(&mut cols[0], "Build date (UTC)", build.built);
                    output::show(&mut cols[1], "Commit", build.commit);
                    output::show(&mut cols[1], "Licence", "Apache-2.0");
                });
                output::show(ui, "Build information", &build.text());
                ui.horizontal_wrapped(|ui| {
                    ui.small("Source repository (LICENSE & NOTICE):");
                    ui.code("https://github.com/romeroj1/dirlark");
                    if ui.small_button("Copy URL").clicked() {
                        ui.ctx()
                            .copy_text("https://github.com/romeroj1/dirlark".into());
                    }
                });
                ui.separator();
                ui.small(
                    "Verified LDAPS only. Directory writes require preview and explicit Apply.",
                );
                ui.small("Credential attributes are hidden and excluded from LDIF export by default. Password persistence is opt-in through your OS credential store; there is no plaintext fallback.");
                ui.small("Certificate inspection is display only: signature, chain, revocation and hostname are not validated.");
                ui.add_space(4.0);
            });
        ui.add_space(4.0);
        if ui.button("Close About").clicked() {
            close = true;
        }
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
        let mut labels = String::new();
        for _ in 0..3 {
            let mut out = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1160.0, 760.0),
                    )),
                    ..Default::default()
                },
                |ui| {
                    let _ = show(ui.ctx());
                },
            );
            out.textures_delta.clear();
            labels.clear();
            for s in out.shapes {
                text(&s.shape, &mut labels);
            }
        }
        assert!(labels.contains("About DIRLARK"), "{labels}");
        assert!(labels.contains("Version"), "{labels}");
        assert!(labels.contains("Source repository"), "{labels}");
        assert!(
            labels.contains("Certificate inspection is display only"),
            "{labels}"
        );
        assert!(labels.contains("Close About"), "{labels}");
        assert!(labels.matches("Copy").count() >= 5, "{labels}");
    }
}
