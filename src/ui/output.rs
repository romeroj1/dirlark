//! A labelled, independently copyable result. One component for decoded fields and encodings.
use eframe::egui;
pub fn show(ui: &mut egui::Ui, label: &str, text: &str) {
    ui.push_id(label, |ui| {
        egui::Frame::group(ui.style())
            .inner_margin(10.0)
            .show(ui, |ui| {
                ui.set_min_width((ui.available_width() - 4.0).max(0.0));
                ui.horizontal(|ui| {
                    ui.strong(label);
                    let id = ui.scope_id().with("copied-until");
                    let copied = ui
                        .ctx()
                        .data(|d| d.get_temp::<f64>(id))
                        .is_some_and(|until| until > ui.input(|i| i.time));
                    let copy = ui
                        .button(if copied { "Copied" } else { "Copy" })
                        .on_hover_text(format!("Copy {label}"));
                    copy.widget_info(|| {
                        egui::WidgetInfo::labeled(
                            egui::Role::Button,
                            ui.is_enabled(),
                            format!("Copy {label}"),
                        )
                    });
                    if copy.clicked() {
                        ui.ctx().copy_text(text.to_owned());
                        let until = ui.input(|i| i.time) + 1.5;
                        ui.ctx().data_mut(|d| d.insert_temp(id, until));
                        ui.ctx()
                            .request_repaint_after(std::time::Duration::from_millis(1500));
                    }
                });
                let preview = if text.len() > 2048 {
                    let mut n = 2048;
                    while !text.is_char_boundary(n) {
                        n -= 1;
                    }
                    &text[..n]
                } else {
                    text
                };
                ui.add(egui::Label::new(egui::RichText::new(preview).monospace()).wrap());
                if preview.len() < text.len() {
                    ui.small("Preview shortened; Copy includes the complete value.");
                }
            });
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    fn copy_position(shapes: &[egui::epaint::ClippedShape]) -> Option<egui::Pos2> {
        fn find(shape: &egui::epaint::Shape) -> Option<egui::Pos2> {
            match shape {
                egui::epaint::Shape::Text(t) if t.galley.text() == "Copy" => {
                    Some(t.pos + egui::vec2(4.0, 4.0))
                }
                egui::epaint::Shape::Vec(v) => v.iter().find_map(find),
                _ => None,
            }
        }
        shapes.iter().find_map(|s| find(&s.shape))
    }
    #[test]
    fn real_copy_button_copies_the_entire_value_without_requiring_full_preview() {
        let ctx = egui::Context::default();
        let text = "é".repeat(3000);
        let mut position = None;
        for _ in 0..3 {
            let mut out = ctx.run_ui(egui::RawInput::default(), |ui| {
                egui::CentralPanel::default().show(ui, |ui| show(ui, "DER base64", &text));
            });
            position = copy_position(&out.shapes).or(position);
            out.textures_delta.clear();
        }
        let pos = position.expect("independent Copy control rendered");
        let mut copied = false;
        for pressed in [true, false] {
            let mut out = ctx.run_ui(
                egui::RawInput {
                    events: vec![
                        egui::Event::PointerMoved(pos),
                        egui::Event::PointerButton {
                            pos,
                            button: egui::PointerButton::Primary,
                            pressed,
                            modifiers: Default::default(),
                        },
                    ],
                    ..Default::default()
                },
                |ui| {
                    egui::CentralPanel::default().show(ui, |ui| show(ui, "DER base64", &text));
                },
            );
            copied |= out
                .platform_output
                .commands
                .iter()
                .any(|c| matches!(c,egui::OutputCommand::CopyText(t) if t==&text));
            out.textures_delta.clear();
        }
        assert!(
            copied,
            "Copy must include all bytes, not the truncated preview"
        );
    }
}
