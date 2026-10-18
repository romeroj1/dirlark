//! Shared native chrome. Built-in fonts and egui controls stay identical across platforms.
use eframe::egui::{self, Color32, FontFamily, FontId, Stroke, TextStyle};

#[derive(Clone, Copy)]
pub struct Palette {
    pub background: Color32,
    pub surface: Color32,
    pub input: Color32,
    pub text: Color32,
    pub muted: Color32,
    pub border: Color32,
    pub accent: Color32,
    pub on_accent: Color32,
    pub selection: Color32,
    pub error: Color32,
    pub warning: Color32,
}
pub fn palette(dark: bool) -> Palette {
    if dark {
        Palette {
            background: Color32::from_rgb(18, 26, 35),
            surface: Color32::from_rgb(23, 34, 46),
            input: Color32::from_rgb(16, 24, 33),
            text: Color32::from_rgb(231, 239, 246),
            muted: Color32::from_rgb(167, 185, 201),
            border: Color32::from_rgb(53, 72, 89),
            accent: Color32::from_rgb(103, 211, 187),
            on_accent: Color32::from_rgb(13, 39, 35),
            selection: Color32::from_rgb(32, 65, 70),
            error: Color32::from_rgb(255, 177, 164),
            warning: Color32::from_rgb(245, 207, 135),
        }
    } else {
        Palette {
            background: Color32::from_rgb(246, 248, 251),
            surface: Color32::WHITE,
            input: Color32::from_rgb(247, 250, 252),
            text: Color32::from_rgb(30, 48, 65),
            muted: Color32::from_rgb(83, 103, 121),
            border: Color32::from_rgb(195, 208, 220),
            accent: Color32::from_rgb(13, 107, 91),
            on_accent: Color32::WHITE,
            selection: Color32::from_rgb(218, 238, 232),
            error: Color32::from_rgb(166, 41, 49),
            warning: Color32::from_rgb(126, 78, 5),
        }
    }
}
pub fn colors(ui: &egui::Ui) -> Palette {
    palette(ui.visuals().dark_mode)
}
pub fn install(ctx: &egui::Context) {
    for mode in [egui::Theme::Dark, egui::Theme::Light] {
        let p = palette(mode == egui::Theme::Dark);
        let mut style = egui::Style {
            text_styles: [
                (
                    TextStyle::Heading,
                    FontId::new(22.0, FontFamily::Proportional),
                ),
                (TextStyle::Body, FontId::new(14.0, FontFamily::Proportional)),
                (
                    TextStyle::Button,
                    FontId::new(13.0, FontFamily::Proportional),
                ),
                (
                    TextStyle::Small,
                    FontId::new(12.0, FontFamily::Proportional),
                ),
                (
                    TextStyle::Monospace,
                    FontId::new(13.0, FontFamily::Monospace),
                ),
            ]
            .into(),
            ..Default::default()
        };
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.spacing.button_padding = egui::vec2(10.0, 5.0);
        style.spacing.interact_size = egui::vec2(28.0, 28.0);
        style.spacing.window_margin = egui::Margin::same(16);
        style.spacing.text_edit_width = 240.0;
        style.spacing.combo_width = 180.0;
        let v = &mut style.visuals;
        v.dark_mode = mode == egui::Theme::Dark;
        v.panel_fill = p.background;
        v.window_fill = p.surface;
        v.extreme_bg_color = p.input;
        v.text_edit_bg_color = Some(p.input);
        v.faint_bg_color = p.surface;
        v.code_bg_color = p.input;
        v.weak_text_color = Some(p.muted);
        v.hyperlink_color = p.accent;
        v.error_fg_color = p.error;
        v.warn_fg_color = p.warning;
        v.window_corner_radius = egui::CornerRadius::same(8);
        v.window_stroke = Stroke::new(1.0, p.border);
        v.selection.bg_fill = p.selection;
        v.selection.stroke = Stroke::new(1.5, p.accent);
        for widget in [
            &mut v.widgets.noninteractive,
            &mut v.widgets.inactive,
            &mut v.widgets.hovered,
            &mut v.widgets.active,
            &mut v.widgets.open,
        ] {
            widget.corner_radius = egui::CornerRadius::same(5);
            widget.fg_stroke = Stroke::new(1.0, p.text);
            widget.bg_stroke = Stroke::new(1.0, p.border);
            widget.bg_fill = p.surface;
            widget.weak_bg_fill = p.surface;
            widget.expansion = 0.0;
        }
        v.widgets.noninteractive.bg_fill = p.background;
        v.widgets.hovered.bg_fill = p.selection;
        v.widgets.hovered.weak_bg_fill = p.selection;
        v.widgets.hovered.bg_stroke = Stroke::new(1.0, p.accent);
        v.widgets.active.bg_stroke = Stroke::new(2.0, p.accent);
        v.widgets.active.bg_fill = p.selection;
        v.widgets.active.weak_bg_fill = p.selection;
        ctx.set_style_of(mode, style);
    }
}
pub fn primary(ui: &mut egui::Ui, label: &str, enabled: bool) -> egui::Response {
    let p = colors(ui);
    ui.add_enabled(
        enabled,
        egui::Button::new(egui::RichText::new(label).color(p.on_accent).strong()).fill(p.accent),
    )
}
pub fn note(ui: &mut egui::Ui, title: &str, message: &str, warning: bool) {
    let p = colors(ui);
    let color = if warning { p.warning } else { p.error };
    egui::Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(1.0, color))
        .corner_radius(5)
        .inner_margin(10)
        .show(ui, |ui| {
            ui.label(egui::RichText::new(title).strong().color(color));
            ui.add(egui::Label::new(message).wrap());
        });
}
#[cfg(test)]
mod tests {
    use super::*;
    fn luminance(c: Color32) -> f32 {
        [c.r(), c.g(), c.b()]
            .into_iter()
            .zip([0.2126, 0.7152, 0.0722])
            .map(|(v, w)| {
                let v = f32::from(v) / 255.0;
                w * if v <= 0.04045 {
                    v / 12.92
                } else {
                    ((v + 0.055) / 1.055).powf(2.4)
                }
            })
            .sum()
    }
    fn contrast(a: Color32, b: Color32) -> f32 {
        let a = luminance(a);
        let b = luminance(b);
        (a.max(b) + 0.05) / (a.min(b) + 0.05)
    }
    #[test]
    fn text_and_feedback_palette_is_readable_in_both_themes() {
        for dark in [true, false] {
            let p = palette(dark);
            for foreground in [p.text, p.muted, p.error, p.warning] {
                for background in [p.background, p.surface] {
                    assert!(
                        contrast(foreground, background) >= 4.5,
                        "insufficient text contrast"
                    );
                }
            }
            assert!(contrast(p.on_accent, p.accent) >= 4.5);
        }
    }
}
