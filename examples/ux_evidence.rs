//! Native renderer evidence only. Release builds cannot seed synthetic workspace state.
#[cfg(debug_assertions)]
fn main() -> eframe::Result {
    use eframe::egui;
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 7 {
        eprintln!("usage: ux_evidence SCENE dark|light OUTPUT WIDTH HEIGHT ZOOM");
        std::process::exit(2);
    }
    let scene = args[1].clone();
    if !dirlark::ui::evidence::SCENES.contains(&scene.as_str()) {
        std::process::exit(2);
    }
    let dark = match args[2].as_str() {
        "dark" => true,
        "light" => false,
        _ => std::process::exit(2),
    };
    let path = std::path::PathBuf::from(&args[3]);
    let width: f32 = args[4].parse().expect("width");
    let height: f32 = args[5].parse().expect("height");
    let zoom: f32 = args[6].parse().expect("zoom");
    eframe::run_native(
        "DIRLARK · synthetic UX evidence",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size([width, height]),
            ..Default::default()
        },
        Box::new(move |cc| {
            cc.egui_ctx.set_theme(if dark {
                egui::Theme::Dark
            } else {
                egui::Theme::Light
            });
            cc.egui_ctx.set_visuals(if dark {
                egui::Visuals::dark()
            } else {
                egui::Visuals::light()
            });
            cc.egui_ctx.set_zoom_factor(zoom);
            Ok(Box::new(dirlark::ui::evidence::workspace(
                cc.egui_ctx.clone(),
                &scene,
                path,
            )))
        }),
    )
}
#[cfg(not(debug_assertions))]
fn main() {
    eprintln!("Synthetic UX evidence requires a debug build; no release fixture mode exists");
    std::process::exit(2);
}
