//! Explicit development smoke mode; captures only when --smoke and a path are supplied.
use eframe::egui;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

type CaptureResult = Arc<Mutex<Option<Result<(), String>>>>;
pub struct SmokeCapture {
    screen: String,
    frames: u32,
    started: Instant,
    path: Option<PathBuf>,
    result: Option<CaptureResult>,
}
impl Default for SmokeCapture {
    fn default() -> Self {
        Self::new()
    }
}
impl SmokeCapture {
    pub fn new() -> Self {
        Self {
            screen: "connection".into(),
            frames: 0,
            started: Instant::now(),
            path: std::env::var_os("DIRLARK_SMOKE_SCREENSHOT").map(PathBuf::from),
            result: None,
        }
    }
    #[cfg(debug_assertions)]
    pub fn for_scene(path: PathBuf, scene: &str) -> Self {
        Self {
            path: Some(path),
            screen: scene.into(),
            ..Self::new()
        }
    }
    pub fn tick(
        &mut self,
        ctx: &egui::Context,
        ready: bool,
        visible: bool,
        credentials_available: bool,
    ) {
        self.frames += 1;
        if self.path.is_none() {
            if self.frames >= 3 {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            } else {
                ctx.request_repaint();
            }
            return;
        }
        if self.started.elapsed() > Duration::from_secs(20) {
            eprintln!("Smoke failed: capture deadline exceeded");
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        if let Some(result) = &self.result {
            if let Some(result) = result.lock().expect("capture state").take() {
                if result.is_err() {
                    eprintln!("Smoke failed: screenshot or receipt could not be saved");
                }
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        } else if self.frames >= 3
            && self.started.elapsed() >= Duration::from_millis(350)
            && ready
            && (visible || self.screen != "connection")
        {
            let path = self.path.clone().expect("capture path");
            let shared: CaptureResult = Arc::new(Mutex::new(None));
            self.result = Some(shared.clone());
            let repaint = ctx.clone();
            let frames = self.frames;
            let screen = self.screen.clone();
            let dark = ctx.global_style().visuals.dark_mode;
            let pixels_per_point = ctx.pixels_per_point();
            let renderer = if cfg!(target_os = "windows") {
                "eframe-wgpu-dx12"
            } else {
                "eframe-glow"
            };
            ctx.request_screenshot(move |pixels| {
                let result=(|| {
                    let bytes:Vec<u8>=pixels.pixels.iter().flat_map(|p|p.to_array()).collect();
                    image::save_buffer(&path,&bytes,pixels.width() as u32,pixels.height() as u32,image::ColorType::Rgba8).map_err(|_|"PNG encoding failed".to_string())?;
                    let receipt=serde_json::json!({"screen":screen,"dark_theme":dark,"pixels_per_point":pixels_per_point,"platform":std::env::consts::OS,"connection_screen_visible":visible,"credential_storage_available":credentials_available,"frames":frames,"width":pixels.width(),"height":pixels.height(),"renderer":renderer,"distinct_colors":pixels.pixels.iter().map(|p|p.to_array()).collect::<std::collections::HashSet<_>>().len()});
                    std::fs::write(path.with_extension("json"),serde_json::to_vec_pretty(&receipt).map_err(|_|"Receipt encoding failed".to_string())?).map_err(|_|"Receipt write failed".to_string())?;
                    Ok(())
                })();
                *shared.lock().expect("capture state")=Some(result);repaint.request_repaint();
            });
        }
        ctx.request_repaint_after(Duration::from_millis(16));
    }
}
