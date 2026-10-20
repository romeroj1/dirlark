//! Startup diagnostics accept categories, never directory data or error payloads.
use std::process::ExitCode;
#[cfg(any(target_os = "windows", test))]
use std::{fs, io::Write, path::Path};

#[cfg(any(target_os = "windows", test))]
const LOG_CAP: u64 = 64 * 1024;

#[derive(Clone, Copy)]
pub enum Event {
    Starting,
    HardwareRenderer,
    SoftwareRenderer,
    OpenGlFailure,
    RendererFailure,
    StartupFailure,
    Panic,
}
impl Event {
    fn text(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::HardwareRenderer => "renderer=dx12-hardware",
            Self::SoftwareRenderer => "renderer=dx12-warp-software",
            Self::OpenGlFailure => {
                "OpenGL initialization failed; OpenGL 2.0+ is required. On Windows use the DirectX12/WARP build or update the display driver."
            }
            Self::RendererFailure => {
                "DirectX12/WARP initialization failed. Update Windows and the display driver; a GPU-less VM needs the Windows DirectX12 WARP software adapter."
            }
            Self::StartupFailure => {
                "Native window/application initialization failed. Check Windows updates and the display driver."
            }
            Self::Panic => {
                "DIRLARK stopped unexpectedly. Restart the app; if this repeats, report startup.log. Panic payload, location and directory data withheld."
            }
        }
    }
}

#[cfg(any(target_os = "windows", test))]
fn record(path: &Path, event: Event) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("No log directory"))?;
    fs::create_dir_all(parent)?;
    let truncate = fs::metadata(path).is_ok_and(|m| m.len() >= LOG_CAP);
    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .append(!truncate)
        .truncate(truncate)
        .open(path)?;
    // Build identity is compile-time metadata. No args, environment dump, panic
    // payload, raw eframe error, profile, DN or password can enter this format.
    writeln!(
        file,
        "DIRLARK {} {} {}: {}",
        crate::build_info::current().version,
        std::env::consts::OS,
        std::env::consts::ARCH,
        event.text()
    )
}

pub fn note(event: Event) {
    #[cfg(target_os = "windows")]
    if let Some(root) = std::env::var_os("LOCALAPPDATA") {
        let _ = record(
            &std::path::PathBuf::from(root).join("Dirlark/startup.log"),
            event,
        );
    }
    #[cfg(not(target_os = "windows"))]
    let _ = event;
}

// Thread-local re-entry protection keeps a failed hook/dialog from recursively
// presenting another dialog; concurrent worker panics still get their own log.
#[cfg(any(target_os = "windows", test))]
fn panic_actions(
    active: &std::cell::Cell<bool>,
    is_main: bool,
    log: impl FnOnce(),
    dialog: impl FnOnce(),
) {
    if active.replace(true) {
        return;
    }
    struct Reset<'a>(&'a std::cell::Cell<bool>);
    impl Drop for Reset<'_> {
        fn drop(&mut self) {
            self.0.set(false);
        }
    }
    let _reset = Reset(active);
    log();
    if is_main {
        dialog();
    }
}

pub fn install() {
    #[cfg(target_os = "windows")]
    {
        note(Event::Starting);
        let main_thread = std::thread::current().id();
        std::thread_local! { static ACTIVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
        std::panic::set_hook(Box::new(move |_info| {
            // Do not chain the default hook: it prints raw payloads/locations.
            ACTIVE.with(|active| {
                panic_actions(
                    active,
                    std::thread::current().id() == main_thread,
                    || {
                        note(Event::Panic);
                        eprintln!(
                            "DIRLARK stopped unexpectedly; see %LOCALAPPDATA%\\Dirlark\\startup.log"
                        );
                    },
                    || show_dialog(Event::Panic),
                )
            });
        }));
    }
}

fn classify(error: &eframe::Error) -> Event {
    match error {
        eframe::Error::OpenGL(_)
        | eframe::Error::Glutin(_)
        | eframe::Error::NoGlutinConfigs(_, _) => Event::OpenGlFailure,
        #[cfg(target_os = "windows")]
        eframe::Error::Wgpu(_) => Event::RendererFailure,
        _ => Event::StartupFailure,
    }
}

#[cfg(target_os = "windows")]
fn show_dialog(event: Event) {
    let _ = rfd::MessageDialog::new().set_title(if matches!(event, Event::Panic) { "DIRLARK stopped unexpectedly" } else { "DIRLARK could not start" })
        .set_description(format!("{}\n\nDiagnostic log: %LOCALAPPDATA%\\Dirlark\\startup.log (if the folder is writable). No credentials or directory data are recorded.", event.text()))
        .set_level(rfd::MessageLevel::Error).show();
}

pub fn fatal(error: &eframe::Error) -> ExitCode {
    report(classify(error))
}

pub fn diagnostic_dialog() -> ExitCode {
    report(Event::OpenGlFailure)
}

fn report(event: Event) -> ExitCode {
    note(event);
    eprintln!("DIRLARK: {}", event.text());
    #[cfg(target_os = "windows")]
    show_dialog(event);
    ExitCode::FAILURE
}

// Actual Windows adapter selection uses this tested policy. Software adapters
// remain eligible when no compatible hardware adapter exists.
#[cfg(any(target_os = "windows", test))]
fn adapter_index(candidates: &[(bool, bool)], force_software: bool) -> Option<usize> {
    if force_software {
        return candidates
            .iter()
            .position(|(compatible, software)| *compatible && *software);
    }
    candidates
        .iter()
        .position(|(compatible, software)| *compatible && !*software)
        .or_else(|| candidates.iter().position(|(compatible, _)| *compatible))
}

/// Window/dock icon. macOS uses the padded artwork (the dock does not mask icons); other
/// platforms use the full-bleed rounded square. Decoded from the embedded PNG, no files or network.
fn window_icon() -> eframe::egui::IconData {
    #[cfg(target_os = "macos")]
    const PNG: &[u8] = include_bytes!("../assets/icon/macos/dirlark-512.png");
    #[cfg(not(target_os = "macos"))]
    const PNG: &[u8] = include_bytes!("../assets/icon/png/dirlark-256.png");
    let image = image::load_from_memory_with_format(PNG, image::ImageFormat::Png)
        .expect("embedded icon is a valid PNG")
        .into_rgba8();
    let (width, height) = image.dimensions();
    eframe::egui::IconData {
        rgba: image.into_raw(),
        width,
        height,
    }
}

pub fn native_options(force_software: bool) -> eframe::NativeOptions {
    let mut options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_app_id("dirlark")
            .with_icon(window_icon()),
        ..Default::default()
    };
    #[cfg(not(target_os = "windows"))]
    {
        let _ = force_software;
        options.renderer = eframe::Renderer::Glow;
    }
    #[cfg(target_os = "windows")]
    {
        use eframe::{egui_wgpu, wgpu};
        let mut setup = egui_wgpu::WgpuSetupCreateNew::without_display_handle();
        setup.instance_descriptor = wgpu::InstanceDescriptor {
            backends: wgpu::Backends::DX12,
            flags: wgpu::InstanceFlags::from_build_config(),
            backend_options: wgpu::BackendOptions::default(),
            memory_budget_thresholds: wgpu::MemoryBudgetThresholds::default(),
            display: None,
        };
        // Windows ships FXC; do not download or bundle DXC/Mesa DLLs, or
        // inherit compiler-path overrides from WGPU_* environment variables.
        setup
            .instance_descriptor
            .backend_options
            .dx12
            .shader_compiler = wgpu::Dx12Compiler::Fxc;
        setup.native_adapter_selector = Some(std::sync::Arc::new(move |adapters, surface| {
            let candidates: Vec<_> = adapters
                .iter()
                .map(|adapter| {
                    (
                        surface.is_none_or(|s| adapter.is_surface_supported(s)),
                        adapter.get_info().device_type == wgpu::DeviceType::Cpu,
                    )
                })
                .collect();
            let index = adapter_index(&candidates, force_software)
                .ok_or_else(|| "No compatible DirectX12 hardware or WARP adapter".to_owned())?;
            note(if candidates[index].1 {
                Event::SoftwareRenderer
            } else {
                Event::HardwareRenderer
            });
            Ok(adapters[index].clone())
        }));
        options.renderer = eframe::Renderer::Wgpu;
        options.wgpu_options.wgpu_setup = setup.into();
    }
    options
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn panic_logs_on_workers_but_dialog_is_main_only_and_cannot_reenter() {
        let active = std::cell::Cell::new(false);
        let logs = std::cell::Cell::new(0);
        let dialogs = std::cell::Cell::new(0);
        panic_actions(
            &active,
            false,
            || logs.set(logs.get() + 1),
            || dialogs.set(dialogs.get() + 1),
        );
        assert_eq!((logs.get(), dialogs.get()), (1, 0));
        panic_actions(
            &active,
            true,
            || logs.set(logs.get() + 1),
            || {
                dialogs.set(dialogs.get() + 1);
                panic_actions(
                    &active,
                    true,
                    || panic!("recursive hook logged"),
                    || panic!("recursive dialog"),
                );
            },
        );
        assert_eq!((logs.get(), dialogs.get()), (2, 1));
        assert!(!active.get());
    }
    #[test]
    fn gpu_less_windows_keeps_compatible_software_adapter() {
        assert_eq!(
            adapter_index(&[(false, false), (true, true)], false),
            Some(1)
        );
        assert_eq!(
            adapter_index(&[(true, true), (true, false)], false),
            Some(1)
        );
        assert_eq!(adapter_index(&[(false, true)], false), None);
        assert_eq!(adapter_index(&[], false), None);
        assert_eq!(adapter_index(&[(true, false), (true, true)], true), Some(1));
        assert_eq!(adapter_index(&[(true, false)], true), None);
    }
    #[test]
    fn native_renderer_is_platform_specific() {
        #[cfg(target_os = "windows")]
        assert!(matches!(
            native_options(false).renderer,
            eframe::Renderer::Wgpu
        ));
        #[cfg(not(target_os = "windows"))]
        assert!(matches!(
            native_options(false).renderer,
            eframe::Renderer::Glow
        ));
    }
    #[test]
    fn window_icon_decodes_to_a_square_rgba_image() {
        let icon = window_icon();
        assert_eq!(icon.width, icon.height);
        assert!(icon.width >= 256);
        assert_eq!(icon.rgba.len(), (icon.width * icon.height * 4) as usize);
        // Corners are transparent (rounded square), the centre is opaque artwork.
        assert_eq!(icon.rgba[3], 0);
        let centre = ((icon.height / 2 * icon.width + icon.width / 2) * 4 + 3) as usize;
        assert_eq!(icon.rgba[centre], 255);
    }
    #[test]
    fn diagnostic_log_never_formats_error_payload_and_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("startup.log");
        let error = eframe::Error::AppCreation(Box::new(std::io::Error::other(
            "SYNTHETIC_PRIVATE_DIRECTORY_PAYLOAD",
        )));
        record(&path, classify(&error)).unwrap();
        record(&path, Event::Panic).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains("SYNTHETIC_PRIVATE_DIRECTORY_PAYLOAD"));
        assert!(text.contains("Panic payload, location and directory data withheld"));
        fs::write(&path, vec![b'x'; LOG_CAP as usize]).unwrap();
        record(&path, Event::Starting).unwrap();
        assert!(fs::metadata(path).unwrap().len() < 1024);
    }
}
