use std::process::ExitCode;

fn main() -> ExitCode {
    if std::env::args().any(|a| a == "--version") {
        println!("{}", dirlark::build_info::current().text());
        return ExitCode::SUCCESS;
    }
    if std::env::args().any(|a| a == "--keychain-selftest") {
        // Headless probe used after release signing: no window, no LDAP, no existing credential.
        return match dirlark::profiles::keychain_selftest() {
            Ok(()) => {
                println!(
                    "PASS: native credential store create/read/delete; temporary entry removed"
                );
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("FAIL: {error}");
                ExitCode::FAILURE
            }
        };
    }
    dirlark::startup::install();
    if std::env::args().any(|a| a == "--test-startup-dialog") {
        return dirlark::startup::diagnostic_dialog();
    }
    let software = std::env::args().any(|a| a == "--software-rendering");
    let smoke = std::env::args().any(|a| a == "--smoke");
    match eframe::run_native(
        "DIRLARK",
        dirlark::startup::native_options(software),
        Box::new(move |cc| Ok(Box::new(dirlark::ui::Workspace::new(cc, smoke)))),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => dirlark::startup::fatal(&error),
    }
}
