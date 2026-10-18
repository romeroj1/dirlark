//! Linux CI supplies a nonexistent D-Bus socket; never touches an existing credential.
fn main() -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err("Run this missing-Secret-Service probe on Linux".into());
    }
    if std::env::var("DBUS_SESSION_BUS_ADDRESS").ok().as_deref()
        != Some("unix:path=/tmp/dirlark-no-session-bus")
    {
        return Err("Probe requires the explicit nonexistent CI D-Bus address".into());
    }
    let error = dirlark::profiles::credential_status()
        .err()
        .ok_or("Expected unavailable Secret Service")?;
    if !error.contains("Credentials cannot be saved") || !error.contains("no plaintext fallback") {
        return Err("Missing clear session-only credential status".into());
    }
    println!("PASS: {error}");
    Ok(())
}
