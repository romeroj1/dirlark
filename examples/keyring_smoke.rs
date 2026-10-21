//! Opt-in native-store verification using a unique, temporary application-owned entry.
fn main() -> Result<(), String> {
    let arg = std::env::args().nth(1).unwrap_or_default();
    if arg == "--dry-run" {
        println!(
            "Would create, read and delete a unique temporary DIRLARK credential; no LDAP connection and no existing credentials accessed"
        );
        return Ok(());
    }
    if arg != "--answer-yes" {
        return Err("Use --dry-run first, then --answer-yes".into());
    }
    dirlark::profiles::keychain_selftest()?;
    println!(
        "PASS: native credential store create/read/delete; temporary entry removed, no secret logged"
    );
    Ok(())
}
