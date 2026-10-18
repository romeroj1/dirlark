//! Opt-in native-store verification using a unique, temporary application-owned entry.
use dirlark::{model::Profile, profiles::credential};
use zeroize::Zeroizing;
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
    let profile = Profile {
        endpoint: "ldaps://keyring-smoke.invalid:636".into(),
        bind_dn: "cn=temporary-runtime-fixture".into(),
        ..Default::default()
    };
    let entry = credential(&profile)?;
    let secret = Zeroizing::new(uuid::Uuid::new_v4().to_string());
    entry
        .set_password(&secret)
        .map_err(|_| "Cannot create temporary native-store entry")?;
    let retrieved = entry.get_password().map(Zeroizing::new);
    let removed = entry.delete_credential();
    removed.map_err(|_| "Temporary native-store entry cleanup failed")?;
    let retrieved = retrieved.map_err(|_| "Native-store read failed; temporary entry deleted")?;
    if *retrieved != *secret {
        return Err("Native-store roundtrip mismatch; temporary entry deleted".into());
    }
    if !matches!(
        entry.get_password().map(Zeroizing::new),
        Err(keyring::Error::NoEntry)
    ) {
        return Err("Native store did not confirm deletion".into());
    }
    println!(
        "PASS: native credential store create/read/delete; temporary entry removed, no secret logged"
    );
    Ok(())
}
