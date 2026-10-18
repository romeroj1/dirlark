use crate::model::Profile;
use std::{fs, io::Write, path::Path};

pub fn load(path: &Path) -> Result<Vec<Profile>, String> {
    if !path
        .try_exists()
        .map_err(|_| "Cannot inspect profiles path")?
    {
        return Ok(Vec::new());
    }
    let bytes = fs::read(path).map_err(|_| "Cannot read profiles")?;
    if bytes.len() > 1024 * 1024 {
        return Err("Profiles exceed size limit".into());
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| "Profiles are invalid; original file preserved".into())
}
/// Read legacy profiles only when the new path is absent. The next explicit
/// profile save writes the new path; the legacy file is never moved or deleted.
pub fn load_with_legacy(path: &Path, legacy: Option<&Path>) -> Result<Vec<Profile>, String> {
    if path
        .try_exists()
        .map_err(|_| "Cannot inspect profiles path")?
    {
        return load(path);
    }
    match legacy {
        Some(old) => load(old),
        None => load(path),
    }
}
pub fn save(path: &Path, profiles: &[Profile]) -> Result<(), String> {
    let dir = path.parent().ok_or("Invalid profiles path")?;
    fs::create_dir_all(dir).map_err(|_| "Cannot create profiles directory")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|_| "Cannot restrict profiles directory")?;
    }
    let tmp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).map_err(|_| "Cannot create profiles file")?;
        let bytes = serde_json::to_vec_pretty(profiles).map_err(|_| "Cannot serialize profiles")?;
        f.write_all(&bytes)
            .and_then(|()| f.sync_all())
            .map_err(|_| "Cannot write profiles")?;
        fs::rename(&tmp, path).map_err(|_| "Cannot atomically replace profiles")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
}
pub fn credential_account(profile: &Profile) -> String {
    // Scope saved credentials to the endpoint and bind identity, not just a mutable profile.
    format!("{}:{}:{}", profile.id, profile.endpoint, profile.bind_dn)
}
pub const CREDENTIALS_UNAVAILABLE: &str = "Credentials cannot be saved: the OS credential service is unavailable. Use a password for this session; no plaintext fallback.";
pub fn credential_status() -> Result<(), String> {
    static INITIALIZED: std::sync::OnceLock<Result<(), String>> = std::sync::OnceLock::new();
    INITIALIZED
        .get_or_init(|| {
            #[cfg(target_os = "macos")]
            let store = apple_native_keyring_store::keychain::Store::new()
                .map_err(|_| CREDENTIALS_UNAVAILABLE.to_string())?;
            #[cfg(target_os = "windows")]
            let store = windows_native_keyring_store::Store::new()
                .map_err(|_| CREDENTIALS_UNAVAILABLE.to_string())?;
            #[cfg(target_os = "linux")]
            let store = dbus_secret_service_keyring_store::Store::new()
                .map_err(|_| CREDENTIALS_UNAVAILABLE.to_string())?;
            keyring::set_default_store(store);
            Ok(())
        })
        .clone()
}
pub const CREDENTIAL_SERVICE: &str = "io.github.romeroj1.dirlark";

/// Public builds use their own namespace and never discover private-build secrets.
pub fn saved_password(profile: &Profile) -> Result<String, String> {
    credential_status()?;
    keyring::Entry::new(CREDENTIAL_SERVICE, &credential_account(profile))
        .and_then(|entry| entry.get_password())
        .map_err(|_| "No saved password available; enter one to connect".into())
}

pub fn credential(profile: &Profile) -> Result<keyring::Entry, String> {
    credential_status()?;
    keyring::Entry::new(CREDENTIAL_SERVICE, &credential_account(profile))
        .map_err(|_| CREDENTIALS_UNAVAILABLE.into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_profiles_preserve_identity_and_original_until_explicit_save() {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("old/profiles.json");
        let new = dir.path().join("new/profiles.json");
        let profile = Profile::default();
        save(&old, std::slice::from_ref(&profile)).unwrap();
        let original = fs::read(&old).unwrap();
        let loaded = load_with_legacy(&new, Some(&old)).unwrap();
        assert!(loaded == vec![profile]);
        assert!(!new.exists());
        save(&new, &loaded).unwrap();
        assert!(load_with_legacy(&new, Some(&old)).unwrap() == loaded);
        assert_eq!(fs::read(old).unwrap(), original);
    }
    #[test]
    fn new_profiles_win_and_corruption_never_falls_back() {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("old.json");
        let new = dir.path().join("new.json");
        save(&old, &[Profile::default()]).unwrap();
        save(&new, &[]).unwrap();
        assert!(load_with_legacy(&new, Some(&old)).unwrap().is_empty());
        fs::write(&new, b"invalid").unwrap();
        assert!(load_with_legacy(&new, Some(&old)).is_err());
        assert_eq!(fs::read(new).unwrap(), b"invalid");
    }
    #[test]
    fn private_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("profiles.json");
        let profile = Profile::default();
        save(&p, std::slice::from_ref(&profile)).unwrap();
        assert!(load(&p).unwrap() == vec![profile]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(p).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
    #[test]
    fn changed_endpoint_or_identity_never_reuses_credential() {
        let mut p = Profile::default();
        let original = credential_account(&p);
        p.endpoint = "ldaps://other.example:636".into();
        assert_ne!(original, credential_account(&p));
        p = Profile::default();
        let original = credential_account(&p);
        p.bind_dn = "cn=other,dc=example".into();
        assert_ne!(original, credential_account(&p));
    }
    #[test]
    fn corrupt_data_is_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("profiles.json");
        fs::write(&p, b"broken").unwrap();
        assert!(load(&p).is_err());
        assert_eq!(fs::read(p).unwrap(), b"broken");
    }
}
