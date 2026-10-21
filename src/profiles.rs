use crate::model::Profile;
use serde::{Deserialize, Serialize};
use std::{fs, io::Write, path::Path};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoredConfig {
    pub theme: Option<String>,
    pub profiles: Vec<Profile>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigDocument {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    theme: Option<String>,
    profiles: Vec<Profile>,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum RawConfig {
    List(Vec<Profile>),
    Document(ConfigDocument),
}

pub fn load_config(path: &Path) -> Result<StoredConfig, String> {
    if !path
        .try_exists()
        .map_err(|_| "Cannot inspect profiles path")?
    {
        return Ok(StoredConfig::default());
    }
    let bytes = fs::read(path).map_err(|_| "Cannot read profiles")?;
    if bytes.len() > 1024 * 1024 {
        return Err("Profiles exceed size limit".into());
    }
    match serde_json::from_slice::<RawConfig>(&bytes)
        .map_err(|_| "Profiles are invalid; original file preserved".to_string())?
    {
        RawConfig::List(profiles) => Ok(StoredConfig {
            theme: None,
            profiles,
        }),
        RawConfig::Document(doc) => Ok(StoredConfig {
            theme: doc.theme,
            profiles: doc.profiles,
        }),
    }
}

pub fn load(path: &Path) -> Result<Vec<Profile>, String> {
    load_config(path).map(|c| c.profiles)
}

/// Read legacy profiles only when the new path is absent. The next explicit
/// profile save writes the new path; the legacy file is never moved or deleted.
pub fn load_config_with_legacy(path: &Path, legacy: Option<&Path>) -> Result<StoredConfig, String> {
    if path
        .try_exists()
        .map_err(|_| "Cannot inspect profiles path")?
    {
        return load_config(path);
    }
    match legacy {
        Some(old) => load_config(old),
        None => load_config(path),
    }
}

pub fn load_with_legacy(path: &Path, legacy: Option<&Path>) -> Result<Vec<Profile>, String> {
    load_config_with_legacy(path, legacy).map(|c| c.profiles)
}

pub fn save(path: &Path, profiles: &[Profile]) -> Result<(), String> {
    let existing_theme = load_config(path).ok().and_then(|c| c.theme);
    save_with_theme(path, profiles, existing_theme.as_deref())
}

pub fn save_with_theme(
    path: &Path,
    profiles: &[Profile],
    theme: Option<&str>,
) -> Result<(), String> {
    let dir = path.parent().ok_or("Invalid profiles path")?;
    fs::create_dir_all(dir).map_err(|_| "Cannot create profiles directory")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|_| "Cannot restrict profiles directory")?;
    }
    let normalized_theme = theme.and_then(|t| match t {
        "dark" | "light" => Some(t.to_string()),
        _ => None,
    });
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
        let bytes = if let Some(theme) = normalized_theme {
            serde_json::to_vec_pretty(&ConfigDocument {
                theme: Some(theme),
                profiles: profiles.to_vec(),
            })
        } else {
            serde_json::to_vec_pretty(profiles)
        }
        .map_err(|_| "Cannot serialize profiles")?;
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
pub const KEYCHAIN_LOCKED_OR_DENIED: &str = "Saved password in the OS keychain is locked or access was denied; enter a session password or unlock the keychain";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SavedCredentialState {
    Present,
    Missing,
    LockedOrDenied(&'static str),
    StoreUnavailable(&'static str),
}

pub fn credential_status() -> Result<(), String> {
    if keyring::get_default_store().is_some() {
        return Ok(());
    }
    static INITIALIZED: std::sync::OnceLock<Result<(), String>> = std::sync::OnceLock::new();
    INITIALIZED
        .get_or_init(|| {
            #[cfg(test)]
            {
                let store =
                    keyring::mock::Store::new().map_err(|_| CREDENTIALS_UNAVAILABLE.to_string())?;
                keyring::set_default_store(store);
                Ok(())
            }
            #[cfg(not(test))]
            {
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
            }
        })
        .clone()
}
pub const CREDENTIAL_SERVICE: &str = "io.github.romeroj1.dirlark";

/// Detect whether this profile already has an OS keychain entry without touching foreign items.
pub fn probe_saved_password(profile: &Profile) -> SavedCredentialState {
    if profile.bind_dn.is_empty() {
        return SavedCredentialState::Missing;
    }
    if credential_status().is_err() {
        return SavedCredentialState::StoreUnavailable(CREDENTIALS_UNAVAILABLE);
    }
    let account = credential_account(profile);
    match keyring::Entry::new(CREDENTIAL_SERVICE, &account).and_then(|entry| entry.get_password()) {
        Ok(secret) => {
            let _ = zeroize::Zeroizing::new(secret);
            SavedCredentialState::Present
        }
        Err(keyring::Error::NoEntry) => SavedCredentialState::Missing,
        Err(_) => SavedCredentialState::LockedOrDenied(KEYCHAIN_LOCKED_OR_DENIED),
    }
}

/// Public builds use their own namespace and never discover private-build secrets.
pub fn saved_password(profile: &Profile) -> Result<String, String> {
    credential_status()?;
    keyring::Entry::new(CREDENTIAL_SERVICE, &credential_account(profile))
        .and_then(|entry| entry.get_password())
        .map_err(|err| match err {
            keyring::Error::NoEntry if profile.password_saved => {
                "Saved password was not found in the OS keychain; enter a password to connect".into()
            }
            keyring::Error::NoEntry => "No saved password available; enter one to connect".into(),
            _ => "Saved password could not be read from the OS keychain (access denied or keychain locked); enter a password for this session or unlock the keychain".into(),
        })
}

pub fn credential(profile: &Profile) -> Result<keyring::Entry, String> {
    credential_status()?;
    keyring::Entry::new(CREDENTIAL_SERVICE, &credential_account(profile))
        .map_err(|_| CREDENTIALS_UNAVAILABLE.into())
}

/// Release-signing probe: create, read back and delete ONE uniquely named, application-owned
/// entry. It never reads, lists or changes an existing credential and never prints a value.
pub fn keychain_selftest() -> Result<(), String> {
    let profile = Profile {
        endpoint: "ldaps://keychain-selftest.invalid:636".into(),
        bind_dn: "cn=temporary-selftest".into(),
        ..Profile::default()
    };
    selftest_roundtrip(&credential(&profile)?)
}

fn selftest_roundtrip(entry: &keyring::Entry) -> Result<(), String> {
    let secret = zeroize::Zeroizing::new(uuid::Uuid::new_v4().to_string());
    entry
        .set_password(&secret)
        .map_err(|_| "Cannot create temporary native-store entry".to_string())?;
    let retrieved = entry.get_password().map(zeroize::Zeroizing::new);
    let removed = entry.delete_credential();
    removed.map_err(|_| "Temporary native-store entry cleanup failed".to_string())?;
    let retrieved =
        retrieved.map_err(|_| "Native-store read failed; temporary entry deleted".to_string())?;
    if *retrieved != *secret {
        return Err("Native-store roundtrip mismatch; temporary entry deleted".into());
    }
    if !matches!(entry.get_password(), Err(keyring::Error::NoEntry)) {
        return Err("Native store did not confirm deletion".into());
    }
    Ok(())
}

pub fn delete_saved_password(profile: &Profile) -> Result<bool, String> {
    credential_status()?;
    let account = credential_account(profile);
    let entry = keyring::Entry::new(CREDENTIAL_SERVICE, &account)
        .map_err(|_| CREDENTIALS_UNAVAILABLE.to_string())?;
    let removed = match entry.delete_credential() {
        Ok(()) => true,
        Err(keyring::Error::NoEntry) => false,
        Err(_) => {
            return Err(
                "Could not remove the saved password from the OS keychain (access denied or keychain locked)"
                    .to_string(),
            );
        }
    };
    match entry.get_password() {
        Err(keyring::Error::NoEntry) => Ok(removed),
        Ok(secret) => {
            let _ = zeroize::Zeroizing::new(secret);
            Err(
                "Saved password could not be removed from the OS keychain; entry is still present"
                    .into(),
            )
        }
        Err(_) => Err(
            "Could not verify saved password removal in the OS keychain (access denied or keychain locked)"
                .into(),
        ),
    }
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
    #[test]
    fn theme_and_password_saved_flag_persist_without_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("profiles.json");
        let profile = Profile {
            bind_dn: "uid=alice,dc=example,dc=org".into(),
            password_saved: true,
            ..Profile::default()
        };
        save_with_theme(&p, std::slice::from_ref(&profile), Some("dark")).unwrap();
        let loaded = load_config(&p).unwrap();
        assert_eq!(loaded.theme.as_deref(), Some("dark"));
        assert_eq!(loaded.profiles, vec![profile.clone()]);
        // Subsequent plain save preserves the existing theme preference.
        save(&p, std::slice::from_ref(&profile)).unwrap();
        assert_eq!(load_config(&p).unwrap().theme.as_deref(), Some("dark"));
    }
    #[test]
    fn keychain_selftest_roundtrips_and_leaves_nothing_behind() {
        keychain_selftest().unwrap();
        let existing = Profile::default();
        credential(&existing)
            .unwrap()
            .set_password("keep-me")
            .unwrap();
        keychain_selftest().unwrap();
        assert_eq!(
            saved_password(&Profile {
                password_saved: true,
                ..existing
            })
            .unwrap(),
            "keep-me"
        );
    }
    #[test]
    fn keychain_selftest_reports_failures_without_values() {
        credential_status().unwrap();
        let entry = credential(&Profile::default()).unwrap();
        let mock: &keyring::mock::Cred = entry.as_any().downcast_ref().unwrap();
        mock.set_error(keyring::Error::NoStorageAccess(Box::new(
            std::io::Error::other("keychain locked"),
        )));
        let error = selftest_roundtrip(&entry).unwrap_err();
        assert_eq!(error, "Cannot create temporary native-store entry");
    }
    #[test]
    fn mock_keyring_create_read_delete_and_missing_or_denied_errors() {
        credential_status().unwrap();
        let mut profile = Profile {
            bind_dn: "uid=alice,dc=example,dc=org".into(),
            password_saved: false,
            ..Profile::default()
        };
        assert_eq!(
            probe_saved_password(&profile),
            SavedCredentialState::Missing
        );
        assert_eq!(
            saved_password(&profile).unwrap_err(),
            "No saved password available; enter one to connect"
        );
        profile.password_saved = true;
        assert_eq!(
            saved_password(&profile).unwrap_err(),
            "Saved password was not found in the OS keychain; enter a password to connect"
        );
        let entry = credential(&profile).unwrap();
        entry.set_password("synthetic-keychain-secret").unwrap();
        assert_eq!(
            probe_saved_password(&profile),
            SavedCredentialState::Present
        );
        assert_eq!(
            saved_password(&profile).unwrap(),
            "synthetic-keychain-secret"
        );
        // Simulate locked/denied keychain on probe, read, and delete.
        let mock: &keyring::mock::Cred = entry.as_any().downcast_ref().unwrap();
        mock.set_error(keyring::Error::NoStorageAccess(Box::new(
            std::io::Error::other("keychain locked"),
        )));
        assert_eq!(
            probe_saved_password(&profile),
            SavedCredentialState::LockedOrDenied(KEYCHAIN_LOCKED_OR_DENIED)
        );
        mock.set_error(keyring::Error::NoStorageAccess(Box::new(
            std::io::Error::other("keychain locked"),
        )));
        assert!(
            saved_password(&profile)
                .unwrap_err()
                .contains("access denied or keychain locked")
        );
        mock.set_error(keyring::Error::NoStorageAccess(Box::new(
            std::io::Error::other("keychain locked"),
        )));
        assert_eq!(
            delete_saved_password(&profile).unwrap_err(),
            "Could not remove the saved password from the OS keychain (access denied or keychain locked)"
        );
        // Secret is still present because delete failed; after transient error clears,
        // deleting removes the credential (Ok(true)), and a second delete reports nothing to forget (Ok(false)).
        assert_eq!(
            saved_password(&profile).unwrap(),
            "synthetic-keychain-secret"
        );
        assert!(delete_saved_password(&profile).unwrap());
        assert!(!delete_saved_password(&profile).unwrap());
        assert_eq!(
            probe_saved_password(&profile),
            SavedCredentialState::Missing
        );
        assert!(
            saved_password(&profile)
                .unwrap_err()
                .contains("not found in the OS keychain")
        );
    }
}
