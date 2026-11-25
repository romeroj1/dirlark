//! Background release discovery and checksum-verified update staging.
use futures_util::StreamExt;
use serde::Deserialize;
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    process::Command,
    sync::mpsc,
    time::Duration,
};

const API: &str = "https://api.github.com/repos/romeroj1/dirlark/releases?per_page=10";
const MAX_ARCHIVE: usize = 150 * 1024 * 1024;
const MAX_EXPANDED: u64 = 500 * 1024 * 1024;
const MAX_ENTRIES: usize = 20_000;
const MAX_EXECUTABLE: u64 = 150 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    Checking,
    Current,
    Available {
        version: String,
        archive_url: String,
        sums_url: String,
        asset_name: String,
    },
    Downloading {
        version: String,
    },
    Ready {
        version: String,
        update: StagedUpdate,
    },
    Failed(String),
}

enum CommandMessage {
    Download,
    Restart(StagedUpdate),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedUpdate {
    launch_path: PathBuf,
    executable_path: PathBuf,
    executable_sha256: [u8; 32],
}

pub struct Updater {
    commands: tokio::sync::mpsc::UnboundedSender<CommandMessage>,
    states: mpsc::Receiver<State>,
    state: State,
}

#[derive(Deserialize)]
struct Release {
    draft: bool,
    prerelease: bool,
    tag_name: String,
    assets: Vec<Asset>,
}
#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

impl Updater {
    pub fn idle() -> Self {
        let (_tx, rx) = mpsc::channel();
        let (commands, _commands_rx) = tokio::sync::mpsc::unbounded_channel();
        Self {
            commands,
            states: rx,
            state: State::Current,
        }
    }
    pub fn start(ctx: eframe::egui::Context) -> Self {
        let (command_tx, command_rx) = tokio::sync::mpsc::unbounded_channel();
        let (state_tx, state_rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("dirlark-updater".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build();
                if let Ok(runtime) = runtime {
                    runtime.block_on(run(command_rx, state_tx, ctx));
                }
            })
            .ok();
        Self {
            commands: command_tx,
            states: state_rx,
            state: State::Checking,
        }
    }

    pub fn state(&self) -> &State {
        &self.state
    }
    pub fn download(&self) {
        let _ = self.commands.send(CommandMessage::Download);
    }
    pub fn restart(&self, update: StagedUpdate) {
        let _ = self.commands.send(CommandMessage::Restart(update));
    }
    pub fn poll(&mut self) {
        while let Ok(state) = self.states.try_recv() {
            self.state = state;
        }
    }
}

pub fn release_build_enabled() -> bool {
    let build = crate::build_info::current();
    release_identity_enabled(build.version, build.commit)
}

fn release_identity_enabled(version: &str, commit: &str) -> bool {
    commit != "dev" && semver::Version::parse(version).is_ok()
}

async fn run(
    mut commands: tokio::sync::mpsc::UnboundedReceiver<CommandMessage>,
    states: mpsc::Sender<State>,
    ctx: eframe::egui::Context,
) {
    let client = match reqwest::Client::builder()
        .user_agent(format!("DIRLARK/{}", crate::build_info::current().version))
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 5 || !trusted_redirect_url(attempt.url()) {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }))
        .build()
    {
        Ok(client) => client,
        Err(_) => {
            send_state(
                &states,
                &ctx,
                State::Failed("Update service unavailable".into()),
            );
            return;
        }
    };
    let mut available: Option<(String, String, String, String)> = None;
    let mut check = tokio::time::interval(Duration::from_secs(60 * 60 * 24));
    loop {
        tokio::select! {
            _ = check.tick() => {
                match latest_release(&client).await {
                    Ok(Some(found)) => {
                        available = Some(found.clone());
                        send_state(&states, &ctx, State::Available { version: found.0, archive_url: found.1, sums_url: found.2, asset_name: found.3 });
                    }
                    Ok(None) => { available = None; send_state(&states, &ctx, State::Current); }
                    Err(_) => send_state(&states, &ctx, State::Failed("Could not check for updates".into())),
                }
            }
            message = commands.recv() => match message {
                Some(CommandMessage::Download) => if let Some(found) = available.clone() {
                    let version = found.0.clone();
                    send_state(&states, &ctx, State::Downloading { version: version.clone() });
                    match stage_release(&client, &found).await {
                        Ok(update) => send_state(&states, &ctx, State::Ready { version, update }),
                        Err(_) => send_state(&states, &ctx, State::Failed("Update could not be verified or staged".into())),
                    }
                },
                Some(CommandMessage::Restart(update)) => {
                    // Relaunch only after an explicit user click on the ready pill.
                    if spawn_ready(&update).is_ok() {
                        std::process::exit(0);
                    }
                }
                None => return,
            }
        }
    }
}

fn send_state(states: &mpsc::Sender<State>, ctx: &eframe::egui::Context, state: State) {
    let _ = states.send(state);
    ctx.request_repaint();
}

async fn latest_release(
    client: &reqwest::Client,
) -> Result<Option<(String, String, String, String)>, ()> {
    let current = semver::Version::parse(crate::build_info::current().version).map_err(|_| ())?;
    let response = client
        .get(API)
        .send()
        .await
        .map_err(|_| ())?
        .error_for_status()
        .map_err(|_| ())?;
    let releases: Vec<Release> = response.json().await.map_err(|_| ())?;
    for release in releases.into_iter().filter(|r| !r.draft) {
        let tag = release
            .tag_name
            .strip_prefix('v')
            .unwrap_or(&release.tag_name);
        let Ok(version) = semver::Version::parse(tag) else {
            continue;
        };
        if version <= current || !release_channel_allows(&current, release.prerelease) {
            continue;
        }
        let Some(archive_name) = platform_archive(&release.tag_name) else {
            return Ok(None);
        };
        let archive = release.assets.iter().find(|a| a.name == archive_name);
        let sums = release.assets.iter().find(|a| a.name == "SHA256SUMS");
        if let (Some(archive), Some(sums)) = (archive, sums) {
            trusted_release_asset(
                &archive.browser_download_url,
                &release.tag_name,
                &archive.name,
            )?;
            trusted_release_asset(&sums.browser_download_url, &release.tag_name, &sums.name)?;
            return Ok(Some((
                release.tag_name,
                archive.browser_download_url.clone(),
                sums.browser_download_url.clone(),
                archive.name.clone(),
            )));
        }
    }
    Ok(None)
}

fn release_channel_allows(current: &semver::Version, release_is_prerelease: bool) -> bool {
    !current.pre.is_empty() || !release_is_prerelease
}

fn trusted_release_asset(value: &str, tag: &str, asset_name: &str) -> Result<(), ()> {
    let url = url::Url::parse(value).map_err(|_| ())?;
    if safe_component(tag).is_ok()
        && !asset_name.is_empty()
        && !asset_name.contains('/')
        && !asset_name.contains('\\')
        && asset_name != "."
        && asset_name != ".."
        && url.scheme() == "https"
        && url.host_str() == Some("github.com")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port_or_known_default() == Some(443)
        && url.query().is_none()
        && url.fragment().is_none()
    {
        let segments: Vec<_> = url.path_segments().ok_or(())?.collect();
        if segments.as_slice()
            == [
                "romeroj1", "dirlark", "releases", "download", tag, asset_name,
            ]
        {
            Ok(())
        } else {
            Err(())
        }
    } else {
        Err(())
    }
}

fn trusted_redirect_url(url: &url::Url) -> bool {
    const ALLOWED_HOSTS: &[&str] = &[
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
        "github-releases.githubusercontent.com",
    ];
    url.scheme() == "https"
        && url
            .host_str()
            .is_some_and(|host| ALLOWED_HOSTS.contains(&host))
        && url.username().is_empty()
        && url.password().is_none()
        && url.port_or_known_default() == Some(443)
}

fn platform_archive(tag: &str) -> Option<String> {
    let target = if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "aarch64-apple-darwin.zip"
    } else if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        "x86_64-pc-windows-msvc.zip"
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "x86_64-unknown-linux-gnu.tar.gz"
    } else {
        return None;
    };
    Some(format!("dirlark-{tag}-{target}"))
}

async fn read_bounded(response: reqwest::Response, cap: usize) -> Result<Vec<u8>, ()> {
    if response.content_length().is_some_and(|n| n > cap as u64) {
        return Err(());
    }
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ())?;
        if bytes.len().saturating_add(chunk.len()) > cap {
            return Err(());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn stage_release(
    client: &reqwest::Client,
    release: &(String, String, String, String),
) -> Result<StagedUpdate, ()> {
    let archive_response = client
        .get(&release.1)
        .send()
        .await
        .map_err(|_| ())?
        .error_for_status()
        .map_err(|_| ())?;
    let archive = read_bounded(archive_response, MAX_ARCHIVE).await?;
    let sums_response = client
        .get(&release.2)
        .send()
        .await
        .map_err(|_| ())?
        .error_for_status()
        .map_err(|_| ())?;
    let sums = read_bounded(sums_response, 64 * 1024).await?;
    let sums = std::str::from_utf8(&sums).map_err(|_| ())?;
    let expected = checksum_for(sums, &release.3).ok_or(())?;
    let actual = ring::digest::digest(&ring::digest::SHA256, &archive);
    let actual = actual
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    if !constant_time_eq(expected.as_bytes(), actual.as_bytes()) {
        return Err(());
    }

    let root = versions_root()?;
    let version_dir = root.join(safe_component(&release.0)?);
    fs::create_dir_all(&root).map_err(|_| ())?;
    fs::create_dir(&version_dir).map_err(|_| ())?;
    let result = if release.3.ends_with(".zip") {
        extract_zip(&archive, &version_dir)
    } else {
        extract_tar_gz(&archive, &version_dir)
    };
    let executables = match result {
        Ok(executables) => executables,
        Err(()) => {
            let _ = fs::remove_dir_all(&version_dir);
            return Err(());
        }
    };
    let executable_name = if cfg!(target_os = "windows") {
        "dirlark.exe"
    } else {
        "dirlark"
    };
    let Some(executable) = executables
        .into_iter()
        .find(|p| p.file_name().is_some_and(|n| n == executable_name))
    else {
        let _ = fs::remove_dir_all(&version_dir);
        return Err(());
    };
    let executable_sha256 = match sha256_file(&executable) {
        Ok(digest) => digest,
        Err(()) => {
            let _ = fs::remove_dir_all(&version_dir);
            return Err(());
        }
    };
    #[cfg(target_os = "macos")]
    let Some(launch_path) = executable
        .ancestors()
        .find(|path| path.file_name().is_some_and(|name| name == "DIRLARK.app"))
        .map(Path::to_path_buf)
    else {
        let _ = fs::remove_dir_all(&version_dir);
        return Err(());
    };
    #[cfg(not(target_os = "macos"))]
    let launch_path = executable.clone();
    Ok(StagedUpdate {
        launch_path,
        executable_path: executable,
        executable_sha256,
    })
}

fn versions_root() -> Result<PathBuf, ()> {
    Ok(directories::ProjectDirs::from("", "", "dirlark")
        .ok_or(())?
        .data_dir()
        .join("versions"))
}

fn sha256_file(path: &Path) -> Result<[u8; 32], ()> {
    let mut file = File::open(path).map_err(|_| ())?;
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = file.read(&mut buffer).map_err(|_| ())?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read as u64).ok_or(())?;
        if total > MAX_EXECUTABLE {
            return Err(());
        }
        context.update(&buffer[..read]);
    }
    context.finish().as_ref().try_into().map_err(|_| ())
}

fn validate_staged_paths(root: &Path, update: &StagedUpdate) -> Result<(PathBuf, PathBuf), ()> {
    let root = fs::canonicalize(root).map_err(|_| ())?;
    let launch = fs::canonicalize(&update.launch_path).map_err(|_| ())?;
    let executable = fs::canonicalize(&update.executable_path).map_err(|_| ())?;
    if !launch.starts_with(&root) || !executable.starts_with(&root) || !executable.is_file() {
        return Err(());
    }
    #[cfg(target_os = "macos")]
    if !launch.is_dir()
        || launch.file_name().is_none_or(|name| name != "DIRLARK.app")
        || !executable.starts_with(&launch)
        || executable.file_name().is_none_or(|name| name != "dirlark")
    {
        return Err(());
    }
    #[cfg(not(target_os = "macos"))]
    if launch != executable
        || executable.file_name().is_none_or(|name| {
            name != if cfg!(target_os = "windows") {
                "dirlark.exe"
            } else {
                "dirlark"
            }
        })
    {
        return Err(());
    }
    Ok((launch, executable))
}

#[allow(dead_code)]
fn staged_binary_matches(path: &Path, expected: &[u8; 32]) -> bool {
    sha256_file(path).is_ok_and(|actual| constant_time_eq(&actual, expected))
}

fn checksum_for(manifest: &str, filename: &str) -> Option<String> {
    manifest.lines().find_map(|line| {
        let (hash, name) = line.split_once("  ")?;
        (name == filename && hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| hash.to_ascii_lowercase())
    })
}
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
}
fn safe_component(value: &str) -> Result<&str, ()> {
    let version = value.strip_prefix('v').unwrap_or(value);
    if value.is_empty() || value.len() > 80 || semver::Version::parse(version).is_err() {
        Err(())
    } else {
        Ok(value)
    }
}
fn safe_relative(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path
            .to_string_lossy()
            .chars()
            .any(|ch| ch == '\\' || ch == ':')
        && path.components().all(|c| matches!(c, Component::Normal(_)))
}

fn extract_zip(bytes: &[u8], root: &Path) -> Result<Vec<PathBuf>, ()> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).map_err(|_| ())?;
    if archive.len() > MAX_ENTRIES {
        return Err(());
    }
    archive.validate_header_consistency().map_err(|_| ())?;
    let mut total = 0u64;
    let mut executables = Vec::new();
    for index in 0..archive.len() {
        let mut member = archive.by_index(index).map_err(|_| ())?;
        let relative = member.enclosed_name().ok_or(())?.to_path_buf();
        let member_name = member.name().map_err(|_| ())?;
        if !safe_relative(&relative) || member_name.contains('\\') {
            return Err(());
        }
        if member
            .unix_mode()
            .is_some_and(|mode| !matches!(mode & 0o170000, 0 | 0o100000 | 0o040000))
        {
            return Err(());
        }
        total = total.checked_add(member.size()).ok_or(())?;
        if total > MAX_EXPANDED {
            return Err(());
        }
        let destination = root.join(relative);
        if member.is_dir() {
            fs::create_dir_all(&destination).map_err(|_| ())?;
            continue;
        }
        let parent = destination.parent().ok_or(())?;
        fs::create_dir_all(parent).map_err(|_| ())?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)
            .map_err(|_| ())?;
        std::io::copy(&mut member, &mut file).map_err(|_| ())?;
        file.flush().map_err(|_| ())?;
        if member.unix_mode().is_some_and(|mode| mode & 0o111 != 0) {
            set_executable(&destination)?;
        }
        if destination
            .file_name()
            .is_some_and(|n| n == "dirlark" || n == "dirlark.exe")
        {
            executables.push(destination);
        }
    }
    Ok(executables)
}

fn extract_tar_gz(bytes: &[u8], root: &Path) -> Result<Vec<PathBuf>, ()> {
    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);
    let entries = archive.entries().map_err(|_| ())?;
    let mut total = 0u64;
    let mut count = 0usize;
    let mut executables = Vec::new();
    for entry in entries {
        let mut entry = entry.map_err(|_| ())?;
        count += 1;
        if count > MAX_ENTRIES {
            return Err(());
        }
        let relative = entry.path().map_err(|_| ())?.into_owned();
        if !safe_relative(&relative)
            || !(entry.header().entry_type().is_file() || entry.header().entry_type().is_dir())
        {
            return Err(());
        }
        if entry.header().entry_type().is_dir() {
            fs::create_dir_all(root.join(relative)).map_err(|_| ())?;
            continue;
        }
        let size = entry.header().size().map_err(|_| ())?;
        total = total.checked_add(size).ok_or(())?;
        if total > MAX_EXPANDED {
            return Err(());
        }
        let destination = root.join(relative);
        fs::create_dir_all(destination.parent().ok_or(())?).map_err(|_| ())?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)
            .map_err(|_| ())?;
        std::io::copy(&mut entry, &mut file).map_err(|_| ())?;
        if entry.header().mode().unwrap_or(0) & 0o111 != 0 {
            set_executable(&destination)?;
        }
        if destination
            .file_name()
            .is_some_and(|n| n == "dirlark" || n == "dirlark.exe")
        {
            executables.push(destination);
        }
    }
    Ok(executables)
}

fn set_executable(_path: &Path) -> Result<(), ()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut p = fs::metadata(_path).map_err(|_| ())?.permissions();
        p.set_mode(p.mode() | 0o100);
        fs::set_permissions(_path, p).map_err(|_| ())?;
    }
    Ok(())
}

pub fn spawn_ready(update: &StagedUpdate) -> Result<(), String> {
    let root = versions_root().map_err(|_| "Could not locate staged update".to_owned())?;
    let (launch, executable) = validate_staged_paths(&root, update)
        .map_err(|_| "Staged update path is no longer valid".to_owned())?;
    if !staged_binary_matches(&executable, &update.executable_sha256) {
        return Err("Staged update executable changed after verification".into());
    }
    #[cfg(target_os = "macos")]
    let result = Command::new("/usr/bin/open").arg("-n").arg(launch).spawn();
    #[cfg(not(target_os = "macos"))]
    let result = Command::new(launch).spawn();
    result
        .map(|_| ())
        .map_err(|_| "Could not start staged update".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[test]
    fn checksum_requires_exact_filename_and_digest_shape() {
        assert_eq!(
            checksum_for(&format!("{}  app.zip\n", "a".repeat(64)), "app.zip"),
            Some("a".repeat(64))
        );
        assert_eq!(
            checksum_for(&format!("{}  other.zip\n", "a".repeat(64)), "app.zip"),
            None
        );
        assert_eq!(checksum_for("short  app.zip\n", "app.zip"), None);
    }
    #[test]
    fn rejects_unsafe_version_and_archive_paths() {
        assert!(safe_component("v0.1.0-alpha.6").is_ok());
        assert!(safe_component("../escape").is_err());
        assert!(!safe_relative(Path::new("../escape")));
        assert!(!safe_relative(Path::new("/absolute")));
        assert!(safe_relative(Path::new("release/dirlark")));
    }
    #[test]
    fn release_asset_requires_exact_repository_tag_and_asset_path() {
        let url =
            "https://github.com/romeroj1/dirlark/releases/download/v0.1.0-alpha.6/dirlark.zip";
        assert!(trusted_release_asset(url, "v0.1.0-alpha.6", "dirlark.zip").is_ok());
        for (url, tag, asset) in [
            (
                "http://github.com/romeroj1/dirlark/releases/download/v1.0.0/app.zip",
                "v1.0.0",
                "app.zip",
            ),
            (
                "https://github.com/attacker/dirlark/releases/download/v1.0.0/app.zip",
                "v1.0.0",
                "app.zip",
            ),
            (
                "https://github.com/romeroj1/dirlark/releases/download/v1.0.0/other.zip",
                "v1.0.0",
                "app.zip",
            ),
            (
                "https://github.com/romeroj1/dirlark/releases/download/v1.0.0/app.zip?x=1",
                "v1.0.0",
                "app.zip",
            ),
            (
                "https://github.com/romeroj1/dirlark/releases/download/v1.0.0/extra/app.zip",
                "v1.0.0",
                "app.zip",
            ),
        ] {
            assert!(trusted_release_asset(url, tag, asset).is_err(), "{url}");
        }
    }

    #[test]
    fn redirects_allow_only_https_github_asset_hosts() {
        for host in [
            "github.com",
            "objects.githubusercontent.com",
            "release-assets.githubusercontent.com",
            "github-releases.githubusercontent.com",
        ] {
            assert!(trusted_redirect_url(
                &url::Url::parse(&format!("https://{host}/asset")).unwrap()
            ));
        }
        for value in [
            "http://github.com/asset",
            "https://github.com.evil.test/asset",
            "https://attacker.test/asset",
            "https://user@github.com/asset",
            "https://github.com:444/asset",
        ] {
            assert!(
                !trusted_redirect_url(&url::Url::parse(value).unwrap()),
                "{value}"
            );
        }
    }

    #[test]
    fn prerelease_channel_policy_and_release_build_gate() {
        let stable = semver::Version::parse("1.2.0").unwrap();
        let alpha = semver::Version::parse("1.2.0-alpha.1").unwrap();
        assert!(!release_channel_allows(&stable, true));
        assert!(release_channel_allows(&stable, false));
        assert!(release_channel_allows(&alpha, true));
        assert!(release_channel_allows(&alpha, false));
        assert!(release_identity_enabled("1.2.0", "abc123"));
        assert!(!release_identity_enabled("1.2.0", "dev"));
        assert!(!release_identity_enabled("unknown", "abc123"));
    }

    #[test]
    fn staged_update_paths_and_executable_digest_are_revalidated() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("versions");
        let version_dir = root.join("v1.2.3");
        fs::create_dir_all(&version_dir).unwrap();
        #[cfg(target_os = "macos")]
        let (launch_path, executable) = {
            let app = version_dir.join("DIRLARK.app");
            let executable = app.join("Contents/MacOS/dirlark");
            fs::create_dir_all(executable.parent().unwrap()).unwrap();
            (app, executable)
        };
        #[cfg(not(target_os = "macos"))]
        let executable = version_dir.join(if cfg!(target_os = "windows") {
            "dirlark.exe"
        } else {
            "dirlark"
        });
        fs::write(&executable, b"verified executable").unwrap();
        let update = StagedUpdate {
            launch_path: {
                #[cfg(target_os = "macos")]
                {
                    launch_path
                }
                #[cfg(not(target_os = "macos"))]
                {
                    executable.clone()
                }
            },
            executable_path: executable.clone(),
            executable_sha256: sha256_file(&executable).unwrap(),
        };
        assert!(validate_staged_paths(&root, &update).is_ok());
        assert!(staged_binary_matches(
            &executable,
            &update.executable_sha256
        ));
        let outside = temp.path().join("outside");
        fs::write(&outside, b"outside").unwrap();
        let escaped = StagedUpdate {
            launch_path: outside.clone(),
            executable_path: outside.clone(),
            executable_sha256: sha256_file(&outside).unwrap(),
        };
        assert!(validate_staged_paths(&root, &escaped).is_err());
        fs::write(&executable, b"tampered executable").unwrap();
        assert!(!staged_binary_matches(
            &executable,
            &update.executable_sha256
        ));
    }
}
