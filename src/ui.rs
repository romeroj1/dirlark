mod about;
mod certificate_view;
#[cfg(debug_assertions)]
pub mod evidence;
mod output;
mod theme;
use crate::{
    directory::{Request, Response, Worker},
    ldif::{self, AttributeChange, Change},
    model::{
        CREDENTIAL_ATTRIBUTES, Entry, Profile, credential_attribute, equality_filter,
        protected_attribute, smart_filter, valid_attribute,
    },
    page_cache::{Key, PageCache},
    paging::{Cursor, Mode, Query},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use eframe::egui;
use std::{
    collections::{BTreeSet, VecDeque},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use zeroize::Zeroizing;

pub struct Workspace {
    #[cfg(debug_assertions)]
    evidence_readonly: bool,
    worker: Worker,
    generation: u64,
    busy: bool,
    connected: bool,
    appearance: egui::ThemePreference,
    about_open: bool,
    include_credentials: bool,
    profiles: Vec<Profile>,
    profile: Profile,
    path: Option<PathBuf>,
    password: Zeroizing<String>,
    remember: bool,
    connecting_saves_or_uses_keychain: bool,
    credential_locked_notice: Option<String>,
    confirm_delete_profile: bool,
    delete_profile_credential: bool,
    credential_storage: Result<(), String>,
    roots: Vec<String>,
    tree_focus_requested: Option<usize>,
    pages: PageCache,
    release: Vec<Cursor>,
    active_page: Option<(Key, Arc<AtomicBool>)>,
    page_size: u16,
    sort: String,
    ordering_rule: String,
    seek_position: u32,
    selected: Option<Entry>,
    pending_read: Option<String>,
    certificate_viewer: Option<certificate_view::Viewer>,
    attributes_height: f32,
    base: String,
    filter: String,
    attrs: String,
    scope: usize,
    query_details: bool,
    quick_search: String,
    last_quick_filter: String,
    builder_attr: String,
    builder_value: String,
    tab: usize,
    attribute: String,
    value: String,
    binary: bool,
    remove_attribute: bool,
    pending: Vec<Change>,
    expected: Option<Entry>,
    preview: bool,
    destructive_confirmed: bool,
    transfer: String,
    file: String,
    schema: Vec<Entry>,
    schema_filter: String,
    status: String,
    logs: VecDeque<String>,
    smoke: Option<crate::smoke::SmokeCapture>,
    connection_screen_visible: bool,
    #[cfg(test)]
    rendered_rows: (usize, usize),
}
impl Workspace {
    pub fn new(cc: &eframe::CreationContext<'_>, smoke: bool) -> Self {
        let path = directories::ProjectDirs::from("io.github", "romeroj1", "Dirlark-Public")
            .map(|p| p.config_dir().join("profiles.json"));
        let mut app = Self::from_path(cc.egui_ctx.clone(), path, None, smoke);
        if cfg!(target_os = "linux") {
            app.send(Request::CredentialStatus);
        }
        app
    }
    fn from_path(
        ctx: egui::Context,
        path: Option<PathBuf>,
        legacy: Option<PathBuf>,
        smoke: bool,
    ) -> Self {
        theme::install(&ctx);
        let loaded = path
            .as_ref()
            .map(|p| crate::profiles::load_config_with_legacy(p, legacy.as_deref()))
            .unwrap_or_else(|| Err("No local config directory available".into()));
        let status = loaded
            .as_ref()
            .err()
            .cloned()
            .unwrap_or_else(|| "Choose a profile and connect over verified LDAPS".into());
        let path = if loaded.is_err() { None } else { path };
        let config = loaded.unwrap_or_default();
        let appearance = match config.theme.as_deref() {
            Some("dark") => {
                ctx.set_theme(egui::ThemePreference::Dark);
                egui::ThemePreference::Dark
            }
            Some("light") => {
                ctx.set_theme(egui::ThemePreference::Light);
                egui::ThemePreference::Light
            }
            _ => ctx.options(|o| o.theme_preference),
        };
        let mut profiles = config.profiles;
        let mut flags_changed = false;
        let mut locked_notice: Option<String> = None;
        if !smoke {
            for p in &mut profiles {
                if p.bind_dn.is_empty() {
                    if p.password_saved {
                        p.password_saved = false;
                        flags_changed = true;
                    }
                    continue;
                }
                match crate::profiles::probe_saved_password(p) {
                    crate::profiles::SavedCredentialState::Present => {
                        if !p.password_saved {
                            p.password_saved = true;
                            flags_changed = true;
                        }
                    }
                    crate::profiles::SavedCredentialState::Missing => {
                        if p.password_saved {
                            p.password_saved = false;
                            flags_changed = true;
                        }
                    }
                    crate::profiles::SavedCredentialState::LockedOrDenied(msg) => {
                        if !p.password_saved {
                            p.password_saved = true;
                            flags_changed = true;
                        }
                        if locked_notice.is_none() {
                            locked_notice = Some(msg.to_string());
                        }
                    }
                    crate::profiles::SavedCredentialState::StoreUnavailable(_) => {}
                }
            }
            if flags_changed
                && let Some(p) = path.as_ref()
                && p.try_exists().unwrap_or(false)
            {
                let _ = crate::profiles::save_with_theme(p, &profiles, config.theme.as_deref());
            }
        }
        let profile = profiles.first().cloned().unwrap_or_default();
        let remember = !profile.bind_dn.is_empty() && profile.password_saved;
        let mut logs = VecDeque::new();
        let status = if let Some(msg) = &locked_notice {
            logs.push_back(msg.clone());
            msg.clone()
        } else {
            status
        };
        Self {
            #[cfg(debug_assertions)]
            evidence_readonly: false,
            worker: Worker::start(ctx),
            generation: 0,
            busy: false,
            connected: false,
            appearance,
            about_open: false,
            include_credentials: false,
            profiles,
            base: profile.base_dn.clone(),
            profile,
            path,
            password: Zeroizing::new(String::new()),
            remember,
            connecting_saves_or_uses_keychain: false,
            credential_locked_notice: locked_notice,
            confirm_delete_profile: false,
            delete_profile_credential: true,
            credential_storage: Ok(()),
            roots: vec![],
            tree_focus_requested: None,
            pages: PageCache::default(),
            release: vec![],
            active_page: None,
            page_size: 100,
            sort: "cn".into(),
            ordering_rule: String::new(),
            seek_position: 1,
            selected: None,
            pending_read: None,
            certificate_viewer: None,
            attributes_height: DEFAULT_ATTRIBUTES_HEIGHT,
            filter: "(objectClass=*)".into(),
            attrs: "*".into(),
            scope: 2,
            query_details: false,
            quick_search: String::new(),
            last_quick_filter: String::new(),
            builder_attr: "cn".into(),
            builder_value: String::new(),
            tab: 0,
            attribute: String::new(),
            value: String::new(),
            binary: false,
            remove_attribute: false,
            pending: vec![],
            expected: None,
            preview: false,
            destructive_confirmed: false,
            transfer: String::new(),
            file: String::new(),
            schema: vec![],
            schema_filter: String::new(),
            status,
            logs,
            smoke: smoke.then(crate::smoke::SmokeCapture::new),
            connection_screen_visible: false,
            #[cfg(test)]
            rendered_rows: (0, 0),
        }
    }
    fn note(&mut self, message: String) {
        self.status = message.clone();
        self.logs.push_back(message);
        while self.logs.len() > 100 {
            self.logs.pop_front();
        }
    }
    fn send(&mut self, request: Request) {
        #[cfg(debug_assertions)]
        if self.evidence_readonly {
            self.note("Read-only visual fixture: no operations dispatched".into());
            return;
        }
        if let Request::Apply { changes, .. } = &request
            && changes.iter().any(|c| matches!(c, Change::Delete(_)))
            && !self.destructive_confirmed
        {
            self.note("Explicitly confirm entry deletion before applying".into());
            return;
        }
        if matches!(request, Request::Read(_)) && !self.pending.is_empty() {
            self.note("Discard the write preview before opening another entry".into());
            return;
        }
        if self.busy {
            self.note("Wait for the current operation".into());
            return;
        }
        let reading = if let Request::Read(dn) = &request {
            Some(dn.clone())
        } else {
            None
        };
        match self.worker.sender.try_send((self.generation, request)) {
            Ok(()) => {
                self.busy = true;
                self.pending_read = reading;
            }
            Err(_) => self.note("Background worker unavailable or queue full".into()),
        }
    }
    fn cancel_page(&mut self) {
        if let Some((key, token)) = self.active_page.take() {
            token.store(true, Ordering::Release);
            // Abandon can invalidate a forward cookie; never retry it after cancellation.
            self.pages.remove(&key);
            self.generation += 1;
            self.busy = false;
            self.note("Search cancelled; restart the query to continue".into());
        }
    }
    fn page_request(
        &mut self,
        key: Key,
        query: Query,
        size: u16,
        cursor: Option<Cursor>,
        seek: Option<u32>,
        reset: bool,
    ) {
        if self.busy {
            return;
        }
        if reset && let Some(cursor) = self.pages.remove(&key) {
            self.release.push(cursor);
        }
        let token = Arc::new(AtomicBool::new(false));
        let release = std::mem::take(&mut self.release);
        self.send(Request::Page {
            key: key.clone(),
            query,
            size,
            cursor: cursor.map(Box::new),
            seek,
            reset,
            cancelled: token.clone(),
            release,
        });
        if self.busy {
            self.active_page = Some((key, token));
        }
    }
    fn more(&mut self, key: Key, seek: Option<u32>) {
        if let Some(cached) = self.pages.get(&key) {
            let (query, size, cursor) = (cached.query.clone(), cached.size, cached.next.clone());
            self.page_request(key, query, size, cursor, seek, seek.is_some());
        }
    }
    fn load_children(&mut self, dn: String) {
        self.page_request(
            Key::Children(dn.clone()),
            Query {
                base: dn,
                scope: 1,
                filter: "(objectClass=*)".into(),
                attrs: vec!["numSubordinates".into()],
                sort: self.sort.clone(),
                ordering_rule: self.ordering_rule.clone(),
            },
            self.page_size,
            None,
            None,
            true,
        );
    }
    fn clear_data(&mut self) {
        if let Some((_, token)) = self.active_page.take() {
            token.store(true, Ordering::Release);
        }
        self.release.clear();
        self.roots.clear();
        self.tree_focus_requested = None;
        self.pages.clear();
        self.selected = None;
        self.pending_read = None;
        self.certificate_viewer = None;
        self.schema.clear();
        self.pending.clear();
        self.expected = None;
        self.transfer.clear();
        self.include_credentials = false;
        self.preview = false;
        self.destructive_confirmed = false;
        self.connected = false;
    }
    fn poll(&mut self) {
        if !self.release.is_empty() && !self.busy {
            let release = std::mem::take(&mut self.release);
            if let Err(std::sync::mpsc::TrySendError::Full((_, Request::CloseCursors(cursors)))) =
                self.worker
                    .sender
                    .try_send((self.generation, Request::CloseCursors(release)))
            {
                self.release = cursors;
            }
        }
        while let Ok((generation, response)) = self.worker.receiver.try_recv() {
            self.accept_response(generation, response);
        }
    }
    fn accept_response(&mut self, generation: u64, response: Response) {
        if generation != self.generation {
            return;
        }
        if matches!(response, Response::Closed) {
            return;
        }
        self.busy = false;
        let active = self.active_page.take();
        match response {
            Response::CredentialStatus(status) => {
                if let Err(message) = &status {
                    self.remember = false;
                    self.note(message.clone());
                }
                self.credential_storage = status;
            }
            Response::Connected(roots) => {
                self.connected = true;
                if self.base.trim().is_empty()
                    && let Some(first) = roots.first()
                {
                    self.base = first.clone();
                }
                self.roots = roots;
                let used_or_saved_keychain = self.connecting_saves_or_uses_keychain
                    || (!self.profile.bind_dn.is_empty()
                        && self.password.is_empty()
                        && matches!(
                            crate::profiles::probe_saved_password(&self.profile),
                            crate::profiles::SavedCredentialState::Present
                                | crate::profiles::SavedCredentialState::LockedOrDenied(_)
                        ));
                if used_or_saved_keychain && !self.profile.bind_dn.is_empty() {
                    self.profile.password_saved = true;
                    self.remember = true;
                    self.credential_locked_notice = None;
                    if let Some(saved) = self.profiles.iter_mut().find(|p| {
                        p.id == self.profile.id
                            && p.endpoint == self.profile.endpoint
                            && p.bind_dn == self.profile.bind_dn
                    }) {
                        saved.password_saved = true;
                        if let Some(path) = &self.path {
                            let _ = crate::profiles::save_with_theme(
                                path,
                                &self.profiles,
                                theme_name(self.appearance).as_deref(),
                            );
                        }
                    }
                }
                self.connecting_saves_or_uses_keychain = false;
                self.note("Connected · TLS certificate and hostname verified".into());
            }
            Response::Disconnected => {
                self.clear_data();
                self.note("Disconnected".into());
            }
            Response::Closed => {}
            Response::Page(key, query, size, page, reset) => {
                let count = page.entries.len();
                let mode = page.mode;
                let total = page.total;
                let has_more = page.next.is_some();
                let warning = page.warning.clone();
                self.release
                    .extend(self.pages.insert(key.clone(), query, size, *page, reset));
                let cached_rows = self.pages.entries(&key).len();
                let evicted = self.pages.get(&key).is_some_and(|q| q.evicted);
                self.note(warning.unwrap_or_else(|| {
                    if has_more {
                        format!(
                            "Fetched {count} rows ({cached_rows} cached) · {mode:?}{}{}",
                            total
                                .map(|n| format!(" · server VLV count {n}"))
                                .unwrap_or_default(),
                            if evicted {
                                " · earlier pages evicted"
                            } else {
                                ""
                            }
                        )
                    } else {
                        format!(
                            "End of results · {cached_rows} rows ({count} in final page) · {mode:?}{}{}",
                            total
                                .map(|n| format!(" · server VLV count {n}"))
                                .unwrap_or_default(),
                            if evicted {
                                " · earlier pages evicted"
                            } else {
                                ""
                            }
                        )
                    }
                }));
            }
            Response::Read(entry) => {
                self.pending_read = None;
                self.certificate_viewer = None;
                if self.base.trim().is_empty() && !entry.dn.is_empty() {
                    self.base = entry.dn.clone();
                }
                self.selected = Some(entry);
                self.attribute.clear();
                self.value.clear();
                self.pending.clear();
                self.preview = false;
                self.tab = 0;
                self.note("Entry loaded".into());
            }
            Response::Schema(entries) => {
                self.schema = entries;
                self.note("Schema loaded".into());
            }
            Response::Applied(count) => {
                let deleted = self.selected.as_ref().is_some_and(|e| {
                    self.pending
                        .iter()
                        .any(|c| matches!(c,Change::Delete(dn) if dn==&e.dn))
                });
                if deleted {
                    self.selected = None;
                    self.pages.clear();
                }
                self.pending.clear();
                self.expected = None;
                self.preview = false;
                self.note(format!(
                    "Applied {count} records; reload to inspect server values"
                ));
                if let Some(e) = &self.selected {
                    self.send(Request::Read(e.dn.clone()));
                }
            }
            Response::Saved => {
                self.note("Profile settings saved; no passwords written to config".into())
            }
            Response::PasswordForgotten { id, removed } => {
                if self.profile.id == id {
                    self.profile.password_saved = false;
                    self.remember = false;
                    self.credential_locked_notice = None;
                }
                for p in &mut self.profiles {
                    if p.id == id {
                        p.password_saved = false;
                    }
                }
                self.note(
                    if removed {
                        "Saved password removed from OS keychain"
                    } else {
                        "Nothing to forget: no saved password was found in the OS keychain"
                    }
                    .into(),
                );
            }
            Response::ProfileDeleted {
                id,
                removed_credential,
            } => {
                self.profiles.retain(|p| p.id != id);
                self.confirm_delete_profile = false;
                if self.profile.id == id {
                    let next = self.profiles.first().cloned().unwrap_or_default();
                    self.select_profile(next);
                }
                self.note(
                    if removed_credential {
                        "Profile deleted and saved password removed from OS keychain"
                    } else {
                        "Profile deleted"
                    }
                    .into(),
                );
            }
            Response::Error(message) => {
                self.connecting_saves_or_uses_keychain = false;
                if message.contains("not found in the OS keychain") {
                    self.profile.password_saved = false;
                    self.remember = false;
                    self.credential_locked_notice = None;
                    if let Some(saved) = self.profiles.iter_mut().find(|p| p.id == self.profile.id)
                    {
                        saved.password_saved = false;
                        if let Some(path) = &self.path {
                            let _ = crate::profiles::save_with_theme(
                                path,
                                &self.profiles,
                                theme_name(self.appearance).as_deref(),
                            );
                        }
                    }
                } else if message.contains("access denied or keychain locked") {
                    self.credential_locked_notice = Some(message.clone());
                }
                if let Some((key, _)) = active {
                    self.pages.invalidate(
                        &key,
                        format!("{message}. Continuation closed; restart to continue"),
                    );
                }
                self.note(message);
            }
        }
    }
    fn saved_profile(&self) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.id == self.profile.id)
    }
    fn credential_target_profile(&self) -> Profile {
        self.saved_profile()
            .cloned()
            .unwrap_or_else(|| self.profile.clone())
    }
    fn select_profile(&mut self, mut profile: Profile) {
        self.credential_locked_notice = None;
        if self.smoke.is_none() && !profile.bind_dn.is_empty() {
            match crate::profiles::probe_saved_password(&profile) {
                crate::profiles::SavedCredentialState::Present => {
                    profile.password_saved = true;
                }
                crate::profiles::SavedCredentialState::Missing => {
                    profile.password_saved = false;
                }
                crate::profiles::SavedCredentialState::LockedOrDenied(msg) => {
                    profile.password_saved = true;
                    self.credential_locked_notice = Some(msg.to_string());
                    self.note(msg.into());
                }
                crate::profiles::SavedCredentialState::StoreUnavailable(_) => {}
            }
            if let Some(saved) = self.profiles.iter_mut().find(|p| {
                p.id == profile.id && p.endpoint == profile.endpoint && p.bind_dn == profile.bind_dn
            }) && saved.password_saved != profile.password_saved
            {
                saved.password_saved = profile.password_saved;
                if let Some(path) = &self.path
                    && path.try_exists().unwrap_or(false)
                {
                    let _ = crate::profiles::save_with_theme(
                        path,
                        &self.profiles,
                        theme_name(self.appearance).as_deref(),
                    );
                }
            }
        } else if profile.bind_dn.is_empty() {
            profile.password_saved = false;
        }
        self.remember = !profile.bind_dn.is_empty()
            && profile.password_saved
            && self.credential_storage.is_ok();
        self.base = profile.base_dn.clone();
        self.profile = profile;
        self.password = Zeroizing::new(String::new());
        self.confirm_delete_profile = false;
        self.delete_profile_credential = true;
    }
    fn connect(&mut self) {
        if self.connected || self.busy {
            return;
        }
        self.generation += 1;
        self.clear_data();
        self.base = self.profile.base_dn.clone();
        self.connecting_saves_or_uses_keychain =
            !self.profile.bind_dn.is_empty() && (self.remember || self.password.is_empty());
        let password = std::mem::replace(&mut self.password, Zeroizing::new(String::new()));
        self.send(Request::Connect(
            self.profile.clone(),
            password,
            self.remember,
        ));
    }
    fn disconnect(&mut self) {
        if !self.connected || self.busy {
            return;
        }
        self.generation += 1;
        self.clear_data();
        self.password = Zeroizing::new(String::new());
        self.send(Request::Disconnect);
    }
    fn save_profile(&mut self) {
        if let Err(e) = self.profile.validate() {
            self.note(e);
        } else if let Some(path) = self.path.clone() {
            if self.smoke.is_none() {
                if self.profile.bind_dn.is_empty() {
                    self.profile.password_saved = false;
                } else {
                    match crate::profiles::probe_saved_password(&self.profile) {
                        crate::profiles::SavedCredentialState::Present
                        | crate::profiles::SavedCredentialState::LockedOrDenied(_) => {
                            self.profile.password_saved = true;
                        }
                        crate::profiles::SavedCredentialState::Missing => {
                            self.profile.password_saved = false;
                        }
                        crate::profiles::SavedCredentialState::StoreUnavailable(_) => {}
                    }
                }
            }
            let mut profiles = self.profiles.clone();
            profiles.retain(|p| p.id != self.profile.id);
            profiles.push(self.profile.clone());
            self.send(Request::SaveProfiles(
                path,
                profiles.clone(),
                theme_name(self.appearance),
            ));
            self.profiles = profiles;
        } else {
            self.note("Profile file unavailable; original data is preserved".into());
        }
    }
    fn forget_password(&mut self) {
        if self.busy {
            return;
        }
        let target = self.credential_target_profile();
        let mut profiles = self.profiles.clone();
        for p in &mut profiles {
            if p.id == target.id {
                p.password_saved = false;
            }
        }
        let save = self
            .path
            .clone()
            .map(|path| (path, profiles, theme_name(self.appearance)));
        self.send(Request::ForgetPassword(target, save));
    }
    fn delete_profile(&mut self, remove_credential: bool) {
        if self.connected || self.busy {
            return;
        }
        let target = self.credential_target_profile();
        let mut profiles = self.profiles.clone();
        profiles.retain(|p| p.id != target.id);
        let save = self
            .path
            .clone()
            .map(|path| (path, profiles, theme_name(self.appearance)));
        self.send(Request::DeleteProfile {
            profile: target,
            remove_credential: remove_credential && self.credential_storage.is_ok(),
            save,
        });
    }
    fn has_unsaved_profile_edits(&self) -> bool {
        match self.profiles.iter().find(|p| p.id == self.profile.id) {
            Some(saved) => saved != &self.profile,
            None => {
                self.profile
                    != Profile {
                        id: self.profile.id,
                        ..Profile::default()
                    }
            }
        }
    }
    fn connection_fields(&mut self, ui: &mut egui::Ui) {
        // Enter in a connection field submits, like a login form. Profile name is excluded.
        let mut submit = false;
        let mut forget = false;
        let prev_endpoint = self.profile.endpoint.clone();
        let prev_bind_dn = self.profile.bind_dn.clone();
        ui.add_enabled_ui(!self.busy, |ui| {
            field(ui, "Profile name", &mut self.profile.name);
        });
        let target = self.credential_target_profile();
        let has_saved_password = (!target.bind_dn.is_empty() && target.password_saved)
            || (!self.profile.bind_dn.is_empty() && self.profile.password_saved);
        ui.add_enabled_ui(!self.connected && !self.busy, |ui| {
            let mut fields = vec![field_response(
                ui,
                "LDAPS endpoint",
                &mut self.profile.endpoint,
            )];
            fields.push(field_response(
                ui,
                "Base DN (blank discovers roots)",
                &mut self.profile.base_dn,
            ));
            fields.push(field_response(
                ui,
                "Bind DN (blank = anonymous)",
                &mut self.profile.bind_dn,
            ));
            if (self.profile.endpoint != prev_endpoint || self.profile.bind_dn != prev_bind_dn)
                && self.profile.bind_dn.is_empty()
            {
                self.remember = false;
            }
            let form_uses_saved_password = !self.profile.bind_dn.is_empty()
                && ((target.password_saved
                    && self.profile.endpoint == target.endpoint
                    && self.profile.bind_dn == target.bind_dn)
                    || (self.saved_profile().is_none() && self.profile.password_saved));
            let password_label = if form_uses_saved_password {
                "Password (saved password will be used)"
            } else {
                "Password (blank uses saved credential)"
            };
            let label = ui.label(
                egui::RichText::new(password_label)
                    .small()
                    .color(theme::colors(ui).muted),
            );
            fields.push(
                ui.add(
                    egui::TextEdit::singleline(&mut *self.password)
                        .id(egui::Id::unique("connection-password"))
                        .password(true)
                        .hint_text(if form_uses_saved_password {
                            "Saved password will be used"
                        } else {
                            ""
                        })
                        .desired_width(f32::INFINITY),
                )
                .labelled_by(label.id),
            );
            submit = fields.iter().any(|response| {
                response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter))
            });
            ui.add_enabled_ui(self.credential_storage.is_ok(), |ui| {
                ui.checkbox(&mut self.remember, "Save password in OS keychain");
            });
        });
        ui.horizontal_wrapped(|ui| {
            if has_saved_password {
                let indicator = if self.credential_locked_notice.is_some() {
                    "🔒 Password saved in keychain (unavailable: locked or access denied)"
                } else {
                    "🔒 Password saved in keychain"
                };
                ui.label(
                    egui::RichText::new(indicator)
                        .small()
                        .color(theme::colors(ui).accent)
                        .strong(),
                );
                if ui
                    .add_enabled(
                        !self.busy && self.credential_storage.is_ok(),
                        egui::Button::new("Forget saved password"),
                    )
                    .clicked()
                {
                    forget = true;
                }
            } else {
                ui.label(
                    egui::RichText::new("No saved password")
                        .small()
                        .color(theme::colors(ui).muted),
                );
            }
        });
        ui.add_enabled_ui(!self.connected && !self.busy, |ui| {
            if let Err(message) = &self.credential_storage {
                ui.scope(|ui| {
                    theme::note(
                        ui,
                        "Session-only password",
                        "OS keychain unavailable. Use a session password. No plaintext fallback.",
                        true,
                    );
                })
                .response
                .on_hover_text(message);
            }
            ui.collapsing("TLS trust · extra CA bundle", |ui| {
                field_with_hint(
                    ui,
                    "Extra CA bundle PEM path",
                    "Full path or ~/… (for example ~/certs/ca.pem)",
                    &mut self.profile.ca_bundle,
                );
            });
            ui.label(
                egui::RichText::new("System roots + selected CA. TLS verification is mandatory.")
                    .small()
                    .color(theme::colors(ui).muted),
            );
        });
        if forget {
            self.forget_password();
        } else if submit {
            self.connect();
        }
    }
    fn profile_form(&mut self, ui: &mut egui::Ui) {
        let compact = ui.ctx().content_rect().height() < 600.0;
        let heading = ui.label(egui::RichText::new("Connection").size(16.0).strong());
        self.connection_screen_visible = ui.is_rect_visible(heading.rect);
        let mut choice = None;
        ui.horizontal(|ui| {
            ui.add_enabled_ui(!self.connected && !self.busy, |ui| {
                egui::ComboBox::from_id_salt("saved-servers")
                    .width((ui.available_width() - 65.0).max(100.0))
                    .selected_text(&self.profile.name)
                    .show_ui(ui, |ui| {
                        for p in &self.profiles {
                            if ui
                                .selectable_label(p.id == self.profile.id, &p.name)
                                .clicked()
                            {
                                choice = Some(p.clone());
                            }
                        }
                    })
                    .response
                    .on_hover_text("Saved server profiles. Disconnect before switching.");
                if ui
                    .button("New")
                    .on_hover_text("New server profile")
                    .clicked()
                {
                    choice = Some(Profile::default());
                }
            });
        });
        if let Some(p) = choice {
            self.select_profile(p);
        }
        if self.connected {
            if compact {
                ui.horizontal_wrapped(|ui| {
                    ui.label(egui::RichText::new("TLS verified").color(theme::colors(ui).accent))
                        .on_hover_text(format!(
                            "{}\nIdentity: {}",
                            self.profile.endpoint,
                            if self.profile.bind_dn.is_empty() {
                                "Anonymous"
                            } else {
                                &self.profile.bind_dn
                            }
                        ));
                    if ui
                        .add_enabled(!self.busy, egui::Button::new("Disconnect"))
                        .clicked()
                    {
                        self.disconnect();
                    }
                });
            } else {
                ui.label(
                    egui::RichText::new("TLS verified")
                        .color(theme::colors(ui).accent)
                        .strong(),
                );
                ui.add(
                    egui::Label::new(egui::RichText::new(&self.profile.endpoint).monospace())
                        .truncate(),
                )
                .on_hover_text(&self.profile.endpoint);
                let identity = if self.profile.bind_dn.is_empty() {
                    "Anonymous"
                } else {
                    &self.profile.bind_dn
                };
                ui.add(egui::Label::new(identity).truncate())
                    .on_hover_text(identity);
                if ui
                    .add_enabled(!self.busy, egui::Button::new("Disconnect"))
                    .clicked()
                {
                    self.disconnect();
                }
            }
            let settings = ui.collapsing("Connection settings", |ui| {
                ui.small("Disconnect before changing server or identity.");
                egui::ScrollArea::vertical()
                    .id_salt("connection-settings")
                    .max_height(210.0)
                    .show(ui, |ui| self.connection_fields(ui));
                if self.has_unsaved_profile_edits() {
                    ui.small("Unsaved profile edits — click Save profile to keep changes across restarts.");
                }
                if ui
                    .add_enabled(!self.busy, egui::Button::new("Save profile"))
                    .clicked()
                {
                    self.save_profile();
                }
            });
            if settings.body_returned.is_none() {
                if self.has_unsaved_profile_edits() {
                    ui.small("Unsaved profile edits — click Save profile to keep changes across restarts.");
                }
                if ui
                    .add_enabled(!self.busy, egui::Button::new("Save profile"))
                    .clicked()
                {
                    self.save_profile();
                }
            }
        } else {
            egui::ScrollArea::vertical()
                .id_salt("connection-fields")
                .max_height((ui.available_height() - 185.0).max(100.0))
                .show(ui, |ui| self.connection_fields(ui));
            ui.add_space(4.0);
            if self.has_unsaved_profile_edits() {
                ui.small(
                    "Unsaved profile edits — click Save profile to keep changes across restarts.",
                );
            }
            let is_saved_profile = self.profiles.iter().any(|p| p.id == self.profile.id);
            ui.horizontal_wrapped(|ui| {
                let connect = theme::primary(ui, "Connect", !self.busy);
                self.connection_screen_visible &= ui.is_rect_visible(connect.rect);
                if connect.clicked() {
                    self.connect();
                }
                if ui
                    .add_enabled(!self.busy, egui::Button::new("Save profile"))
                    .clicked()
                {
                    self.save_profile();
                }
                if is_saved_profile
                    && ui
                        .add_enabled(!self.busy, egui::Button::new("Delete profile"))
                        .clicked()
                {
                    self.confirm_delete_profile = true;
                    self.delete_profile_credential = true;
                }
            });
            if self.confirm_delete_profile && is_saved_profile {
                ui.add_space(4.0);
                let has_target_bind_dn = !self.credential_target_profile().bind_dn.is_empty();
                ui.add_enabled_ui(!self.busy, |ui| {
                    if has_target_bind_dn && self.credential_storage.is_ok() {
                        ui.checkbox(
                            &mut self.delete_profile_credential,
                            "Also remove saved password from OS keychain",
                        );
                    }
                    ui.horizontal_wrapped(|ui| {
                        if ui.button("Confirm delete profile").clicked() {
                            self.delete_profile(self.delete_profile_credential);
                        }
                        if ui.button("Cancel").clicked() {
                            self.confirm_delete_profile = false;
                        }
                    });
                });
            }
        }
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(4.0);
        ui.label(egui::RichText::new("Directory").size(16.0).strong());
        ui.horizontal(|ui| {
            ui.small("Rows per page");
            ui.add_enabled(
                !self.busy,
                egui::DragValue::new(&mut self.page_size).range(25..=500),
            );
        });
        if !self.connected {
            ui.small("Connect to discover naming contexts. Anonymous access needs no bind DN.");
        } else if !compact {
            ui.small("Expand a branch to fetch its children. Cached pages stay bounded.");
        }
        let rows = tree_rows(&self.roots, &self.pages);
        let mut action = None;
        let mut touched = vec![];
        ui.scope(|ui| {
            ui.spacing_mut().interact_size.y = 24.0;
            ui.spacing_mut().button_padding.y = 2.0;
            ui.spacing_mut().item_spacing.y = 2.0;
            let mut scroll = egui::ScrollArea::both().id_salt("tree-scroll");
            if let Some(index) = self.tree_focus_requested {
                scroll = scroll.vertical_scroll_offset(index as f32 * 26.0);
            }
            scroll.show_rows(ui, 24.0, rows.len(), |ui, visible| {
                for index in visible {
                    #[cfg(test)]
                    {
                        self.rendered_rows.1 += 1;
                    }
                    let row = &rows[index];
                    if let Some((key, offset)) = &row.source {
                        touched.push((key.clone(), *offset));
                    }
                    ui.horizontal(|ui| {
                        ui.set_min_height(24.0);
                        ui.add_space(row.depth as f32 * 12.0);
                        match &row.kind {
                            TreeKind::Node(dn, count) => {
                                let loaded = self.pages.contains(&Key::Children(dn.clone()));
                                let toggle = ui.add_enabled(
                                    !self.busy,
                                    egui::Button::new("")
                                        .min_size(egui::vec2(22.0, 24.0))
                                        .frame(false),
                                );
                                toggle.widget_info(|| {
                                    egui::WidgetInfo::labeled(
                                        egui::Role::Button,
                                        !self.busy,
                                        format!(
                                            "{} children of {dn}",
                                            if loaded { "Collapse" } else { "Expand" }
                                        ),
                                    )
                                });
                                let mut icon = toggle.clone();
                                icon.rect = toggle.rect.shrink(6.0);
                                egui::collapsing_header::paint_default_icon(
                                    ui,
                                    if loaded { 1.0 } else { 0.0 },
                                    &icon,
                                );
                                if toggle
                                    .on_hover_text("Expand lazily or collapse cached children")
                                    .clicked()
                                {
                                    action = Some(TreeAction::Toggle(dn.clone(), loaded));
                                }
                                let label = count
                                    .map(|n| format!("{} · {n} children", rdn_label(dn)))
                                    .unwrap_or_else(|| rdn_label(dn).to_string());
                                let response = ui
                                    .push_id(("tree-node", dn), |ui| {
                                        ui.add(
                                            egui::Button::selectable(
                                                self.pending_read.as_deref().or_else(|| {
                                                    self.selected.as_ref().map(|e| e.dn.as_str())
                                                }) == Some(dn.as_str()),
                                                label,
                                            )
                                            .truncate(),
                                        )
                                    })
                                    .inner
                                    .on_hover_text(dn);
                                if self
                                    .pending_read
                                    .as_deref()
                                    .or_else(|| self.selected.as_ref().map(|e| e.dn.as_str()))
                                    == Some(dn.as_str())
                                {
                                    let p = theme::colors(ui);
                                    ui.painter().rect_filled(
                                        egui::Rect::from_min_size(
                                            response.rect.min,
                                            egui::vec2(3.0, response.rect.height()),
                                        ),
                                        0.0,
                                        p.accent,
                                    );
                                }
                                if response.has_focus() {
                                    ui.painter().rect_stroke(
                                        response.rect.expand(2.0),
                                        2.0,
                                        egui::Stroke::new(1.0, theme::colors(ui).accent),
                                        egui::StrokeKind::Inside,
                                    );
                                }
                                if self.tree_focus_requested == Some(index) {
                                    response.request_focus();
                                    self.tree_focus_requested = None;
                                }
                                if response.clicked() {
                                    action = Some(TreeAction::Read(dn.clone()));
                                }
                                if response.has_focus() && !self.busy {
                                    let key = ui.input_mut(|i| {
                                        [
                                            egui::Key::ArrowUp,
                                            egui::Key::ArrowDown,
                                            egui::Key::ArrowLeft,
                                            egui::Key::ArrowRight,
                                        ]
                                        .into_iter()
                                        .find(|key| i.consume_key(egui::Modifiers::NONE, *key))
                                    });
                                    match key {
                                        Some(egui::Key::ArrowRight) if !loaded => {
                                            action = Some(TreeAction::Toggle(dn.clone(), false))
                                        }
                                        Some(egui::Key::ArrowLeft) if loaded => {
                                            action = Some(TreeAction::Toggle(dn.clone(), true))
                                        }
                                        Some(key) => {
                                            self.tree_focus_requested =
                                                tree_neighbor(&rows, index, key);
                                            ui.ctx().request_repaint();
                                        }
                                        None => {}
                                    }
                                }
                            }
                            TreeKind::More(parent) => {
                                if ui
                                    .add_enabled(
                                        !self.busy,
                                        egui::Button::new("Load more children…"),
                                    )
                                    .clicked()
                                {
                                    action = Some(TreeAction::More(parent.clone()));
                                }
                            }
                            TreeKind::Notice(message) => {
                                ui.add(egui::Label::new(message).truncate())
                                    .on_hover_text(message);
                            }
                        }
                    });
                }
            });
        });
        for (key, offset) in touched {
            self.pages.touch(&key, offset);
        }
        match action {
            Some(TreeAction::Toggle(dn, true)) => {
                if let Some(cursor) = self.pages.remove(&Key::Children(dn)) {
                    self.release.push(cursor);
                }
            }
            Some(TreeAction::Toggle(dn, false)) => self.load_children(dn),
            Some(TreeAction::Read(dn)) => self.send(Request::Read(dn)),
            Some(TreeAction::More(dn)) => self.more(Key::Children(dn), None),
            None => {}
        }
    }
    fn entry_view(&mut self, ui: &mut egui::Ui) {
        if let Some(dn) = &self.pending_read {
            ui.heading(rdn_label(dn));
            output::show(ui, "Distinguished name", dn);
            if self.busy {
                ui.spinner();
                ui.label("Loading entry attributes…");
            } else {
                ui.label("Entry details could not be loaded. Select the entry again to retry.");
            }
            return;
        }
        let Some(entry) = self.selected.clone() else {
            ui.add_space(34.0);
            ui.heading(if self.connected {
                "Choose an entry"
            } else {
                "Your directory, clearly organized"
            });
            ui.add_space(8.0);
            ui.label(if self.connected { "Expand a branch on the left, or search for an entry. Children are fetched only when you ask." } else { "Choose a saved server or enter a verified LDAPS endpoint. Leave the bind DN blank for anonymous access." });
            ui.add_space(12.0);
            if self.connected && theme::primary(ui, "Search directory", true).clicked() {
                self.tab = 1;
            }
            ui.small("Directory writes always require a separate review and explicit Apply.");
            return;
        };
        ui.heading(format!(
            "{} · {}",
            if entry.dn.to_ascii_lowercase().starts_with("ou=") {
                "OU"
            } else {
                "Entry"
            },
            rdn_label(&entry.dn)
        ));
        ui.horizontal(|ui| {
            let width = (ui.available_width() - 80.0).max(80.0);
            ui.add_sized(
                [width, 26.0],
                egui::Label::new(egui::RichText::new(&entry.dn).monospace()).truncate(),
            )
            .on_hover_text(&entry.dn);
            if ui.button("Copy DN").clicked() {
                ui.ctx().copy_text(entry.dn.clone());
            }
        });
        ui.horizontal_wrapped(|ui| {
            ui.small(format!(
                "{} attributes · credential values stay hidden",
                entry.attrs.len()
            ));
            let certificates = crate::certificates::user_certificate_count(&entry);
            if certificates > 0 {
                ui.strong(format!("Certs: {certificates}")).on_hover_text("Number of userCertificate values, including attribute options. Decoding does not verify trust.");
            }
            if ui
                .add_enabled(
                    !self.busy,
                    egui::Button::new("Reload entry / discard draft"),
                )
                .clicked()
            {
                self.pending.clear();
                self.expected = None;
                self.preview = false;
                self.send(Request::Read(entry.dn.clone()));
            }
        });
        if !entry.attrs.keys().any(|name| !credential_attribute(name)) {
            ui.label(if self.profile.bind_dn.is_empty() {"No readable attributes for this entry. Anonymous access only exposes public attributes; log on or pick another entry."} else {"No readable attributes for this entry. Your current directory identity has no readable attributes; log on with another identity or pick another entry."});
        }
        if !entry
            .attrs
            .keys()
            .any(|name| crate::certificates::kind(name).is_some())
        {
            ui.small("No certificates on this entry");
        }
        ui.add_space(6.0);
        let name_width = (ui.available_width() * 0.27).clamp(100.0, 260.0);
        let value_width = (ui.available_width() - name_width - 36.0).max(100.0);
        let remaining = ui.available_height();
        let upper = split_height(self.attributes_height, remaining);
        egui::ScrollArea::vertical()
            .id_salt("entry-attributes")
            .auto_shrink([false, false])
            .max_height(upper)
            .show(ui, |ui| {
                egui::Grid::new("attributes")
                    .striped(true)
                    .num_columns(2)
                    .spacing([16.0, 8.0])
                    .show(ui, |ui| {
                        for (name, values) in &entry.attrs {
                            ui.vertical(|ui| {
                                ui.set_width(name_width);
                                ui.label(egui::RichText::new(name).monospace().color(theme::colors(ui).muted));
                                ui.small(format!("{} {}", values.len(), if values.len() == 1 {"value"} else {"values"}));
                            });
                            ui.vertical(|ui| {
                                ui.set_width(value_width);
                                for (index, value) in values.iter().enumerate() {
                                    if !credential_attribute(name) && crate::certificates::kind(name).is_some() {
                                        ui.push_id((name,index), |ui| {
                                            ui.horizontal_wrapped(|ui| {
                                                ui.label(format!("Value {} of {} · {} bytes",index+1,values.len(),value.len()));
                                                if ui.button("View certificate").clicked() {self.certificate_viewer=certificate_view::Viewer::new(&entry,name,index);}
                                            });
                                            ui.collapsing("Raw value · base64", |ui| {
                                                if value.len() <= crate::certificates::MAX_VALUE { output::show(ui,"DER / container · base64",&STANDARD.encode(value)); }
                                                else {ui.label("Value too large for preview; use LDIF export.");}
                                            });
                                        });
                                    } else if credential_attribute(name) {
                                        ui.label("[credential value hidden]");
                                    } else {
                                        let text = display(value);
                                        ui.horizontal_wrapped(|ui| {
                                            ui.add(egui::Label::new(&text).wrap());
                                            if ui
                                                .small_button("Copy")
                                                .on_hover_text(format!("Copy {name} value"))
                                                .clicked()
                                            {
                                                ui.ctx().copy_text(text.clone());
                                            }
                                        });
                                    }
                                }
                            });
                            ui.end_row();
                        }
                    });
            });
        attributes_splitter(ui, &mut self.attributes_height, remaining);
        egui::ScrollArea::vertical()
            .id_salt("entry-draft")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.label(
                    egui::RichText::new("Draft attribute change")
                        .size(16.0)
                        .strong(),
                );
                ui.small("This entry only. Preview first; nothing is written until you Apply.");
                field(ui, "Attribute name", &mut self.attribute);
                ui.label("Values (one per line)");
                ui.add(
                    egui::TextEdit::multiline(&mut self.value)
                        .desired_rows(3)
                        .desired_width(f32::INFINITY),
                );
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.binary, "Values are base64");
                    ui.checkbox(&mut self.remove_attribute, "Delete entire attribute");
                });
                if ui
                    .add_enabled(
                        !self.busy,
                        egui::Button::new(
                            egui::RichText::new("Preview change")
                                .color(theme::colors(ui).on_accent),
                        )
                        .fill(theme::colors(ui).accent),
                    )
                    .clicked()
                {
                    if !valid_attribute(&self.attribute) || protected_attribute(&self.attribute) {
                        self.note("Choose an editable attribute description".into());
                    } else {
                        let values = if self.binary {
                            self.value
                                .lines()
                                .map(|v| STANDARD.decode(v).map_err(|_| "Invalid base64 value"))
                                .collect::<Result<Vec<_>, _>>()
                        } else {
                            Ok(self.value.lines().map(|s| s.as_bytes().to_vec()).collect())
                        };
                        match values {
                            Err(e) => self.note(e.into()),
                            Ok(values) => {
                                let change = if self.remove_attribute {
                                    AttributeChange::Delete(self.attribute.clone(), vec![])
                                } else {
                                    AttributeChange::Replace(self.attribute.clone(), values)
                                };
                                self.pending = vec![Change::Modify {
                                    dn: entry.dn.clone(),
                                    changes: vec![change],
                                }];
                                self.expected = Some(entry.clone());
                                self.preview = true;
                                self.destructive_confirmed = false;
                            }
                        }
                    }
                }
                if ui
                    .add_enabled(
                        !self.busy,
                        egui::Button::new(
                            egui::RichText::new("Preview entry deletion")
                                .color(theme::colors(ui).error),
                        ),
                    )
                    .clicked()
                {
                    self.pending = vec![Change::Delete(entry.dn.clone())];
                    self.expected = Some(entry.clone());
                    self.preview = true;
                    self.destructive_confirmed = false;
                }
            });
    }
    fn filter_is_unmodified_or_generated(&self) -> bool {
        self.filter.trim().is_empty()
            || self.filter == "(objectClass=*)"
            || (!self.last_quick_filter.is_empty() && self.filter == self.last_quick_filter)
    }
    fn sync_quick_search_filter(&mut self) {
        if self.filter_is_unmodified_or_generated()
            && let Ok(filter) = smart_filter(&self.quick_search)
        {
            self.last_quick_filter = filter.clone();
            self.filter = filter;
        }
    }
    fn apply_quick_search_filter(&mut self) -> bool {
        match smart_filter(&self.quick_search) {
            Ok(filter) => {
                self.last_quick_filter = filter.clone();
                self.filter = filter;
                true
            }
            Err(message) => {
                self.note(message);
                false
            }
        }
    }
    fn run_search(&mut self) {
        if !self.connected || self.busy {
            return;
        }
        if !self.quick_search.trim().is_empty() && self.filter_is_unmodified_or_generated() {
            match smart_filter(&self.quick_search) {
                Ok(filter) => {
                    self.last_quick_filter = filter.clone();
                    self.filter = filter;
                }
                Err(message) => {
                    self.note(message);
                    return;
                }
            }
        }
        if self.base.trim().is_empty() {
            if let Some(selected) = &self.selected
                && !selected.dn.is_empty()
            {
                self.base = selected.dn.clone();
            } else if let Some(first) = self.roots.first()
                && !first.is_empty()
            {
                self.base = first.clone();
            }
        }
        if self.base.trim().is_empty() {
            self.note(
                "Cannot run search: choose a search base DN first (for example a naming context from the directory tree)"
                    .into(),
            );
            return;
        }
        let query = Query {
            base: self.base.clone(),
            scope: self.scope as u8,
            filter: self.filter.clone(),
            attrs: self
                .attrs
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
            sort: self.sort.clone(),
            ordering_rule: self.ordering_rule.clone(),
        };
        self.page_request(Key::Search, query, self.page_size, None, None, true);
    }
    fn search_controls(&mut self, ui: &mut egui::Ui, run: bool) {
        ui.horizontal_wrapped(|ui| {
            ui.label("Quick search · plain text (uid/cn/mail) or (LDAP filter)");
            let input = ui.add(
                egui::TextEdit::singleline(&mut self.quick_search)
                    .hint_text("Plain text (alice) or (uid=alice*)")
                    .desired_width(260.0),
            );
            if input.changed() {
                self.sync_quick_search_filter();
            }
            let enter_pressed = input.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if (ui.button("Use smart filter").clicked() || enter_pressed)
                && self.apply_quick_search_filter()
                && enter_pressed
                && self.connected
                && !self.busy
            {
                self.run_search();
            }
        });
        if ui.available_width() > 640.0 {
            ui.columns(2, |columns| {
                field_with_hint(
                    &mut columns[0],
                    "Search base DN",
                    "dc=example,dc=org",
                    &mut self.base,
                );
                field(&mut columns[1], "LDAP filter", &mut self.filter);
            });
        } else {
            field_with_hint(ui, "Search base DN", "dc=example,dc=org", &mut self.base);
            field(ui, "LDAP filter", &mut self.filter);
        }
        ui.collapsing(
            "Advanced · attributes, filter builder and server sorting",
            |ui| {
                field(ui, "Attributes (comma separated)", &mut self.attrs);
                ui.collapsing("Build an equality or presence filter", |ui| {
                    field(ui, "Attribute", &mut self.builder_attr);
                    field(ui, "Exact value", &mut self.builder_value);
                    ui.horizontal(|ui| {
                        if ui.button("Use equality").clicked() {
                            match equality_filter(&self.builder_attr, &self.builder_value) {
                                Ok(f) => self.filter = f,
                                Err(e) => self.note(e),
                            }
                        }
                        if ui.button("Use presence").clicked()
                            && valid_attribute(&self.builder_attr)
                        {
                            self.filter = format!("({}=*)", self.builder_attr);
                        }
                    });
                });
                field(ui, "Server sort attribute (VLV)", &mut self.sort);
                field(
                    ui,
                    "Ordering rule OID (optional, VLV)",
                    &mut self.ordering_rule,
                );
            },
        );
        ui.horizontal_wrapped(|ui| {
            ui.small("Scope");
            for (index, name) in ["Base", "Children", "Subtree"].iter().enumerate() {
                ui.radio_value(&mut self.scope, index, *name);
            }
            ui.add_space(8.0);
            ui.small("Rows per page");
            ui.add(egui::DragValue::new(&mut self.page_size).range(25..=500));
            if run && theme::primary(ui, "Run search", self.connected && !self.busy).clicked() {
                self.run_search();
            }
        });
    }
    fn search_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("Search directory");
        let compact = ui.ctx().content_rect().height() < 600.0;
        if compact {
            ui.horizontal_wrapped(|ui| {
                ui.toggle_value(&mut self.query_details, "Edit query");
                if theme::primary(ui, "Run search", self.connected && !self.busy).clicked() {
                    self.run_search();
                }
            });
            if self.query_details {
                egui::ScrollArea::vertical()
                    .id_salt("compact-query")
                    .max_height((ui.available_height() * 0.45).max(80.0))
                    .show(ui, |ui| self.search_controls(ui, false));
            } else {
                ui.add(egui::Label::new(egui::RichText::new(&self.filter).monospace()).truncate())
                    .on_hover_text(format!("Base: {}\nFilter: {}", self.base, self.filter));
            }
        } else {
            self.search_controls(ui, true);
        }
        let cached = self.pages.get(&Key::Search);
        let completed = cached.is_some();
        let has_more = cached.is_some_and(|q| q.next.is_some());
        let vlv = cached.is_some_and(|q| q.mode == Mode::Vlv);
        if let Some(q) = cached {
            ui.label(format!(
                "{} · {} cached rows{}{}",
                page_mode(q.mode),
                self.pages.entries(&Key::Search).len(),
                q.total
                    .map(|n| format!(" · server VLV count {n}"))
                    .unwrap_or_default(),
                if q.next.is_none() && q.warning.is_none() {
                    " · all results loaded"
                } else {
                    ""
                }
            ));
            if q.evicted {
                ui.label("Earlier pages evicted to keep memory bounded. Use VLV position or restart a forward-only query to revisit them.");
            }
            if let Some(warning) = &q.warning {
                theme::note(ui, "Results incomplete", warning, true);
            }
        }
        if vlv {
            ui.horizontal(|ui| {
                ui.add_enabled(
                    vlv,
                    egui::DragValue::new(&mut self.seek_position)
                        .range(1..=i32::MAX as u32)
                        .prefix("VLV position "),
                );
                if ui
                    .add_enabled(vlv && !self.busy, egui::Button::new("Go to position"))
                    .clicked()
                {
                    self.more(Key::Search, Some(self.seek_position));
                }
            });
        }
        if !compact {
            ui.small("Only requested pages are fetched. The total is unknown unless the server supplies it. Form edits apply on Run search.");
        }
        ui.horizontal(|ui| {
            let width = (ui.available_width() * 0.72).max(100.0);
            ui.allocate_ui_with_layout(
                egui::vec2(width, 20.0),
                egui::Layout::left_to_right(egui::Align::Center),
                |ui| {
                    ui.set_min_width(width);
                    ui.strong("Distinguished name");
                },
            );
            ui.add(egui::Label::new(egui::RichText::new("Common name").strong()).truncate())
                .on_hover_text("Common name · shown if cn was requested");
        });
        let entries = self.pages.entries(&Key::Search);
        if entries.is_empty() {
            ui.add_space(18.0);
            ui.strong(if completed {
                "No matching entries"
            } else {
                "Ready when you are"
            });
            ui.label(if completed{"Check the base, scope and filter, or confirm that this identity has search access. A zero-row page does not prove the directory is empty."}else{"Define a base and filter, then Run search. No subtree is downloaded in advance."});
        }
        let mut open = None;
        let mut load_more = false;
        let mut touched = vec![];
        ui.scope(|ui| {
            ui.spacing_mut().interact_size.y = 24.0;
            ui.spacing_mut().button_padding.y = 2.0;
            ui.spacing_mut().item_spacing.y = 2.0;
            egui::ScrollArea::vertical()
                .id_salt("paged-results")
                .show_rows(
                    ui,
                    24.0,
                    entries.len() + usize::from(has_more),
                    |ui, visible| {
                        for index in visible {
                            #[cfg(test)]
                            {
                                self.rendered_rows.0 += 1;
                            }
                            if let Some((offset, entry)) = entries.get(index) {
                                touched.push(*offset);
                                ui.horizontal(|ui| {
                                    let width = (ui.available_width() * 0.72).max(100.0);
                                    let response = ui
                                        .add_sized(
                                            [width, 24.0],
                                            egui::Button::selectable(
                                                self.selected
                                                    .as_ref()
                                                    .is_some_and(|e| e.dn == entry.dn),
                                                "",
                                            )
                                            .left_text(egui::RichText::new(&entry.dn).monospace())
                                            .truncate(),
                                        )
                                        .on_hover_text(&entry.dn);
                                    if response.clicked() {
                                        open = Some(entry.dn.clone());
                                    }
                                    response.context_menu(|ui| {
                                        if ui.button("Copy distinguished name").clicked() {
                                            ui.ctx().copy_text(entry.dn.clone());
                                            ui.close();
                                        }
                                    });
                                    let common_name = entry
                                        .attrs
                                        .iter()
                                        .find(|(name, _)| name.eq_ignore_ascii_case("cn"))
                                        .and_then(|(_, v)| v.first())
                                        .map(|v| std::str::from_utf8(v).unwrap_or("[binary]"))
                                        .unwrap_or("—");
                                    ui.add(egui::Label::new(common_name).truncate())
                                        .on_hover_text(common_name);
                                });
                            } else if ui
                                .add_enabled(
                                    !self.busy,
                                    egui::Button::new("Load more results…")
                                        .min_size(egui::vec2(0.0, 24.0)),
                                )
                                .clicked()
                            {
                                load_more = true;
                            }
                        }
                    },
                );
        });
        for offset in touched {
            self.pages.touch(&Key::Search, offset);
        }
        if let Some(dn) = open {
            self.send(Request::Read(dn));
        }
        if load_more {
            self.more(Key::Search, None);
        }
    }
    fn schema_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("Schema definitions");
        if ui
            .add_enabled(
                self.connected && !self.busy,
                egui::Button::new("Discover and load schema"),
            )
            .clicked()
        {
            self.send(Request::Schema(self.base.clone()));
        }
        field(ui, "Find definition", &mut self.schema_filter);
        let needle = self.schema_filter.to_ascii_lowercase();
        egui::ScrollArea::vertical().show(ui, |ui| {
            for e in &self.schema {
                for (kind, values) in &e.attrs {
                    ui.collapsing(kind, |ui| {
                        for v in values {
                            let text = String::from_utf8_lossy(v);
                            if text.to_ascii_lowercase().contains(&needle) {
                                ui.label(text);
                                ui.separator();
                            }
                        }
                    });
                }
            }
        });
    }
    fn stage_import(&mut self) {
        match ldif::parse(&self.transfer) {
            Ok(changes) if !changes.is_empty() && changes.len() <= 250 => {
                self.pending = changes;
                self.expected = None;
                self.preview = true;
                self.destructive_confirmed = false;
            }
            Ok(_) => self.note("Import requires 1 to 250 records; split larger imports".into()),
            Err(e) => self.note(e),
        }
    }
    fn set_credential_export(&mut self, include: bool) {
        if self.include_credentials && !include {
            self.transfer.clear();
            self.note(
                "Sensitive export disabled; draft cleared. Export again to create a safe draft."
                    .into(),
            );
        }
        self.include_credentials = include;
    }
    fn export_entries(&self, entries: &[Entry]) -> String {
        ldif::export_with_credentials(entries, self.include_credentials)
    }
    fn load_ldif_file(&mut self) {
        let path = match crate::model::expand_local_path(&self.file) {
            Ok(path) => path,
            Err(message) => {
                self.note(message);
                return;
            }
        };
        let meta = match std::fs::metadata(&path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.note(
                    "Cannot read LDIF file: file not found; check the path (for example ~/Downloads/entries.ldif)"
                        .into(),
                );
                return;
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                self.note("Cannot read LDIF file: permission denied".into());
                return;
            }
            Err(_) => {
                self.note("Cannot read LDIF file; check the file path and permissions".into());
                return;
            }
        };
        if meta.is_dir() {
            self.note("Cannot read LDIF file: path is a directory, not a file".into());
            return;
        }
        if meta.len() > 16 * 1024 * 1024 {
            self.note("Cannot read LDIF file: file exceeds the 16 MiB maximum".into());
            return;
        }
        match std::fs::read_to_string(&path) {
            Ok(s) => {
                self.transfer = s;
                self.pending.clear();
                self.preview = false;
                self.note("LDIF file loaded into draft".into());
            }
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                self.note("Cannot read LDIF file: file is not valid UTF-8".into());
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                self.note("Cannot read LDIF file: permission denied".into());
            }
            Err(_) => self.note("Cannot read LDIF file (UTF-8, maximum 16 MiB)".into()),
        }
    }
    fn save_ldif_file(&mut self) {
        use std::io::Write;
        let path = match crate::model::expand_local_path(&self.file) {
            Ok(path) => path,
            Err(message) => {
                self.note(message);
                return;
            }
        };
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options
            .open(&path)
            .and_then(|mut f| f.write_all(self.transfer.as_bytes()))
        {
            Ok(()) => self.note("LDIF saved to new file".into()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                self.note(
                    "Cannot create file: file already exists (existing files are never overwritten)"
                        .into(),
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.note(
                    "Cannot create file: parent folder does not exist; check the file path".into(),
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                self.note("Cannot create file: permission denied (folder is not writable)".into());
            }
            Err(_) => self.note(
                "Cannot create file; enter a full file path in a writable folder (existing files are never overwritten)"
                    .into(),
            ),
        }
    }
    fn transfer_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("LDIF transfer");
        ui.label("Search export includes only currently cached rows; unfetched or evicted pages are excluded.");
        ui.label("Paste content/add, modify, or delete records. Preview performs no LDAP writes.");
        let mut include = self.include_credentials;
        ui.checkbox(
            &mut include,
            "Include credential attributes in exports (sensitive)",
        )
        .on_hover_text(CREDENTIAL_ATTRIBUTES.join(", "));
        self.set_credential_export(include);
        if self.include_credentials {
            theme::note(
                ui,
                "Sensitive export enabled",
                "Exported LDIF can include password hashes and directory key material. Keep it private. The attribute inspector and write preview still hide these values.",
                true,
            );
        }
        field_with_hint(
            ui,
            "Local LDIF file path",
            "Full path or ~/… (for example ~/Downloads/export.ldif)",
            &mut self.file,
        );
        ui.horizontal(|ui| {
            if ui.button("Load file").clicked() {
                self.load_ldif_file();
            }
            if ui.button("Export selected entry into draft").clicked()
                && let Some(e) = &self.selected
            {
                self.transfer = self.export_entries(std::slice::from_ref(e));
            }
            if ui.button("Export cached search rows into draft").clicked() {
                self.transfer = self.export_entries(
                    &self
                        .pages
                        .entries(&Key::Search)
                        .into_iter()
                        .map(|(_, e)| e.clone())
                        .collect::<Vec<_>>(),
                );
            }
        });
        ui.add(
            egui::TextEdit::multiline(&mut self.transfer)
                .code_editor()
                .desired_rows(16)
                .desired_width(f32::INFINITY),
        );
        ui.horizontal(|ui| {
            if ui.button("Save draft as new file").clicked() {
                self.save_ldif_file();
            }
            if ui.button("Preview import").clicked() {
                self.stage_import();
            }
        });
    }
    fn preview_window(&mut self, ctx: &egui::Context) {
        if !self.preview {
            return;
        }
        let response = egui::Modal::new(egui::Id::unique("write-review")).show(ctx, |ui| {
            ui.set_width((ctx.content_rect().width() - 72.0).clamp(240.0, 660.0));
            ui.heading("Review directory writes");
            ui.label(egui::RichText::new(&self.profile.name).strong());
            ui.add(egui::Label::new(egui::RichText::new(&self.profile.endpoint).monospace()).wrap());
            ui.label("Preview performs no writes. Apply sends the operations below. Multi-record imports can partially succeed and stop at the first failure.");
            ui.separator();
            egui::ScrollArea::vertical()
                .id_salt("review-operations")
                .max_height((ctx.content_rect().height() * 0.45).max(90.0))
                .show(ui, |ui| {
                    for change in &self.pending {
                        ui.add_space(6.0);
                        match change {
                            Change::Add(entry) => {
                                ui.strong("ADD entry");
                                ui.label(&entry.dn);
                                ui.code(ldif::export(std::slice::from_ref(entry)));
                            }
                            Change::Delete(dn) => {
                                ui.colored_label(theme::colors(ui).error, "DELETE entry");
                                ui.add(egui::Label::new(egui::RichText::new(dn).monospace()).wrap());
                            }
                            Change::Modify { dn, changes } => {
                                ui.strong("MODIFY entry");
                                ui.add(egui::Label::new(egui::RichText::new(dn).monospace()).wrap());
                                for change in changes {
                                    let (operation, name, values) = match change {
                                        AttributeChange::Add(a, v) => ("Add", a, v),
                                        AttributeChange::Replace(a, v) => ("Replace", a, v),
                                        AttributeChange::Delete(a, v) => ("Delete", a, v),
                                    };
                                    ui.label(egui::RichText::new(format!("{operation} {name}")).strong());
                                    let before = self.expected.as_ref().and_then(|e| {
                                        e.attrs.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, v)| v)
                                    });
                                    ui.columns(2, |columns| {
                                        columns[0].small(format!("Before · {} values", before.map_or(0, Vec::len)));
                                        if let Some(before) = before {
                                            for value in before {
                                                columns[0].add(egui::Label::new(egui::RichText::new(attribute_display(name, value)).monospace()).wrap());
                                            }
                                        }
                                        columns[1].small(format!("After input · {} values", values.len()));
                                        for value in values {
                                            columns[1].add(egui::Label::new(egui::RichText::new(attribute_display(name, value)).monospace()).wrap());
                                        }
                                    });
                                }
                            }
                        }
                        ui.add_space(8.0);
                        ui.separator();
                    }
                });
            let deletes = self.pending.iter().filter(|c| matches!(c, Change::Delete(_))).count();
            if deletes > 0 {
                theme::note(ui, "Deletion cannot be undone here", "Confirm the exact target before applying. This action is sent to the directory server.", true);
                ui.checkbox(&mut self.destructive_confirmed, format!("I explicitly confirm deleting {deletes} entries"));
            }
            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                if theme::primary(ui, "Apply reviewed writes", self.connected && !self.busy && !self.pending.is_empty() && (deletes == 0 || self.destructive_confirmed)).clicked() {
                    self.send(Request::Apply { changes: self.pending.clone(), expected: self.expected.clone() });
                }
                if ui.button("Discard preview").clicked() {
                    self.pending.clear();
                    self.expected = None;
                    self.preview = false;
                    self.destructive_confirmed = false;
                }
                if ui.button("Close · keep draft").clicked() {
                    self.preview = false;
                    self.destructive_confirmed = false;
                }
            });
        });
        if response.should_close() {
            self.destructive_confirmed = false;
            self.preview = false;
        }
    }
}
enum TreeKind {
    Node(String, Option<u64>),
    More(String),
    Notice(String),
}
struct TreeRow {
    depth: usize,
    kind: TreeKind,
    source: Option<(Key, u32)>,
}
enum TreeAction {
    Toggle(String, bool),
    Read(String),
    More(String),
}
fn tree_neighbor(rows: &[TreeRow], index: usize, key: egui::Key) -> Option<usize> {
    match key {
        egui::Key::ArrowUp => (0..index)
            .rev()
            .find(|i| matches!(rows[*i].kind, TreeKind::Node(..))),
        egui::Key::ArrowDown => {
            (index + 1..rows.len()).find(|i| matches!(rows[*i].kind, TreeKind::Node(..)))
        }
        egui::Key::ArrowLeft => (0..index).rev().find(|i| {
            rows[*i].depth < rows[index].depth && matches!(rows[*i].kind, TreeKind::Node(..))
        }),
        _ => None,
    }
}
fn tree_rows(roots: &[String], cache: &PageCache) -> Vec<TreeRow> {
    fn children(
        dn: &str,
        depth: usize,
        cache: &PageCache,
        seen: &mut BTreeSet<String>,
        rows: &mut Vec<TreeRow>,
    ) {
        if depth >= 24 || !seen.insert(dn.to_string()) {
            return;
        }
        let key = Key::Children(dn.to_string());
        let Some(query) = cache.get(&key) else {
            return;
        };
        if query.evicted {
            rows.push(TreeRow {
                depth: depth + 1,
                kind: TreeKind::Notice(
                    "Earlier children evicted · collapse/reload to revisit".into(),
                ),
                source: None,
            });
        }
        for (offset, entry) in cache.entries(&key) {
            let count = entry
                .values("numSubordinates")
                .first()
                .and_then(|s| s.parse().ok())
                .or_else(|| {
                    cache
                        .get(&Key::Children(entry.dn.clone()))
                        .and_then(|q| q.total)
                        .map(u64::from)
                });
            rows.push(TreeRow {
                depth: depth + 1,
                kind: TreeKind::Node(entry.dn.clone(), count),
                source: Some((key.clone(), offset)),
            });
            children(&entry.dn, depth + 1, cache, seen, rows);
        }
        if cache.entries(&key).is_empty() && query.next.is_none() && query.warning.is_none() {
            rows.push(TreeRow {
                depth: depth + 1,
                kind: TreeKind::Notice("No child entries".into()),
                source: None,
            });
        }
        if let Some(message) = &query.warning {
            rows.push(TreeRow {
                depth: depth + 1,
                kind: TreeKind::Notice(message.clone()),
                source: None,
            });
        }
        if query.next.is_some() {
            rows.push(TreeRow {
                depth: depth + 1,
                kind: TreeKind::More(dn.to_string()),
                source: None,
            });
        }
    }
    let mut rows = vec![];
    let mut seen = BTreeSet::new();
    for root in roots {
        rows.push(TreeRow {
            depth: 0,
            kind: TreeKind::Node(
                root.clone(),
                cache
                    .get(&Key::Children(root.clone()))
                    .and_then(|q| q.total)
                    .map(u64::from),
            ),
            source: None,
        });
        children(root, 0, cache, &mut seen, &mut rows);
    }
    rows
}
fn field(ui: &mut egui::Ui, label: &str, value: &mut String) {
    field_response(ui, label, value);
}
fn field_with_hint(ui: &mut egui::Ui, label: &str, hint: &str, value: &mut String) {
    let label_response = ui.label(
        egui::RichText::new(label)
            .small()
            .color(theme::colors(ui).muted),
    );
    let id = match label {
        "LDAP filter" => egui::Id::unique("query-filter"),
        "LDAPS endpoint" => egui::Id::unique("connection-endpoint"),
        _ => ui.make_persistent_id(("field", label)),
    };
    ui.add(
        egui::TextEdit::singleline(value)
            .id(id)
            .hint_text(hint)
            .desired_width(f32::INFINITY),
    )
    .labelled_by(label_response.id);
}
fn field_response(ui: &mut egui::Ui, label: &str, value: &mut String) -> egui::Response {
    let label_response = ui.label(
        egui::RichText::new(label)
            .small()
            .color(theme::colors(ui).muted),
    );
    let id = match label {
        "LDAP filter" => egui::Id::unique("query-filter"),
        "LDAPS endpoint" => egui::Id::unique("connection-endpoint"),
        _ => ui.make_persistent_id(("field", label)),
    };
    ui.add(
        egui::TextEdit::singleline(value)
            .id(id)
            .desired_width(f32::INFINITY),
    )
    .labelled_by(label_response.id)
}
fn rdn_label(dn: &str) -> &str {
    let mut escaped = false;
    for (index, c) in dn.char_indices() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == ',' {
            return &dn[..index];
        }
    }
    dn
}
fn page_mode(mode: Mode) -> &'static str {
    match mode {
        Mode::Forward => "Forward pages · total unknown",
        Mode::Vlv => "Sorted windows",
        Mode::Limited => "Server-limited results",
    }
}
fn attribute_display(name: &str, bytes: &[u8]) -> String {
    if credential_attribute(name) {
        "[credential value hidden]".into()
    } else {
        display(bytes)
    }
}
fn status_color(ui: &egui::Ui, message: &str) -> egui::Color32 {
    let p = theme::colors(ui);
    let lower = message.to_ascii_lowercase();
    if lower.contains("limit") || lower.contains("incomplete") {
        p.warning
    } else if [
        "failed",
        "cannot",
        "unavailable",
        "invalid",
        "denied",
        "could not",
        "error",
        "not found",
        "timed out",
        "refused",
        "mismatch",
        "expired",
        "not trusted",
        "omitted",
    ]
    .iter()
    .any(|word| lower.contains(word))
    {
        p.error
    } else {
        p.text
    }
}
fn display(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec())
        .unwrap_or_else(|_| format!("base64: {}", STANDARD.encode(bytes)))
}
fn theme_name(preference: egui::ThemePreference) -> Option<String> {
    match preference {
        egui::ThemePreference::Dark => Some("dark".into()),
        egui::ThemePreference::Light => Some("light".into()),
        egui::ThemePreference::System => None,
    }
}
impl Workspace {
    fn shortcuts(&mut self, ctx: &egui::Context) {
        if self.about_open {
            return;
        }
        if self.certificate_viewer.is_some() {
            if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
                self.certificate_viewer = None;
            }
            return;
        }
        if self.preview {
            return;
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::F)) {
            self.tab = 1;
            self.query_details = true;
            ctx.memory_mut(|m| m.request_focus(egui::Id::unique("query-filter")));
        }
        if !self.connected
            && !self.busy
            && ctx.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::L))
        {
            ctx.memory_mut(|m| m.request_focus(egui::Id::unique("connection-endpoint")));
        }
        for (tab, key) in [
            egui::Key::Num1,
            egui::Key::Num2,
            egui::Key::Num3,
            egui::Key::Num4,
        ]
        .into_iter()
        .enumerate()
        {
            if ctx.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, key)) {
                self.tab = tab;
            }
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::Enter)) {
            if self.tab == 1 && self.connected {
                self.run_search();
            } else if !self.connected {
                self.connect();
            }
        }
        if self.active_page.is_some()
            && ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
        {
            self.cancel_page();
        }
    }
    fn render(&mut self, ui: &mut egui::Ui) {
        self.poll();
        let ctx = ui.ctx().clone();
        self.shortcuts(&ctx);
        let palette = theme::colors(ui);
        egui::Panel::top("app-heading")
            .frame(
                egui::Frame::new()
                    .fill(palette.surface)
                    .inner_margin(egui::Margin::symmetric(16, 10)),
            )
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(egui::RichText::new("DIRLARK").size(21.0).strong());
                    if ctx.content_rect().width() > 700.0 {
                        ui.label(egui::RichText::new("Directory workbench").color(palette.muted));
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("About").clicked() {
                            self.about_open = true;
                        }
                        let previous = self.appearance;
                        egui::ComboBox::from_id_salt("appearance")
                            .width(95.0)
                            .selected_text(match self.appearance {
                                egui::ThemePreference::System => "System theme",
                                egui::ThemePreference::Dark => "Dark theme",
                                egui::ThemePreference::Light => "Light theme",
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut self.appearance,
                                    egui::ThemePreference::System,
                                    "System theme",
                                );
                                ui.selectable_value(
                                    &mut self.appearance,
                                    egui::ThemePreference::Dark,
                                    "Dark theme",
                                );
                                ui.selectable_value(
                                    &mut self.appearance,
                                    egui::ThemePreference::Light,
                                    "Light theme",
                                );
                            });
                        if previous != self.appearance {
                            ctx.set_theme(self.appearance);
                            if let Some(path) = &self.path {
                                let _ = crate::profiles::save_with_theme(
                                    path,
                                    &self.profiles,
                                    theme_name(self.appearance).as_deref(),
                                );
                            }
                        }
                        ui.menu_button("Shortcuts", |ui| {
                            for line in [
                                "Cmd/Ctrl+L · connection endpoint",
                                "Cmd/Ctrl+F · search filter",
                                "Cmd/Ctrl+1–4 · workspace tabs",
                                "Cmd/Ctrl+Enter · connect / run search",
                                "Esc · cancel search / close review",
                                "Tab / Shift+Tab · move focus",
                                "Tree arrows · move / expand / collapse",
                                "Enter / Space · activate focused control",
                            ] {
                                ui.label(line);
                            }
                        });
                    });
                });
            });
        egui::Panel::bottom("status")
            .frame(
                egui::Frame::new()
                    .fill(palette.surface)
                    .inner_margin(egui::Margin::symmetric(12, 6)),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    if self.busy {
                        ui.spinner();
                    }
                    let width = (ui.available_width() - 120.0).max(80.0);
                    ui.add_sized(
                        [width, 24.0],
                        egui::Label::new(
                            egui::RichText::new(&self.status).color(status_color(ui, &self.status)),
                        )
                        .truncate(),
                    )
                    .on_hover_text(&self.status);
                    if ui
                        .add_enabled(
                            self.active_page.is_some(),
                            egui::Button::new("Cancel search"),
                        )
                        .clicked()
                    {
                        self.cancel_page();
                    }
                });
                ui.collapsing("Operation log", |ui| {
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(!self.logs.is_empty(), egui::Button::new("Copy log"))
                            .clicked()
                        {
                            let joined: Vec<&str> = self.logs.iter().map(String::as_str).collect();
                            ui.ctx().copy_text(joined.join("\n"));
                        }
                        ui.small(format!("{} entries", self.logs.len()));
                    });
                    egui::ScrollArea::vertical()
                        .id_salt("operation-log")
                        .max_height(100.0)
                        .show(ui, |ui| {
                            for line in self.logs.iter().rev() {
                                ui.add(egui::Label::new(line).selectable(true));
                            }
                        });
                });
            });
        egui::Panel::left("profiles")
            .default_size(300.0_f32.min(ctx.content_rect().width() * 0.38))
            .max_size((ctx.content_rect().width() * 0.45).max(180.0))
            .resizable(true)
            .frame(egui::Frame::new().fill(palette.surface).inner_margin(14))
            .show(ui, |ui| self.profile_form(ui));
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(palette.background).inner_margin(18))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    for (index, name) in ["Entry", "Search", "Schema", "LDIF"].iter().enumerate() {
                        ui.selectable_value(&mut self.tab, index, *name);
                    }
                });
                ui.add_space(8.0);
                ui.separator();
                ui.add_space(8.0);
                if !self.pending.is_empty() && !self.preview {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            egui::RichText::new(format!(
                                "{} pending write operations · {}",
                                self.pending.len(),
                                self.profile.name
                            ))
                            .color(palette.warning),
                        );
                        if ui.button("Review draft").clicked() {
                            self.preview = true;
                        }
                        if ui.button("Discard draft").clicked() {
                            self.pending.clear();
                            self.expected = None;
                            self.destructive_confirmed = false;
                        }
                    });
                    ui.separator();
                }
                let color = status_color(ui, &self.status);
                if color == palette.error
                    && self.credential_storage.as_ref().err() != Some(&self.status)
                {
                    theme::note(ui, "Operation needs attention", &self.status, false);
                    ui.add_space(8.0);
                }
                if self.tab == 1 {
                    self.search_view(ui);
                } else if self.tab == 0 {
                    self.entry_view(ui);
                } else {
                    egui::ScrollArea::vertical()
                        .id_salt(("workspace-tab", self.tab))
                        .auto_shrink([false, false])
                        .show(ui, |ui| match self.tab {
                            0 => self.entry_view(ui),
                            2 => self.schema_view(ui),
                            _ => self.transfer_view(ui),
                        });
                }
            });
        self.preview_window(&ctx);
        if let Some(viewer) = &mut self.certificate_viewer
            && !viewer.show(&ctx, self.selected.as_ref())
        {
            self.certificate_viewer = None;
        }
        if self.about_open {
            self.about_open = about::show(&ctx);
        }
        let capture_ready = !self.busy;
        #[cfg(debug_assertions)]
        let capture_ready = capture_ready || self.evidence_readonly;
        if let Some(smoke) = &mut self.smoke {
            smoke.tick(
                &ctx,
                capture_ready,
                self.connection_screen_visible,
                self.credential_storage.is_ok(),
            );
        }
    }
}
impl eframe::App for Workspace {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.render(ui);
    }
}

const DEFAULT_ATTRIBUTES_HEIGHT: f32 = 360.0;

// Keep both panes usable on short viewports. Desired size survives entry changes.
fn split_height(desired: f32, available: f32) -> f32 {
    let min = 100.0_f32.min((available * 0.4).max(24.0));
    let max = (available - 120.0).max(min);
    desired.clamp(min, max)
}
fn attributes_splitter(ui: &mut egui::Ui, desired: &mut f32, available: f32) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), 12.0),
        egui::Sense::click_and_drag(),
    );
    response.widget_info(|| {
        egui::WidgetInfo::labeled(
            egui::Role::Slider,
            ui.is_enabled(),
            "Resize entry attributes",
        )
    });
    let response = response
        .on_hover_text("Drag to resize attributes · ↑/↓ when focused · double-click to reset");
    if response.drag_started() {
        response.request_focus();
    }
    if response.dragged() {
        *desired = split_height(*desired + response.drag_delta().y, available);
    }
    if response.has_focus() {
        ui.input(|i| {
            if i.key_pressed(egui::Key::ArrowUp) {
                *desired -= 16.0;
            }
            if i.key_pressed(egui::Key::ArrowDown) {
                *desired += 16.0;
            }
            if i.key_pressed(egui::Key::Home) {
                *desired = 0.0;
            }
            if i.key_pressed(egui::Key::End) {
                *desired = available;
            }
        });
        *desired = split_height(*desired, available);
    }
    if response.double_clicked() {
        *desired = DEFAULT_ATTRIBUTES_HEIGHT;
    }
    if response.hovered() || response.dragged() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeVertical);
    }
    let color = if response.has_focus() || response.hovered() {
        theme::colors(ui).accent
    } else {
        ui.visuals().widgets.noninteractive.bg_stroke.color
    };
    ui.painter().line_segment(
        [rect.left_center(), rect.right_center()],
        egui::Stroke::new(1.0, color),
    );
    ui.painter().rect_filled(
        egui::Rect::from_center_size(rect.center(), egui::vec2(42.0, 3.0)),
        2.0,
        color,
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_and_pending_details_never_show_the_previous_entry() {
        let ctx = egui::Context::default();
        let mut w = Workspace::from_path(ctx.clone(), None, None, false);
        for credentials_only in [false, true] {
            w.profile.bind_dn = if credentials_only {
                "cn=reader,dc=example,dc=test".into()
            } else {
                String::new()
            };
            w.selected = Some(Entry {
                dn: "ou=Empty,dc=example,dc=test".into(),
                attrs: if credentials_only {
                    [("userPassword".into(), vec![b"synthetic-hidden".to_vec()])].into()
                } else {
                    Default::default()
                },
            });
            let mut painted = String::new();
            for _ in 0..2 {
                let mut out = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(1280.0, 900.0),
                        )),
                        ..Default::default()
                    },
                    |ui| {
                        egui::CentralPanel::default().show(ui, |ui| w.entry_view(ui));
                    },
                );
                painted.clear();
                for shape in &out.shapes {
                    rendered_text(&shape.shape, &mut painted);
                }
                out.textures_delta.clear();
            }
            assert!(painted.contains("No readable attributes"));
            assert!(painted.contains(if credentials_only {
                "current directory identity"
            } else {
                "Anonymous access"
            }));
            assert!(painted.contains("No certificates"));
            assert!(!painted.contains("synthetic-hidden"));
        }
        w.pending_read = Some("ou=Loading,dc=example,dc=test".into());
        w.busy = true;
        let mut out = ctx.run_ui(Default::default(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| w.entry_view(ui));
        });
        let mut painted = String::new();
        for shape in &out.shapes {
            rendered_text(&shape.shape, &mut painted);
        }
        out.textures_delta.clear();
        assert!(painted.contains("Loading entry attributes"));
        assert!(!painted.contains("ou=Empty"));
        w.accept_response(
            w.generation,
            Response::Read(Entry {
                dn: "ou=Loading,dc=example,dc=test".into(),
                attrs: Default::default(),
            }),
        );
        assert!(w.pending_read.is_none());
    }
    #[test]
    fn splitter_pointer_and_keyboard_resize_with_bounds_and_reset() {
        let ctx = egui::Context::default();
        let mut height = 260.0;
        let mut time = 0.0;
        let mut frame = |events: Vec<egui::Event>, focus: bool, height: &mut f32| {
            time += 0.05;
            let mut response = None;
            let mut output = ctx.run_ui(
                egui::RawInput {
                    time: Some(time),
                    events,
                    ..Default::default()
                },
                |ui| {
                    egui::CentralPanel::default().show(ui, |ui| {
                        let r = attributes_splitter(ui, height, 600.0);
                        if focus {
                            r.request_focus();
                        }
                        response = Some(r);
                    });
                },
            );
            output.textures_delta.clear();
            response.unwrap()
        };
        let r = frame(vec![], true, &mut height);
        let key = |key| egui::Event::Key {
            key,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: Default::default(),
        };
        frame(vec![key(egui::Key::ArrowDown)], false, &mut height);
        assert_eq!(height, 276.0);
        frame(vec![key(egui::Key::End)], false, &mut height);
        assert_eq!(height, 480.0);
        frame(vec![key(egui::Key::Home)], false, &mut height);
        assert_eq!(height, 100.0);
        let pos = r.rect.center();
        let pointer = |pos, pressed| egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: Default::default(),
        };
        frame(
            vec![egui::Event::PointerMoved(pos), pointer(pos, true)],
            false,
            &mut height,
        );
        let moved = pos + egui::vec2(0.0, 35.0);
        frame(vec![egui::Event::PointerMoved(moved)], false, &mut height);
        assert!(height > 100.0);
        frame(vec![pointer(moved, false)], false, &mut height);
        // Two ordinary clicks on the handle reset to the default height.
        for _ in 0..2 {
            frame(
                vec![egui::Event::PointerMoved(pos), pointer(pos, true)],
                false,
                &mut height,
            );
            frame(vec![pointer(pos, false)], false, &mut height);
        }
        assert_eq!(height, DEFAULT_ATTRIBUTES_HEIGHT);
        for available in [80.0, 150.0, 400.0, 900.0] {
            let h = split_height(10000.0, available);
            assert!(h.is_finite() && h > 0.0 && h < available);
        }
    }
    #[test]
    fn certificate_counts_render_and_reload_clears_the_open_viewer() {
        let ctx = egui::Context::default();
        let mut w = Workspace::from_path(ctx.clone(), None, None, false);
        let entry = Entry {
            dn: "cn=synthetic".into(),
            attrs: [
                (
                    "userCertificate;binary".into(),
                    vec![vec![0x30, 0], vec![0x30, 0]],
                ),
                ("USERCERTIFICATE;lang-en".into(), vec![vec![0x30, 0]]),
            ]
            .into(),
        };
        w.selected = Some(entry.clone());
        w.attributes_height = 350.0;
        let mut painted = String::new();
        for _ in 0..3 {
            let mut out = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1280.0, 900.0),
                    )),
                    ..Default::default()
                },
                |ui| {
                    egui::CentralPanel::default().show(ui, |ui| w.entry_view(ui));
                },
            );
            painted.clear();
            for clipped in &out.shapes {
                rendered_text(&clipped.shape, &mut painted);
            }
            out.textures_delta.clear();
        }
        // Attribute names must not collapse into a one-character-wide grid column.
        fn name_width(shape: &egui::epaint::Shape) -> Option<f32> {
            match shape {
                egui::epaint::Shape::Text(t) if t.galley.text() == "userCertificate;binary" => {
                    Some(t.galley.size().x)
                }
                egui::epaint::Shape::Vec(v) => v.iter().find_map(name_width),
                _ => None,
            }
        }
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1280.0, 900.0),
                )),
                ..Default::default()
            },
            |ui| {
                egui::CentralPanel::default().show(ui, |ui| w.entry_view(ui));
            },
        );
        assert!(
            output
                .shapes
                .iter()
                .find_map(|s| name_width(&s.shape))
                .unwrap()
                > 120.0
        );
        output.textures_delta.clear();
        assert!(painted.contains("Certs: 3"));
        assert!(painted.contains("Value 2 of 2"));
        w.certificate_viewer = certificate_view::Viewer::new(&entry, "userCertificate;binary", 0);
        key(&ctx, &mut w, egui::Key::Escape, Default::default());
        assert!(w.certificate_viewer.is_none());
        w.certificate_viewer = certificate_view::Viewer::new(&entry, "userCertificate;binary", 0);
        w.accept_response(0, Response::Read(entry));
        assert!(w.certificate_viewer.is_none());
        assert_eq!(
            w.attributes_height, 350.0,
            "Entry reload must preserve pane size"
        );
    }
    fn workspace(path: PathBuf) -> Workspace {
        Workspace::from_path(egui::Context::default(), Some(path), None, false)
    }
    fn key(ctx: &egui::Context, w: &mut Workspace, key: egui::Key, modifiers: egui::Modifiers) {
        let mut output = ctx.run_ui(
            egui::RawInput {
                events: vec![egui::Event::Key {
                    key,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers,
                }],
                ..Default::default()
            },
            |_ui| w.shortcuts(ctx),
        );
        output.textures_delta.clear();
    }
    fn connection_frame(ctx: &egui::Context, w: &mut Workspace, events: Vec<egui::Event>) {
        let mut out = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(900.0, 700.0),
                )),
                events,
                ..Default::default()
            },
            |ui| {
                egui::CentralPanel::default().show(ui, |ui| w.connection_fields(ui));
            },
        );
        out.textures_delta.clear();
    }
    fn enter() -> Vec<egui::Event> {
        [true, false]
            .into_iter()
            .map(|pressed| egui::Event::Key {
                key: egui::Key::Enter,
                physical_key: None,
                pressed,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            })
            .collect()
    }
    #[test]
    fn enter_in_the_password_field_connects_but_enter_elsewhere_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = egui::Context::default();
        let mut w = Workspace::from_path(
            ctx.clone(),
            Some(dir.path().join("profiles.json")),
            None,
            false,
        );
        w.profile.endpoint = "ldaps://localhost:636".into();
        w.profile.bind_dn = "uid=test,dc=example".into();
        connection_frame(&ctx, &mut w, vec![]);
        // No field focused: Enter must not connect.
        let before = w.generation;
        connection_frame(&ctx, &mut w, enter());
        assert_eq!(w.generation, before, "Enter with nothing focused connected");
        // Focus the password field, paste, press Enter.
        ctx.memory_mut(|m| m.request_focus(egui::Id::unique("connection-password")));
        connection_frame(&ctx, &mut w, vec![]);
        connection_frame(
            &ctx,
            &mut w,
            vec![egui::Event::Paste("synthetic-secret".into())],
        );
        assert_eq!(&*w.password, "synthetic-secret");
        connection_frame(&ctx, &mut w, enter());
        assert_eq!(
            w.generation,
            before + 1,
            "Enter in the password field did not connect"
        );
        assert!(w.busy);
        // Pressing Enter again while busy must not double-submit.
        ctx.memory_mut(|m| m.request_focus(egui::Id::unique("connection-password")));
        connection_frame(&ctx, &mut w, vec![]);
        connection_frame(&ctx, &mut w, enter());
        assert_eq!(
            w.generation,
            before + 1,
            "Enter while busy double-submitted"
        );
        // Enter in the endpoint field also connects when idle.
        w.busy = false;
        ctx.memory_mut(|m| m.request_focus(egui::Id::unique("connection-endpoint")));
        connection_frame(&ctx, &mut w, vec![]);
        connection_frame(&ctx, &mut w, enter());
        assert_eq!(
            w.generation,
            before + 2,
            "Enter in the endpoint field did not connect"
        );
    }
    #[test]
    fn keyboard_navigation_never_applies_a_pending_write() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = workspace(dir.path().join("profiles.json"));
        let ctx = egui::Context::default();
        key(&ctx, &mut w, egui::Key::F, egui::Modifiers::COMMAND);
        assert_eq!(w.tab, 1);
        key(&ctx, &mut w, egui::Key::Num4, egui::Modifiers::COMMAND);
        assert_eq!(w.tab, 3);
        w.pending.push(Change::Delete("cn=Test".into()));
        w.preview = true;
        w.connected = true;
        key(&ctx, &mut w, egui::Key::Enter, egui::Modifiers::COMMAND);
        assert!(!w.busy);
        assert!(!w.destructive_confirmed);
        assert!(w.worker.receiver.try_recv().is_err());
        w.preview = false;
        let token = Arc::new(AtomicBool::new(false));
        w.active_page = Some((Key::Search, token.clone()));
        key(&ctx, &mut w, egui::Key::Escape, egui::Modifiers::NONE);
        assert!(token.load(Ordering::Acquire));
    }
    #[test]
    fn credential_values_are_hidden_in_inspection_and_modify_preview() {
        for name in CREDENTIAL_ATTRIBUTES
            .iter()
            .copied()
            .chain(["otherPASSWORD", "UnicodePwd;binary"])
        {
            assert_eq!(
                attribute_display(name, b"must-not-display"),
                "[credential value hidden]"
            );
        }
        assert_eq!(attribute_display("cn", b"Visible"), "Visible");
        let dir = tempfile::tempdir().unwrap();
        let mut w = workspace(dir.path().join("profiles.json"));
        assert!(!w.include_credentials);
        w.include_credentials = true;
        w.clear_data();
        assert!(!w.include_credentials);
    }
    #[test]
    fn tree_navigation_skips_sentinels_and_finds_parent_without_fetching() {
        let rows = vec![
            TreeRow {
                depth: 0,
                kind: TreeKind::Node("dc=test".into(), None),
                source: None,
            },
            TreeRow {
                depth: 1,
                kind: TreeKind::Node("ou=A,dc=test".into(), None),
                source: None,
            },
            TreeRow {
                depth: 1,
                kind: TreeKind::More("dc=test".into()),
                source: None,
            },
            TreeRow {
                depth: 1,
                kind: TreeKind::Node("ou=B,dc=test".into(), None),
                source: None,
            },
        ];
        assert_eq!(tree_neighbor(&rows, 1, egui::Key::ArrowDown), Some(3));
        assert_eq!(tree_neighbor(&rows, 3, egui::Key::ArrowUp), Some(1));
        assert_eq!(tree_neighbor(&rows, 3, egui::Key::ArrowLeft), Some(0));
        assert_eq!(tree_neighbor(&rows, 0, egui::Key::ArrowUp), None);
    }
    #[test]
    fn credential_export_is_explicit_and_resets_buffer_and_connection_state() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = workspace(dir.path().join("profiles.json"));
        let entry = Entry {
            dn: "cn=Example,dc=test".into(),
            attrs: [
                ("cn".into(), vec![b"Example".to_vec()]),
                ("unicodePwd;binary".into(), vec![b"private sample".to_vec()]),
            ]
            .into(),
        };
        assert!(!w.include_credentials);
        assert!(
            !w.export_entries(std::slice::from_ref(&entry))
                .contains("private sample")
        );
        w.set_credential_export(true);
        w.transfer = w.export_entries(std::slice::from_ref(&entry));
        assert!(w.transfer.contains("private sample"));
        assert!(w.transfer.contains("WARNING"));
        w.set_credential_export(false);
        assert!(w.transfer.is_empty());
        assert!(!w.include_credentials);
        w.set_credential_export(true);
        w.transfer = w.export_entries(&[entry]);
        w.accept_response(0, Response::Disconnected);
        assert!(!w.include_credentials && w.transfer.is_empty());
        assert!(w.logs.iter().all(|s| !s.contains("private sample")));
    }
    fn rendered_text(shape: &egui::epaint::Shape, output: &mut String) {
        match shape {
            egui::epaint::Shape::Text(text) => output.push_str(text.galley.text()),
            egui::epaint::Shape::Vec(shapes) => {
                for shape in shapes {
                    rendered_text(shape, output);
                }
            }
            _ => {}
        }
    }
    #[test]
    fn inspection_and_write_preview_never_render_credential_values() {
        for name in CREDENTIAL_ATTRIBUTES.iter().copied().chain([
            "CustomPASSWORD",
            "UnicodePwd;binary",
            "CustomSECRET;binary",
        ]) {
            assert_eq!(
                attribute_display(name, b"private sample"),
                "[credential value hidden]"
            );
            let ctx = egui::Context::default();
            let dir = tempfile::tempdir().unwrap();
            let mut w = workspace(dir.path().join("profiles.json"));
            let entry = Entry {
                dn: "cn=Example,dc=test".into(),
                attrs: [(name.into(), vec![b"private sample".to_vec()])].into(),
            };
            w.selected = Some(entry.clone());
            w.expected = Some(entry);
            w.pending = vec![Change::Modify {
                dn: "cn=Example,dc=test".into(),
                changes: vec![AttributeChange::Replace(
                    name.into(),
                    vec![b"private sample".to_vec()],
                )],
            }];
            w.preview = true;
            // Settle the real widgets; inspect paint text and clipboard commands, not only the helper.
            for _ in 0..2 {
                let mut frame = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(1200.0, 900.0),
                        )),
                        ..Default::default()
                    },
                    |ui| {
                        egui::CentralPanel::default().show(ui, |ui| w.entry_view(ui));
                        w.preview_window(&ctx);
                    },
                );
                let mut text = String::new();
                for clipped in &frame.shapes {
                    rendered_text(&clipped.shape, &mut text);
                }
                assert!(
                    !text.contains("private sample"),
                    "credential rendered for {name}"
                );
                assert!(text.contains("[credential value hidden]"));
                assert!(
                    !format!("{:?}", frame.platform_output.commands).contains("private sample")
                );
                frame.textures_delta.clear();
            }
            assert!(w.logs.iter().all(|s| !s.contains("private sample")));
            assert!(w.worker.receiver.try_recv().is_err());
        }
        assert_eq!(attribute_display("cn", b"Example"), "Example");
    }
    #[test]
    fn import_preview_does_not_dispatch_writes() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = workspace(dir.path().join("profiles.json"));
        w.connected = true;
        w.transfer = "dn: cn=Test,dc=example\ncn: Test\nobjectClass: person\nsn: Test\n".into();
        w.stage_import();
        assert!(w.preview);
        assert_eq!(w.pending.len(), 1);
        assert!(!w.busy);
        assert!(w.worker.receiver.try_recv().is_err());
    }
    #[test]
    fn failure_preserves_draft_and_stale_result_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = workspace(dir.path().join("profiles.json"));
        w.generation = 2;
        w.transfer = "dn: cn=Test,dc=example\ncn: Test\n".into();
        w.stage_import();
        w.busy = true;
        w.accept_response(2, Response::Error("write denied".into()));
        assert!(w.preview);
        assert_eq!(w.pending.len(), 1);
        assert!(!w.busy);
        w.accept_response(1, Response::Connected(vec!["dc=stale".into()]));
        assert!(!w.connected);
        assert!(w.roots.is_empty());
    }
    #[test]
    fn corrupt_profile_file_cannot_be_overwritten_by_ui() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profiles.json");
        std::fs::write(&path, "invalid").unwrap();
        let w = workspace(path.clone());
        assert!(w.path.is_none());
        assert_eq!(std::fs::read_to_string(path).unwrap(), "invalid");
    }
    #[test]
    fn disconnect_clears_directory_data() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = workspace(dir.path().join("profiles.json"));
        w.connected = true;
        w.roots.push("dc=example".into());
        w.transfer = "directory data".into();

        w.pending.push(Change::Delete("cn=Test".into()));
        w.accept_response(0, Response::Disconnected);
        assert!(!w.connected);
        assert!(
            w.roots.is_empty()
                && w.pages.usage() == (0, 0)
                && w.transfer.is_empty()
                && w.pending.is_empty()
        );
    }
    #[test]
    fn destructive_import_requires_fresh_explicit_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = workspace(dir.path().join("profiles.json"));
        w.connected = true;
        w.transfer = "dn: cn=Test,dc=example\nchangetype: delete\n".into();
        w.destructive_confirmed = true;
        w.stage_import();
        assert!(!w.destructive_confirmed);
        w.send(Request::Apply {
            changes: w.pending.clone(),
            expected: None,
        });
        assert!(!w.busy);
        assert!(w.status.contains("Explicitly confirm"));
        assert!(w.worker.receiver.try_recv().is_err());
        w.destructive_confirmed = true;
        w.stage_import();
        assert!(!w.destructive_confirmed);
    }
    #[test]
    fn unavailable_credential_service_disables_saving_and_explains_session_only() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = workspace(dir.path().join("profiles.json"));
        w.remember = true;
        w.accept_response(
            0,
            Response::CredentialStatus(Err(crate::profiles::CREDENTIALS_UNAVAILABLE.into())),
        );
        assert!(!w.remember);
        assert!(w.credential_storage.is_err());
        assert!(w.status.contains("Credentials cannot be saved"));
        assert!(w.status.contains("no plaintext fallback"));
        assert!(!w.connected);
        assert!(w.path.is_some());
    }
    fn fixture_page(offset: u32) -> crate::paging::Page {
        crate::paging::Page {
            entries: (offset..offset + 500)
                .map(|n| Entry {
                    dn: format!("cn=Person{n},dc=scale"),
                    attrs: Default::default(),
                })
                .collect(),
            next: None,
            offset,
            total: Some(1_000_000),
            mode: Mode::Vlv,
            warning: None,
        }
    }
    fn fixture_query() -> Query {
        Query {
            base: "dc=scale".into(),
            scope: 2,
            filter: "(objectClass=*)".into(),
            attrs: vec![],
            sort: "cn".into(),
            ordering_rule: String::new(),
        }
    }
    #[test]
    fn virtual_scroll_renders_only_visible_search_and_tree_rows() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = workspace(dir.path().join("profiles.json"));
        w.roots = vec!["dc=scale".into()];
        for offset in (1..=4000).step_by(500) {
            w.pages.insert(
                Key::Search,
                fixture_query(),
                500,
                fixture_page(offset),
                false,
            );
            w.pages.insert(
                Key::Children("dc=scale".into()),
                fixture_query(),
                500,
                fixture_page(offset),
                false,
            );
        }
        let ctx = egui::Context::default();
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1200.0, 900.0),
                )),
                ..Default::default()
            },
            |ui| {
                egui::Panel::left("tree-test")
                    .default_size(300.0)
                    .show(ui, |ui| w.profile_form(ui));
                egui::CentralPanel::default().show(ui, |ui| w.search_view(ui));
            },
        );
        output.textures_delta.clear();
        assert!(
            w.rendered_rows.0 > 0 && w.rendered_rows.0 < 100,
            "search rendered {} rows",
            w.rendered_rows.0
        );
        assert!(
            w.rendered_rows.1 > 0 && w.rendered_rows.1 < 100,
            "tree rendered {} rows",
            w.rendered_rows.1
        );
        assert_eq!(w.pages.entries(&Key::Search).len(), 4000);
    }
    #[test]
    fn cancelling_search_invalidates_cursor_and_discards_late_page() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = workspace(dir.path().join("profiles.json"));
        w.generation = 7;
        let token = Arc::new(AtomicBool::new(false));
        w.active_page = Some((Key::Search, token.clone()));
        w.busy = true;
        w.cancel_page();
        assert!(token.load(Ordering::Acquire));
        assert!(!w.busy);
        w.accept_response(
            7,
            Response::Page(
                Key::Search,
                fixture_query(),
                500,
                Box::new(fixture_page(1)),
                true,
            ),
        );
        assert!(!w.pages.contains(&Key::Search));
        assert!(w.status.contains("cancelled"));
    }
    #[test]
    fn repeated_tree_dns_do_not_expand_exponentially() {
        let mut cache = PageCache::default();
        let mut page = fixture_page(1);
        for entry in &mut page.entries {
            entry.dn = "dc=scale".into();
        }
        cache.insert(
            Key::Children("dc=scale".into()),
            fixture_query(),
            500,
            page,
            false,
        );
        assert_eq!(tree_rows(&["dc=scale".into()], &cache).len(), 501);
    }
    #[test]
    fn page_failure_closes_continuation_but_preserves_bounded_rows() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = workspace(dir.path().join("profiles.json"));
        let mut page = fixture_page(1);
        page.next = Some(Cursor {
            connection: uuid::Uuid::nil(),
            query: fixture_query(),
            mode: Mode::Forward,
            cookie: vec![1],
            offset: 501,
            total: None,
        });
        w.pages
            .insert(Key::Search, fixture_query(), 500, page, true);
        w.active_page = Some((Key::Search, Arc::new(AtomicBool::new(false))));
        w.busy = true;
        w.accept_response(
            0,
            Response::Error("Server administrative limit reached".into()),
        );
        let cached = w.pages.get(&Key::Search).unwrap();
        assert!(cached.next.is_none());
        assert!(
            cached
                .warning
                .as_ref()
                .unwrap()
                .contains("Continuation closed")
        );
        assert_eq!(w.pages.entries(&Key::Search).len(), 500);
    }
    fn wait_for_worker(w: &mut Workspace) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while w.busy && std::time::Instant::now() < deadline {
            w.poll();
            if w.busy {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        }
        assert!(!w.busy, "worker did not complete in time");
    }
    #[test]
    fn saved_password_indicator_forget_delete_and_connected_save_profile() {
        crate::profiles::credential_status().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profiles.json");
        let profile = Profile {
            name: "myldap".into(),
            endpoint: "ldaps://directory.example.org:636".into(),
            base_dn: "dc=example,dc=org".into(),
            bind_dn: "uid=alice,dc=example,dc=org".into(),
            ca_bundle: String::new(),
            password_saved: true,
            ..Profile::default()
        };
        crate::profiles::credential(&profile)
            .unwrap()
            .set_password("synthetic-keychain-secret")
            .unwrap();
        crate::profiles::save_with_theme(&path, std::slice::from_ref(&profile), Some("dark"))
            .unwrap();
        let ctx = egui::Context::default();
        let mut w = Workspace::from_path(ctx.clone(), Some(path.clone()), None, false);
        assert_eq!(w.appearance, egui::ThemePreference::Dark);
        assert!(w.profile.password_saved);
        assert!(w.remember);
        // Render profile_form when disconnected: saved-password indicator and Forget button must render.
        let mut painted = String::new();
        for _ in 0..2 {
            let mut out = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(900.0, 700.0),
                    )),
                    ..Default::default()
                },
                |ui| {
                    egui::CentralPanel::default().show(ui, |ui| w.profile_form(ui));
                },
            );
            painted.clear();
            for s in &out.shapes {
                rendered_text(&s.shape, &mut painted);
            }
            out.textures_delta.clear();
        }
        assert!(painted.contains("Password saved in keychain"));
        assert!(painted.contains("Forget saved password"));
        assert!(painted.contains("Password (saved password will be used)"));
        assert!(painted.contains("Delete profile"));
        // While connected, Save profile remains visible even when Connection settings is collapsed.
        w.connected = true;
        for _ in 0..2 {
            let mut out = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(900.0, 700.0),
                    )),
                    ..Default::default()
                },
                |ui| {
                    egui::CentralPanel::default().show(ui, |ui| w.profile_form(ui));
                },
            );
            painted.clear();
            for s in &out.shapes {
                rendered_text(&s.shape, &mut painted);
            }
            out.textures_delta.clear();
        }
        assert!(
            painted.contains("Save profile"),
            "Save profile must remain visible while connected"
        );
        w.connected = false;
        // Forget saved password deletes the keychain entry and clears password_saved on disk.
        w.forget_password();
        wait_for_worker(&mut w);
        assert!(!w.profile.password_saved);
        assert!(!w.remember);
        assert_eq!(w.status, "Saved password removed from OS keychain");
        assert!(
            crate::profiles::saved_password(&w.profile)
                .unwrap_err()
                .contains("No saved password available")
        );
        assert!(!crate::profiles::load(&path).unwrap()[0].password_saved);
        // Re-save a keychain password and test Delete profile with keychain removal.
        crate::profiles::credential(&w.profile)
            .unwrap()
            .set_password("second-secret")
            .unwrap();
        w.profile.password_saved = true;
        w.delete_profile(true);
        wait_for_worker(&mut w);
        assert!(w.profiles.is_empty());
        assert!(crate::profiles::load(&path).unwrap().is_empty());
        assert!(crate::profiles::saved_password(&profile).is_err());
    }
    #[test]
    fn existing_keychain_entry_without_flag_sets_saved_indicator_on_load_and_connect() {
        crate::profiles::credential_status().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profiles.json");
        // Profile on disk has password_saved = false (simulating pre-alpha.3 profiles.json),
        // while the OS keychain already holds a password for this profile.
        let profile = Profile {
            name: "existing-keychain".into(),
            endpoint: "ldaps://directory.example.org:636".into(),
            base_dn: "dc=example,dc=org".into(),
            bind_dn: "uid=alice,dc=example,dc=org".into(),
            ca_bundle: String::new(),
            password_saved: false,
            ..Profile::default()
        };
        let entry = crate::profiles::credential(&profile).unwrap();
        entry.set_password("existing-secret").unwrap();
        crate::profiles::save(&path, std::slice::from_ref(&profile)).unwrap();

        let ctx = egui::Context::default();
        let mut w = Workspace::from_path(ctx.clone(), Some(path.clone()), None, false);
        assert!(
            w.profile.password_saved,
            "existing keychain entry must set password_saved on profile load"
        );
        assert!(w.remember);
        assert!(crate::profiles::load(&path).unwrap()[0].password_saved);

        let mut painted = String::new();
        for _ in 0..2 {
            let mut out = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(900.0, 700.0),
                    )),
                    ..Default::default()
                },
                |ui| {
                    egui::CentralPanel::default().show(ui, |ui| w.profile_form(ui));
                },
            );
            painted.clear();
            for s in &out.shapes {
                rendered_text(&s.shape, &mut painted);
            }
            out.textures_delta.clear();
        }
        assert!(painted.contains("Password saved in keychain"));
        assert!(painted.contains("Forget saved password"));

        // Also verify blank-password connect when password_saved and remember start false in memory.
        w.profile.password_saved = false;
        w.profiles[0].password_saved = false;
        w.remember = false;
        w.password.clear();
        w.connecting_saves_or_uses_keychain =
            !w.profile.bind_dn.is_empty() && (w.remember || w.password.is_empty());
        w.busy = true;
        w.accept_response(0, Response::Connected(vec!["dc=example,dc=org".into()]));
        assert!(w.profile.password_saved);
        assert!(w.remember);
        assert!(crate::profiles::load(&path).unwrap()[0].password_saved);

        // Locked/denied keychain entry on load reports saved but unavailable with a clear message.
        let mock: &keyring::mock::Cred = entry.as_any().downcast_ref().unwrap();
        mock.set_error(keyring::Error::NoStorageAccess(Box::new(
            std::io::Error::other("keychain locked"),
        )));
        let mut locked_profile = profile.clone();
        locked_profile.password_saved = false;
        crate::profiles::save(&path, std::slice::from_ref(&locked_profile)).unwrap();
        let mut w_locked = Workspace::from_path(ctx.clone(), Some(path.clone()), None, false);
        assert!(w_locked.profile.password_saved);
        assert!(w_locked.status.contains("locked or access was denied"));
        for _ in 0..2 {
            let mut out = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(900.0, 700.0),
                    )),
                    ..Default::default()
                },
                |ui| {
                    egui::CentralPanel::default().show(ui, |ui| w_locked.profile_form(ui));
                },
            );
            painted.clear();
            for s in &out.shapes {
                rendered_text(&s.shape, &mut painted);
            }
            out.textures_delta.clear();
        }
        assert!(
            painted.contains("Password saved in keychain (unavailable: locked or access denied)")
        );
        assert!(painted.contains("Forget saved password"));
        let _ = crate::profiles::delete_saved_password(&profile);
    }
    #[test]
    fn edited_endpoint_or_bind_dn_still_forgets_and_deletes_saved_profile_credential() {
        crate::profiles::credential_status().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profiles.json");
        let saved = Profile {
            name: "prod".into(),
            endpoint: "ldaps://prod.example.org:636".into(),
            base_dn: "dc=example,dc=org".into(),
            bind_dn: "uid=alice,dc=example,dc=org".into(),
            ca_bundle: String::new(),
            password_saved: true,
            ..Profile::default()
        };
        crate::profiles::credential(&saved)
            .unwrap()
            .set_password("prod-secret")
            .unwrap();
        crate::profiles::save(&path, std::slice::from_ref(&saved)).unwrap();

        let ctx = egui::Context::default();
        let mut w = Workspace::from_path(ctx.clone(), Some(path.clone()), None, false);
        // Edit endpoint and bind_dn in the form WITHOUT clicking Save profile.
        w.profile.endpoint = "ldaps://edited.example.org:636".into();
        w.profile.bind_dn = "uid=bob,dc=example,dc=org".into();
        let edited_copy = w.profile.clone();
        crate::profiles::credential(&edited_copy)
            .unwrap()
            .set_password("other-secret")
            .unwrap();

        // Forget must still remain visible in the UI and target the SAVED profile's key.
        let mut painted = String::new();
        for _ in 0..2 {
            let mut out = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(900.0, 700.0),
                    )),
                    ..Default::default()
                },
                |ui| {
                    egui::CentralPanel::default().show(ui, |ui| w.profile_form(ui));
                },
            );
            painted.clear();
            for s in &out.shapes {
                rendered_text(&s.shape, &mut painted);
            }
            out.textures_delta.clear();
        }
        assert!(painted.contains("Forget saved password"));

        w.forget_password();
        wait_for_worker(&mut w);
        assert_eq!(w.status, "Saved password removed from OS keychain");
        // A later blank-password connect on the original saved profile must NOT still find prod-secret.
        let mut unflagged_saved = saved.clone();
        unflagged_saved.password_saved = false;
        assert_eq!(
            crate::profiles::saved_password(&unflagged_saved).unwrap_err(),
            "No saved password available; enter one to connect"
        );
        // Unrelated credential under edited_copy was not touched.
        assert_eq!(
            crate::profiles::saved_password(&edited_copy).unwrap(),
            "other-secret"
        );
        // Forgetting again when the entry is already absent reports "Nothing to forget".
        w.forget_password();
        wait_for_worker(&mut w);
        assert!(w.status.contains("Nothing to forget"));

        // Re-save prod-secret on the saved profile, keep edited form values, and test Delete profile.
        crate::profiles::credential(&saved)
            .unwrap()
            .set_password("prod-secret-2")
            .unwrap();
        w.profiles[0].password_saved = true;
        w.delete_profile(true);
        wait_for_worker(&mut w);
        assert!(w.profiles.is_empty());
        assert!(crate::profiles::saved_password(&unflagged_saved).is_err());
        let _ = crate::profiles::delete_saved_password(&edited_copy);
    }
    #[test]
    fn keychain_delete_failure_surfaces_error_and_preserves_saved_state() {
        crate::profiles::credential_status().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profiles.json");
        let saved = Profile {
            name: "locked-delete".into(),
            endpoint: "ldaps://locked.example.org:636".into(),
            base_dn: "dc=example,dc=org".into(),
            bind_dn: "uid=alice,dc=example,dc=org".into(),
            ca_bundle: String::new(),
            password_saved: true,
            ..Profile::default()
        };
        let entry = crate::profiles::credential(&saved).unwrap();
        entry.set_password("cannot-delete-yet").unwrap();
        crate::profiles::save(&path, std::slice::from_ref(&saved)).unwrap();

        let ctx = egui::Context::default();
        let mut w = Workspace::from_path(ctx, Some(path.clone()), None, false);

        // Inject a failure on delete_credential during Forget password.
        let mock: &keyring::mock::Cred = entry.as_any().downcast_ref().unwrap();
        mock.set_error(keyring::Error::NoStorageAccess(Box::new(
            std::io::Error::other("keychain locked"),
        )));
        w.forget_password();
        wait_for_worker(&mut w);
        assert!(
            w.status
                .contains("Could not remove the saved password from the OS keychain"),
            "status was: {}",
            w.status
        );
        assert!(w.profile.password_saved);
        assert!(w.profiles[0].password_saved);
        assert!(crate::profiles::load(&path).unwrap()[0].password_saved);

        // Inject a failure on delete_credential during Delete profile.
        mock.set_error(keyring::Error::NoStorageAccess(Box::new(
            std::io::Error::other("keychain locked"),
        )));
        w.delete_profile(true);
        wait_for_worker(&mut w);
        assert!(
            w.status
                .contains("Could not remove the saved password from the OS keychain")
        );
        assert_eq!(w.profiles.len(), 1);
        assert_eq!(crate::profiles::load(&path).unwrap().len(), 1);

        // Once the error clears, Forget succeeds and removes the secret.
        w.forget_password();
        wait_for_worker(&mut w);
        assert!(!w.profile.password_saved);
        assert!(crate::profiles::saved_password(&saved).is_err());
    }
    #[test]
    fn search_defaults_base_dn_applies_quick_search_and_reports_end_of_results() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = workspace(dir.path().join("profiles.json"));
        assert_eq!(w.scope, 2, "search scope must default to Subtree");
        // Connected with no discovered roots and empty base DN: run_search refuses cleanly without dispatching.
        w.accept_response(w.generation, Response::Connected(vec![]));
        assert!(w.base.is_empty());
        w.run_search();
        assert!(!w.busy);
        assert!(w.status.contains("choose a search base DN"));
        // Connected with a discovered naming context populates base DN automatically when blank.
        w.accept_response(
            w.generation,
            Response::Connected(vec!["dc=example,dc=org".into()]),
        );
        assert_eq!(w.base, "dc=example,dc=org");
        // Typing in quick_search and calling run_search applies smart_filter automatically.
        w.quick_search = "alice".into();
        w.run_search();
        assert_eq!(
            w.filter, "(|(uid=alice)(cn=*alice*)(mail=alice))",
            "run_search must apply quick_search when filter is still default"
        );
        assert!(w.busy);
        // Final page (next = None) reports End of results.
        w.busy = false;
        w.accept_response(
            w.generation,
            Response::Page(
                Key::Search,
                fixture_query(),
                500,
                Box::new(fixture_page(1)),
                true,
            ),
        );
        assert!(
            w.status.starts_with("End of results · 500 rows"),
            "unexpected final page status: {}",
            w.status
        );
    }
    #[test]
    fn quick_search_preserves_hand_edited_filter_until_use_smart_filter() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = workspace(dir.path().join("profiles.json"));
        w.accept_response(
            w.generation,
            Response::Connected(vec!["dc=example,dc=org".into()]),
        );
        // When filter is still default or matches the last generated filter, typing in quick_search updates it.
        w.quick_search = "al".into();
        w.sync_quick_search_filter();
        assert_eq!(w.filter, "(|(uid=al)(cn=*al*)(mail=al))");
        w.quick_search = "alice".into();
        w.sync_quick_search_filter();
        assert_eq!(w.filter, "(|(uid=alice)(cn=*alice*)(mail=alice))");

        // User hand-edits the LDAP filter field.
        w.filter = "(&(objectClass=person)(uid=alice))".into();
        // Subsequent keystrokes in quick_search or running search must NOT overwrite the hand-edited filter.
        w.quick_search = "bob".into();
        w.sync_quick_search_filter();
        assert_eq!(
            w.filter, "(&(objectClass=person)(uid=alice))",
            "hand-edited LDAP filter must not be overwritten by quick_search keystrokes"
        );
        w.run_search();
        assert_eq!(
            w.filter, "(&(objectClass=person)(uid=alice))",
            "run_search must preserve hand-edited LDAP filter"
        );
        w.busy = false;

        // Explicitly clicking "Use smart filter" replaces the filter and re-couples quick_search.
        assert!(w.apply_quick_search_filter());
        assert_eq!(w.filter, "(|(uid=bob)(cn=*bob*)(mail=bob))");
        w.quick_search = "carol".into();
        w.sync_quick_search_filter();
        assert_eq!(w.filter, "(|(uid=carol)(cn=*carol*)(mail=carol))");
    }
    #[test]
    fn ldif_file_load_and_save_report_specific_errors_and_create_0600_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = workspace(dir.path().join("profiles.json"));
        w.transfer = "dn: cn=Alice,dc=example\ncn: Alice\n".into();
        // Empty path
        w.file.clear();
        w.load_ldif_file();
        assert!(w.status.contains("enter a file path"));
        w.save_ldif_file();
        assert!(w.status.contains("enter a file path"));
        // Missing file on load
        w.file = dir.path().join("missing.ldif").to_str().unwrap().into();
        w.load_ldif_file();
        assert!(w.status.contains("file not found"));
        // Directory path on load
        w.file = dir.path().to_str().unwrap().into();
        w.load_ldif_file();
        assert!(w.status.contains("path is a directory"));
        // Missing parent directory on save
        w.file = dir
            .path()
            .join("no-such-folder")
            .join("out.ldif")
            .to_str()
            .unwrap()
            .into();
        w.save_ldif_file();
        assert!(w.status.contains("parent folder does not exist"));
        // Save new file succeeds and sets 0600 on Unix; second save refuses to overwrite.
        let target = dir.path().join("exported.ldif");
        w.file = target.to_str().unwrap().into();
        w.save_ldif_file();
        assert_eq!(w.status, "LDIF saved to new file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        w.save_ldif_file();
        assert!(w.status.contains("file already exists"));
        // Load saved file back into transfer draft.
        w.transfer.clear();
        w.load_ldif_file();
        assert!(w.transfer.contains("cn: Alice"));
        assert_eq!(w.status, "LDIF file loaded into draft");
    }
    #[test]
    fn ldap_code_descriptions_cover_common_rfc4511_errors() {
        for (rc, expected) in [
            (32, "noSuchObject"),
            (34, "invalidDNSyntax"),
            (49, "invalidCredentials"),
            (50, "insufficientAccessRights"),
            (53, "unwillingToPerform"),
            (65, "objectClassViolation"),
            (68, "entryAlreadyExists"),
        ] {
            assert!(
                crate::directory::ldap_code_description(rc).contains(expected),
                "rc {rc} missing {expected}"
            );
        }
    }
}
