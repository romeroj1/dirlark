use crate::{
    ldif::{AttributeChange, Change},
    model::{Entry, Profile, protected_attribute},
    paging::{self, Capabilities, Cursor, Mode, Page, Query},
};
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Mod, Scope, SearchEntry, SearchOptions};
use std::{
    collections::HashSet,
    fs,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use zeroize::Zeroizing;

pub const TIMEOUT: Duration = Duration::from_secs(15);
fn network_error(_: impl std::fmt::Display) -> String {
    "LDAP operation failed; verify TLS trust, hostname, connectivity and access rights".into()
}
fn check(result: ldap3::LdapResult) -> Result<(), String> {
    if result.rc == 0 {
        Ok(())
    } else if matches!(result.rc, 3 | 4 | 11) {
        Err(limit_message(result.rc))
    } else {
        Err(format!(
            "LDAP result {} (operation was not successful)",
            result.rc
        ))
    }
}
fn limit_message(code: u32) -> String {
    let kind = match code {
        3 => "time",
        4 => "size",
        _ => "administrative",
    };
    format!(
        "Server {kind} limit reached; results are incomplete. Refine your search (narrow the filter or base); if a page was refused, reduce the page size. No total is assumed"
    )
}
fn convert(raw: ldap3::ResultEntry) -> Entry {
    let found = SearchEntry::construct(raw);
    let mut attrs = std::collections::BTreeMap::new();
    for (k, v) in found.attrs {
        attrs.insert(k, v.into_iter().map(String::into_bytes).collect());
    }
    for (k, v) in found.bin_attrs {
        attrs.entry(k).or_insert_with(Vec::new).extend(v);
    }
    Entry {
        dn: found.dn,
        attrs,
    }
}
pub fn tls_config(ca_bundle: &str) -> Result<Arc<rustls::ClientConfig>, String> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    if !ca_bundle.is_empty() {
        let bytes = fs::read(ca_bundle).map_err(|_| "Cannot read selected CA bundle")?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err("CA bundle exceeds 4 MiB".into());
        }
        use rustls::pki_types::pem::PemObject;
        let certs = rustls::pki_types::CertificateDer::pem_slice_iter(&bytes)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "Invalid PEM CA bundle")?;
        if certs.is_empty() {
            return Err("CA bundle contains no certificates".into());
        }
        for cert in certs {
            roots.add(cert).map_err(|_| "Invalid CA certificate")?;
        }
    }
    if roots.is_empty() {
        return Err("No trusted root certificates available".into());
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| "TLS configuration failed")?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Arc::new(config))
}
pub struct Directory {
    ldap: Ldap,
    driver: tokio::task::JoinHandle<()>,
    connection: uuid::Uuid,
    capabilities: Option<Capabilities>,
}
impl Drop for Directory {
    fn drop(&mut self) {
        self.driver.abort();
    }
}
impl Directory {
    pub async fn connect(profile: &Profile, password: &str) -> Result<Self, String> {
        profile.validate()?;
        if !profile.bind_dn.is_empty() && password.is_empty() {
            return Err("Simple bind requires a nonempty password".into());
        }
        let settings = LdapConnSettings::new()
            .set_conn_timeout(TIMEOUT)
            .set_config(tls_config(&profile.ca_bundle)?);
        let (conn, ldap) = tokio::time::timeout(
            TIMEOUT,
            LdapConnAsync::with_settings(settings, &profile.endpoint),
        )
        .await
        .map_err(|_| "Connection timed out")?
        .map_err(network_error)?;
        let driver = tokio::spawn(async move {
            let _ = conn.drive().await;
        });
        let mut directory = Self {
            ldap,
            driver,
            connection: uuid::Uuid::new_v4(),
            capabilities: None,
        };
        let result = directory
            .ldap
            .with_timeout(TIMEOUT)
            .simple_bind(
                &profile.bind_dn,
                if profile.bind_dn.is_empty() {
                    ""
                } else {
                    password
                },
            )
            .await
            .map_err(network_error)?;
        check(result)?;
        Ok(directory)
    }
    pub async fn disconnect(&mut self) {
        let _ = self.ldap.with_timeout(TIMEOUT).unbind().await;
    }
    pub async fn search(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: Vec<String>,
    ) -> Result<Vec<Entry>, String> {
        let mut stream = self
            .ldap
            .with_timeout(TIMEOUT)
            .with_search_options(SearchOptions::new().sizelimit(500).timelimit(10))
            .streaming_search_with(
                ldap3::adapters::EntriesOnly::new(),
                base,
                scope,
                filter,
                attrs,
            )
            .await
            .map_err(network_error)?;
        let id = stream.ldap_handle().last_id();
        let collected = tokio::time::timeout(TIMEOUT, async {
            let mut entries = Vec::new();
            while let Some(entry) = stream.next().await.map_err(network_error)? {
                if entries.len() >= 500 {
                    return Err("Search exceeds the client limit of 500 entries".to_string());
                }
                entries.push(entry);
            }
            Ok(entries)
        })
        .await
        .unwrap_or_else(|_| Err("Search deadline exceeded".into()));
        let entries = match collected {
            Ok(entries) => entries,
            Err(error) => {
                let _ = stream.ldap_handle().abandon(id).await;
                let _ = stream.finish().await;
                return Err(error);
            }
        };
        let result = stream.finish().await;
        check(result.clone())?;
        if !result.refs.is_empty() {
            return Err(
                "Search returned referrals; they were not followed and results are incomplete"
                    .into(),
            );
        }
        Ok(entries
            .into_iter()
            .map(|raw| {
                let found = SearchEntry::construct(raw);
                let mut attrs = std::collections::BTreeMap::new();
                for (k, v) in found.attrs {
                    attrs.insert(k, v.into_iter().map(String::into_bytes).collect());
                }
                for (k, v) in found.bin_attrs {
                    attrs.entry(k).or_insert_with(Vec::new).extend(v);
                }
                Entry {
                    dn: found.dn,
                    attrs,
                }
            })
            .collect())
    }
    pub async fn capabilities(&mut self) -> Result<Capabilities, String> {
        if let Some(caps) = self.capabilities {
            return Ok(caps);
        }
        let root = self
            .search(
                "",
                Scope::Base,
                "(objectClass=*)",
                vec!["supportedControl".into()],
            )
            .await?;
        let caps = Capabilities::from_controls(
            &root
                .first()
                .map(|e| e.values("supportedControl"))
                .unwrap_or_default(),
        );
        self.capabilities = Some(caps);
        Ok(caps)
    }
    /// One bounded page, never an auto-paging adapter. Cookies stay on their original connection/query.
    pub async fn page(
        &mut self,
        query: &Query,
        size: u16,
        cursor: Option<&Cursor>,
        seek: Option<u32>,
        cancelled: &AtomicBool,
    ) -> Result<Page, String> {
        query.validate(size)?;
        if cancelled.load(Ordering::Acquire) {
            return Err("Search cancelled; restart to continue".into());
        }
        if let Some(c) = cursor
            && (c.connection != self.connection || c.query != *query)
        {
            return Err(
                "Page cursor belongs to another query or connection; restart search".into(),
            );
        }
        let caps = self.capabilities().await?;
        let mut mode = cursor.map(|c| c.mode).unwrap_or(if caps.vlv {
            Mode::Vlv
        } else if caps.paged {
            Mode::Forward
        } else {
            Mode::Limited
        });
        if seek.is_some() && mode != Mode::Vlv {
            return Err(
                "This server supports forward-only paging; restart to revisit evicted rows".into(),
            );
        }
        let mut cookie = cursor.map(|c| c.cookie.clone()).unwrap_or_default();
        let mut offset = seek.unwrap_or_else(|| cursor.map(|c| c.offset).unwrap_or(1));
        if offset == 0 || offset > i32::MAX as u32 {
            return Err("VLV position must be between 1 and 2147483647".into());
        }
        let mut total = cursor.and_then(|c| c.total);
        let mut warning = None;
        loop {
            let controls = match mode {
                Mode::Vlv => paging::vlv(
                    size,
                    offset,
                    total,
                    &cookie,
                    &query.sort,
                    &query.ordering_rule,
                ),
                Mode::Forward => vec![paging::paged(size, &cookie)],
                Mode::Limited => vec![],
            };
            let (entries, result) = self.fetch_page(query, size, controls, cancelled).await?;
            let value = |oid: &str| {
                result
                    .ctrls
                    .iter()
                    .find(|c| c.1.ctype == oid)
                    .and_then(|c| c.1.val.as_deref())
            };
            let control_declined = value(paging::VLV_RESPONSE).is_some_and(|v| {
                paging::vlv_response(v).is_err_and(|e| e.starts_with("Server declined VLV"))
            });
            let declined_vlv = mode == Mode::Vlv
                && (control_declined
                    || matches!(result.rc, 12 | 18 | 53 | 60 | 76)
                    || (result.rc == 0
                        && (value(paging::VLV_RESPONSE).is_none()
                            || value(paging::SORT_RESPONSE).is_none()
                            || value(paging::SORT_RESPONSE)
                                .is_some_and(|v| paging::sort_response(v).is_err()))));
            if declined_vlv {
                mode = if caps.paged {
                    Mode::Forward
                } else {
                    Mode::Limited
                };
                cookie.clear();
                offset = 1;
                total = None;
                warning = Some(
                    "Server declined VLV/sort for this query; restarted with forward-only paging"
                        .into(),
                );
                continue;
            }
            if !result.refs.is_empty() {
                return Err("Referrals were not followed; results are incomplete".into());
            }
            let limited = matches!(result.rc, 3 | 4 | 11);
            if result.rc != 0 && !limited {
                check(result)?;
                unreachable!();
            }
            let mut next = None;
            if limited {
                warning = Some(limit_message(result.rc));
            } else {
                match mode {
                    Mode::Forward => {
                        cookie = paging::paged_response(value(paging::PAGED).ok_or("Server omitted the required paging response; restart with a narrower query")?)?;
                        if !cookie.is_empty() {
                            if entries.is_empty() {
                                return Err(
                                    "Server returned an empty continuing page; restart search"
                                        .into(),
                                );
                            }
                            next = Some(Cursor {
                                connection: self.connection,
                                query: query.clone(),
                                mode,
                                cookie,
                                offset: offset.saturating_add(entries.len() as u32),
                                total: None,
                            });
                        }
                    }
                    Mode::Vlv => {
                        paging::sort_response(
                            value(paging::SORT_RESPONSE).ok_or("Missing sort response")?,
                        )?;
                        let (position, count, context) = paging::vlv_response(
                            value(paging::VLV_RESPONSE).ok_or("Missing VLV response")?,
                        )?;
                        offset = position;
                        total = count;
                        let after = offset.saturating_add(entries.len() as u32);
                        if !entries.is_empty() && count.is_none_or(|n| after <= n) {
                            next = Some(Cursor {
                                connection: self.connection,
                                query: query.clone(),
                                mode,
                                cookie: context,
                                offset: after,
                                total,
                            });
                        }
                    }
                    Mode::Limited => {
                        warning = Some("Server does not advertise paging; showing one bounded window. Narrow the query to browse further".into());
                    }
                }
            }
            return Ok(Page {
                entries,
                next,
                offset,
                total,
                mode,
                warning,
            });
        }
    }
    async fn fetch_page(
        &mut self,
        query: &Query,
        size: u16,
        controls: Vec<ldap3::controls::RawControl>,
        cancelled: &AtomicBool,
    ) -> Result<(Vec<Entry>, ldap3::LdapResult), String> {
        let deadline = if size == 0 {
            Duration::from_secs(1)
        } else {
            TIMEOUT
        };
        let paginated = !controls.is_empty();
        let mut stream = self
            .ldap
            .with_timeout(deadline)
            .with_controls(controls)
            // RFC 2696 sizeLimit is for the entire sequence, not a page. The control,
            // streaming entry/byte guards and deadline enforce the client window.
            .with_search_options(
                SearchOptions::new()
                    .sizelimit(if paginated { 0 } else { i32::from(size) })
                    .timelimit(10),
            )
            .streaming_search_with(
                ldap3::adapters::EntriesOnly::new(),
                &query.base,
                [Scope::Base, Scope::OneLevel, Scope::Subtree][usize::from(query.scope)],
                &query.filter,
                query.attrs.clone(),
            )
            .await
            .map_err(network_error)?;
        let id = stream.ldap_handle().last_id();
        let collected = tokio::time::timeout(deadline, async {
            let cancellation = async { while !cancelled.load(Ordering::Acquire) { tokio::time::sleep(Duration::from_millis(20)).await; } };
            tokio::pin!(cancellation);
            let mut entries = Vec::new();
            let mut bytes = 0usize;
            loop {
                let raw = tokio::select! {
                    biased;
                    _ = &mut cancellation => return Err("Search cancelled; restart to continue".to_string()),
                    raw = stream.next() => raw.map_err(network_error)?,
                };
                let Some(raw) = raw else { break; };
                if raw.is_ref() || raw.is_intermediate() { return Err("Referrals/intermediate results were not followed; results are incomplete".into()); }
                if entries.len() >= usize::from(size) { return Err("Server exceeded the requested page size; narrow the query".into()); }
                let entry = convert(raw);
                bytes = bytes.saturating_add(paging::entry_bytes(&entry));
                if bytes > paging::PAGE_BYTES { return Err("Page exceeds the 2 MiB client budget; request fewer attributes or a smaller page".into()); }
                entries.push(entry);
            }
            Ok(entries)
        }).await.unwrap_or_else(|_| Err("Search deadline exceeded; narrow the query or reduce page size".into()));
        match collected {
            Ok(entries) => Ok((entries, stream.finish().await)),
            Err(error) => {
                let _ = stream.ldap_handle().with_timeout(TIMEOUT).abandon(id).await;
                let _ = stream.finish().await;
                Err(error)
            }
        }
    }
    /// Release an idle RFC 2696 sequence. VLV contexts are server-managed.
    pub async fn close_cursor(&mut self, cursor: Cursor) {
        if cursor.connection == self.connection
            && cursor.mode == Mode::Forward
            && !cursor.cookie.is_empty()
        {
            let _ = self
                .fetch_page(
                    &cursor.query,
                    0,
                    vec![paging::paged(0, &cursor.cookie)],
                    &AtomicBool::new(false),
                )
                .await;
        }
    }
    pub async fn read(&mut self, dn: &str) -> Result<Entry, String> {
        self.search(
            dn,
            Scope::Base,
            "(objectClass=*)",
            vec!["*".into(), "+".into()],
        )
        .await?
        .into_iter()
        .next()
        .ok_or("Entry was not returned".into())
    }
    pub async fn schema(&mut self, base: &str) -> Result<Vec<Entry>, String> {
        let root = self.read(base).await?;
        let schema = if let Some(dn) = root.values("subschemaSubentry").first() {
            dn.clone()
        } else {
            self.read("")
                .await?
                .values("subschemaSubentry")
                .first()
                .cloned()
                .ok_or("Server did not advertise a subschema entry")?
        };
        self.search(
            &schema,
            Scope::Base,
            "(objectClass=*)",
            vec![
                "attributeTypes".into(),
                "objectClasses".into(),
                "ldapSyntaxes".into(),
                "matchingRules".into(),
                "matchingRuleUse".into(),
            ],
        )
        .await
    }
    pub async fn apply_changes(
        &mut self,
        changes: &[Change],
        expected: Option<&Entry>,
    ) -> Result<usize, String> {
        if let Some(original) = expected
            && self.read(&original.dn).await? != *original
        {
            return Err("Entry changed on the server; reload and review the draft again".into());
        }
        for (applied, change) in changes.iter().enumerate() {
            if let Err(error) = self.apply(change).await {
                return Err(format!(
                    "{applied}/{} records applied; stopped: {error}",
                    changes.len()
                ));
            }
        }
        Ok(changes.len())
    }
    pub async fn apply(&mut self, change: &Change) -> Result<(), String> {
        if change.dn().is_empty() {
            return Err("Root DSE writes are forbidden".into());
        }
        let result = match change {
            Change::Add(e) => {
                if e.attrs.keys().any(|a| protected_attribute(a)) {
                    return Err("Protected attributes cannot be imported".into());
                }
                let attrs = e
                    .attrs
                    .iter()
                    .map(|(k, v)| {
                        (
                            k.as_bytes().to_vec(),
                            v.iter().cloned().collect::<HashSet<_>>(),
                        )
                    })
                    .collect();
                self.ldap.with_timeout(TIMEOUT).add(&e.dn, attrs).await
            }
            Change::Delete(dn) => self.ldap.with_timeout(TIMEOUT).delete(dn).await,
            Change::Modify { dn, changes } => {
                let mut mods = Vec::new();
                for c in changes {
                    let (name, values) = match c {
                        AttributeChange::Add(a, v)
                        | AttributeChange::Replace(a, v)
                        | AttributeChange::Delete(a, v) => (a, v),
                    };
                    if protected_attribute(name) {
                        return Err("Protected attribute is read-only".into());
                    }
                    let name = name.as_bytes().to_vec();
                    let values = values.iter().cloned().collect();
                    mods.push(match c {
                        AttributeChange::Add(..) => Mod::Add(name, values),
                        AttributeChange::Replace(..) => Mod::Replace(name, values),
                        AttributeChange::Delete(..) => Mod::Delete(name, values),
                    });
                }
                self.ldap.with_timeout(TIMEOUT).modify(dn, mods).await
            }
        }
        .map_err(network_error)?;
        check(result)
    }
}
// Deliberately no Debug: a queued request may contain a password or directory data.
pub enum Request {
    CredentialStatus,
    Connect(Profile, Zeroizing<String>, bool),
    Disconnect,
    Page {
        key: crate::page_cache::Key,
        query: Query,
        size: u16,
        cursor: Option<Box<Cursor>>,
        seek: Option<u32>,
        reset: bool,
        cancelled: Arc<AtomicBool>,
        release: Vec<Cursor>,
    },
    CloseCursors(Vec<Cursor>),
    Read(String),
    Schema(String),
    Apply {
        changes: Vec<Change>,
        expected: Option<Entry>,
    },
    SaveProfiles(std::path::PathBuf, Vec<Profile>),
}
pub enum Response {
    CredentialStatus(Result<(), String>),
    Connected(Vec<String>),
    Disconnected,
    Page(crate::page_cache::Key, Query, u16, Box<Page>, bool),
    Closed,
    Read(Entry),
    Schema(Vec<Entry>),
    Applied(usize),
    Saved,
    Error(String),
}
pub struct Worker {
    pub sender: std::sync::mpsc::SyncSender<(u64, Request)>,
    pub receiver: std::sync::mpsc::Receiver<(u64, Response)>,
}
impl Worker {
    pub fn start(ctx: eframe::egui::Context) -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel::<(u64, Request)>(4);
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(4);
        std::thread::spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            runtime.block_on(async move {
                let mut directory: Option<Directory> = None;
                while let Ok((generation, request)) = rx.recv() {
                    let result = execute(&mut directory, request)
                        .await
                        .unwrap_or_else(Response::Error);
                    if result_tx.send((generation, result)).is_err() {
                        break;
                    }
                    ctx.request_repaint();
                }
                if let Some(mut d) = directory {
                    d.disconnect().await;
                }
            });
        });
        Self {
            sender: tx,
            receiver: result_rx,
        }
    }
}
async fn execute(directory: &mut Option<Directory>, request: Request) -> Result<Response, String> {
    match request {
        Request::CredentialStatus => Ok(Response::CredentialStatus(
            crate::profiles::credential_status(),
        )),
        Request::Connect(p, mut password, remember) => {
            if let Some(mut d) = directory.take() {
                d.disconnect().await;
            }
            if !p.bind_dn.is_empty() && password.is_empty() {
                *password = crate::profiles::saved_password(&p)?;
            }
            let mut d = Directory::connect(&p, &password).await?;
            let roots = if p.base_dn.is_empty() {
                d.read("").await?.values("namingContexts")
            } else {
                vec![p.base_dn.clone()]
            };
            if remember && !p.bind_dn.is_empty() {
                crate::profiles::credential(&p)?
                    .set_password(&password)
                    .map_err(|_| "Connected, but credential storage failed; connection closed")?;
            }
            *directory = Some(d);
            Ok(Response::Connected(roots))
        }
        Request::CloseCursors(cursors) => {
            if let Some(d) = directory {
                for cursor in cursors {
                    d.close_cursor(cursor).await;
                }
            }
            Ok(Response::Closed)
        }
        Request::Disconnect => {
            if let Some(mut d) = directory.take() {
                d.disconnect().await;
            }
            Ok(Response::Disconnected)
        }
        Request::SaveProfiles(path, profiles) => {
            crate::profiles::save(&path, &profiles)?;
            Ok(Response::Saved)
        }
        other => {
            let d = directory.as_mut().ok_or("Connect to a directory first")?;
            match other {
                Request::Page {
                    key,
                    query,
                    size,
                    cursor,
                    seek,
                    reset,
                    cancelled,
                    release,
                } => {
                    for cursor in release {
                        d.close_cursor(cursor).await;
                    }
                    let page = d
                        .page(&query, size, cursor.as_deref(), seek, &cancelled)
                        .await?;
                    Ok(Response::Page(key, query, size, Box::new(page), reset))
                }
                Request::Read(dn) => Ok(Response::Read(d.read(&dn).await?)),
                Request::Schema(base) => Ok(Response::Schema(d.schema(&base).await?)),
                Request::Apply { changes, expected } => Ok(Response::Applied(
                    d.apply_changes(&changes, expected.as_ref()).await?,
                )),
                _ => unreachable!(),
            }
        }
    }
}
