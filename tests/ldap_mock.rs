//! A minimal in-process LDAPS peer: generated test-only keys, no slapd or real credentials.
use dirlark::{
    directory::Directory,
    ldif::{AttributeChange, Change},
    model::Profile,
    paging::{self, Mode, Query},
};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use std::{
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::TlsAcceptor;

fn tlv(tag: u8, value: impl AsRef<[u8]>) -> Vec<u8> {
    let v = value.as_ref();
    let mut out = vec![tag];
    if v.len() < 128 {
        out.push(v.len() as u8);
    } else {
        let n = (v.len() as u32).to_be_bytes();
        let p = n.iter().position(|x| *x != 0).unwrap();
        out.push(0x80 | (4 - p) as u8);
        out.extend_from_slice(&n[p..]);
    }
    out.extend_from_slice(v);
    out
}
fn fields(mut input: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = vec![];
    while !input.is_empty() {
        let tag = input[0];
        let b = input[1];
        let (len, start) = if b < 128 {
            (b as usize, 2)
        } else {
            let n = (b & 127) as usize;
            let len = input[2..2 + n]
                .iter()
                .fold(0, |a, b| (a << 8) | *b as usize);
            (len, 2 + n)
        };
        out.push((tag, input[start..start + len].to_vec()));
        input = &input[start + len..];
    }
    out
}
fn message(id: &[u8], op: Vec<u8>) -> Vec<u8> {
    tlv(0x30, [tlv(2, id), op].concat())
}
fn result(id: &[u8], tag: u8, code: u8) -> Vec<u8> {
    message(
        id,
        tlv(tag, [tlv(10, [code]), tlv(4, []), tlv(4, [])].concat()),
    )
}
fn entry(id: &[u8], dn: &str, attrs: &[(&str, &[&str])]) -> Vec<u8> {
    let attrs = attrs
        .iter()
        .flat_map(|(k, values)| {
            tlv(
                0x30,
                [
                    tlv(4, k),
                    tlv(
                        0x31,
                        values.iter().flat_map(|s| tlv(4, s)).collect::<Vec<_>>(),
                    ),
                ]
                .concat(),
            )
        })
        .collect::<Vec<_>>();
    message(id, tlv(0x64, [tlv(4, dn), tlv(0x30, attrs)].concat()))
}
// Force a real TLS writer to retain its final record once. A socket may do
// exactly this under backpressure: write_all accepts plaintext, not delivery.
struct BackpressuredSocket {
    inner: TcpStream,
    pause_once: Arc<AtomicBool>,
}
impl AsyncRead for BackpressuredSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for BackpressuredSocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.pause_once.swap(false, Ordering::AcqRel) {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

type Bind = (Vec<u8>, Vec<u8>);
struct Mock {
    profile: Profile,
    _ca: tempfile::NamedTempFile,
    task: tokio::task::JoinHandle<()>,
    operations: Arc<Mutex<Vec<u8>>>,
    binds: Arc<Mutex<Vec<Bind>>>,
    generated: Arc<AtomicUsize>,
    buffered_tails: Arc<AtomicUsize>,
}
impl Drop for Mock {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Mock {
    async fn start(host: &str, expired: bool) -> Self {
        let mut ca = CertificateParams::new(vec![]).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca.self_signed(&ca_key).unwrap();
        let mut leaf = CertificateParams::new(vec![host.into()]).unwrap();
        if expired {
            leaf.not_before = rcgen::date_time_ymd(2000, 1, 1);
            leaf.not_after = rcgen::date_time_ymd(2001, 1, 1);
        }
        let leaf_key = KeyPair::generate().unwrap();
        let issuer = Issuer::from_params(&ca, &ca_key);
        let cert = leaf.signed_by(&leaf_key, &issuer).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let operations = Arc::new(Mutex::new(vec![]));
        let seen = operations.clone();
        let binds = Arc::new(Mutex::new(vec![]));
        let seen_binds = binds.clone();
        let generated = Arc::new(AtomicUsize::new(0));
        let generated_task = generated.clone();
        let buffered_tails = Arc::new(AtomicUsize::new(0));
        let buffered_task = buffered_tails.clone();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                stream.set_nodelay(true).unwrap();
                let acceptor = acceptor.clone();
                let seen = seen.clone();
                let seen_binds = seen_binds.clone();
                let generated = generated_task.clone();
                let buffered_tails = buffered_task.clone();
                tokio::spawn(async move {
                    let pause_once = Arc::new(AtomicBool::new(false));
                    let socket = BackpressuredSocket {
                        inner: stream,
                        pause_once: pause_once.clone(),
                    };
                    let Ok(mut stream) = acceptor.accept(socket).await else {
                        return;
                    };
                    loop {
                        let Ok(tag) = stream.read_u8().await else {
                            return;
                        };
                        if tag != 0x30 {
                            return;
                        }
                        let Ok(b) = stream.read_u8().await else {
                            return;
                        };
                        let len = if b < 128 {
                            b as usize
                        } else {
                            let mut n = vec![0; (b & 127) as usize];
                            if stream.read_exact(&mut n).await.is_err() {
                                return;
                            }
                            n.iter().fold(0, |a, b| (a << 8) | *b as usize)
                        };
                        if len > 1024 * 1024 {
                            return;
                        }
                        let mut body = vec![0; len];
                        if stream.read_exact(&mut body).await.is_err() {
                            return;
                        }
                        let f = fields(&body);
                        let id = &f[0].1;
                        let (op, data) = &f[1];
                        seen.lock().unwrap().push(*op);
                        if *op == 0x60 {
                            // Simple bind: version, name, [0] password.
                            let b = fields(data);
                            seen_binds
                                .lock()
                                .unwrap()
                                .push((b[1].1.clone(), b[2].1.clone()));
                        }
                        let mut oversized = false;
                        let mut fragmented = false;
                        let mut truncated = false;
                        let reply = match op {
                            0x60 => result(id, 0x61, 0),
                            0x42 => return,
                            0x50 => continue,
                            0x63 => {
                                let parts = fields(data);
                                let base = String::from_utf8_lossy(&parts[0].1);
                                if base == "dc=slow" {
                                    continue;
                                }
                                if base.starts_with("dc=million") {
                                    if base == "dc=million-children" {
                                        assert_eq!(uint(&parts[1].1), 1);
                                    }
                                    let controls = f
                                        .get(2)
                                        .map(|(_, value)| fields(value))
                                        .unwrap_or_default();
                                    let find = |oid: &str| {
                                        controls.iter().find_map(|(_, raw)| {
                                            let c = fields(raw);
                                            (c[0].1 == oid.as_bytes())
                                                .then(|| c.last().unwrap().1.clone())
                                        })
                                    };
                                    let page = find(paging::PAGED);
                                    let vlv = find(paging::VLV);
                                    let mut response_controls = vec![];
                                    let (offset, size) = if let Some(page) = page {
                                        let inner = fields(&page);
                                        let values = fields(&inner[0].1);
                                        let size = uint(&values[0].1);
                                        let offset = String::from_utf8(values[1].1.clone())
                                            .unwrap()
                                            .parse::<u32>()
                                            .unwrap_or(0);
                                        let next = (offset + size).min(1_000_000);
                                        let cookie = if size == 0 || next == 1_000_000 {
                                            String::new()
                                        } else {
                                            next.to_string()
                                        };
                                        response_controls.push(raw_control(
                                            paging::PAGED,
                                            tlv(0x30, [int(1_000_000), tlv(4, cookie)].concat()),
                                        ));
                                        (offset, size)
                                    } else if let Some(vlv) = vlv {
                                        assert!(find(paging::SORT).is_some());
                                        if base == "dc=million-fallback" {
                                            stream.write_all(&result(id, 0x65, 12)).await.unwrap();
                                            stream.flush().await.unwrap();
                                            continue;
                                        }
                                        let inner = fields(&vlv);
                                        let values = fields(&inner[0].1);
                                        let target = fields(&values[2].1);
                                        let offset = uint(&target[0].1) - 1;
                                        let size = uint(&values[0].1) + uint(&values[1].1) + 1;
                                        response_controls.push(raw_control(
                                            paging::SORT_RESPONSE,
                                            tlv(0x30, tlv(10, [0])),
                                        ));
                                        response_controls.push(raw_control(
                                            paging::VLV_RESPONSE,
                                            tlv(
                                                0x30,
                                                [
                                                    int(offset + 1),
                                                    int(1_000_000),
                                                    tlv(10, [0]),
                                                    tlv(4, b"test-context"),
                                                ]
                                                .concat(),
                                            ),
                                        ));
                                        (offset, size)
                                    } else {
                                        (0, 25)
                                    };
                                    assert!(
                                        size <= 500,
                                        "client must never request an unbounded page"
                                    );
                                    let count = size.min(1_000_000 - offset);
                                    for n in offset..offset + count {
                                        let dn = format!("cn=Person{n:07},dc=example");
                                        stream
                                            .write_all(&entry(
                                                id,
                                                &dn,
                                                &[
                                                    ("cn", &["Scale fixture"]),
                                                    ("numSubordinates", &["0"]),
                                                ],
                                            ))
                                            .await
                                            .unwrap();
                                        generated.fetch_add(1, Ordering::Relaxed);
                                    }
                                    let mut done = fields(&result(id, 0x65, 0)).remove(0).1;
                                    done.extend(tlv(0xa0, response_controls.concat()));
                                    stream.write_all(&tlv(0x30, done)).await.unwrap();
                                    stream.flush().await.unwrap();
                                    continue;
                                }
                                let e = if base.is_empty() {
                                    entry(
                                        id,
                                        "",
                                        &[
                                            ("objectClass", &["top"]),
                                            (
                                                "supportedControl",
                                                &[paging::PAGED, paging::SORT, paging::VLV],
                                            ),
                                            ("namingContexts", &["dc=example"]),
                                            ("subschemaSubentry", &["cn=schema"]),
                                        ],
                                    )
                                } else if base == "cn=schema" {
                                    entry(
                                        id,
                                        "cn=schema",
                                        &[("attributeTypes", &["( 2.5.4.3 NAME 'cn' )"])],
                                    )
                                } else if base == "cn=CredentialFixture,dc=example" {
                                    entry(
                                        id,
                                        "cn=CredentialFixture,dc=example",
                                        &[
                                            ("objectClass", &["person"]),
                                            ("cn", &["CredentialFixture"]),
                                            ("sn", &["Example"]),
                                            ("userPassword", &["{SSHA}synthetic-test-only-hash"]),
                                            ("unicodePwd;binary", &["synthetic-unicode-pwd"]),
                                        ],
                                    )
                                } else {
                                    entry(
                                        id,
                                        "cn=Pilot,dc=example",
                                        &[
                                            ("objectClass", &["person"]),
                                            ("cn", &["Pilot"]),
                                            ("sn", &["Example"]),
                                            ("subschemaSubentry", &["cn=schema"]),
                                        ],
                                    )
                                };
                                match base.as_ref() {
                                    "dc=overflow" => [e.repeat(501), result(id, 0x65, 0)].concat(),
                                    "dc=partial" => [e, result(id, 0x65, 4)].concat(),
                                    "dc=admin" => [e, result(id, 0x65, 11)].concat(),
                                    "dc=time" => [e, result(id, 0x65, 3)].concat(),
                                    "dc=byte-overflow" | "dc=byte-overflow-fragmented" => {
                                        oversized = true;
                                        fragmented = base.ends_with("-fragmented");
                                        [
                                            entry(
                                                id,
                                                "cn=Large,dc=example",
                                                &[(
                                                    "description",
                                                    &[&"x".repeat(paging::PAGE_BYTES)],
                                                )],
                                            ),
                                            result(id, 0x65, 0),
                                        ]
                                        .concat()
                                    }
                                    "dc=byte-truncated" => {
                                        truncated = true;
                                        let mut reply = entry(
                                            id,
                                            "cn=Large,dc=example",
                                            &[("description", &[&"x".repeat(paging::PAGE_BYTES)])],
                                        );
                                        reply.truncate(128);
                                        reply
                                    }
                                    "dc=referral" => [
                                        e,
                                        message(
                                            id,
                                            tlv(0x73, tlv(4, "ldaps://elsewhere.invalid:636")),
                                        ),
                                        result(id, 0x65, 0),
                                    ]
                                    .concat(),
                                    _ => [e, result(id, 0x65, 0)].concat(),
                                }
                            }
                            0x66 => result(id, 0x67, 0),
                            0x68 => result(id, 0x69, 0),
                            0x4a => result(
                                id,
                                0x6b,
                                if data == b"cn=Denied,dc=example" {
                                    50
                                } else {
                                    0
                                },
                            ),
                            _ => return,
                        };
                        if oversized {
                            let (prefix, tail) = reply.split_at(reply.len() - 64);
                            for chunk in prefix.chunks(if fragmented { 4096 } else { prefix.len() })
                            {
                                if stream.write_all(chunk).await.is_err() {
                                    return;
                                }
                                if fragmented {
                                    tokio::task::yield_now().await;
                                }
                            }
                            if stream.flush().await.is_err() {
                                return;
                            }
                            tokio::time::sleep(Duration::from_millis(5)).await;
                            pause_once.store(true, Ordering::Release);
                            if stream.write_all(tail).await.is_err() {
                                return;
                            }
                            assert!(
                                stream.get_ref().1.wants_write(),
                                "fixture must retain the final TLS record"
                            );
                            buffered_tails.fetch_add(1, Ordering::Relaxed);
                        } else if stream.write_all(&reply).await.is_err() {
                            return;
                        }
                        // write_all accepts TLS plaintext; a final encrypted record can
                        // remain buffered after socket backpressure. Drain it before
                        // waiting for the next LDAP request, including on Windows.
                        if stream.flush().await.is_err() {
                            return;
                        }
                        if truncated {
                            return;
                        }
                    }
                });
            }
        });
        let mut ca_file = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        ca_file.write_all(ca_cert.pem().as_bytes()).unwrap();
        let profile = Profile {
            endpoint: format!("ldaps://localhost:{port}"),
            ca_bundle: ca_file.path().to_str().unwrap().into(),
            base_dn: "dc=example".into(),
            ..Default::default()
        };
        Self {
            profile,
            _ca: ca_file,
            task,
            operations,
            binds,
            generated,
            buffered_tails,
        }
    }
}
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}
#[test]
fn ldaps_protocol_read_write_schema_and_unbind() {
    runtime().block_on(async {
        tokio::time::timeout(Duration::from_secs(10), async {
            let server = Mock::start("localhost", false).await;
            let (mut client, capture) = Directory::connect_observed(&server.profile, "")
                .await
                .unwrap();
            assert_eq!(capture.failure, None);
            assert!(!capture.chain.is_empty());
            assert!(matches!(capture.protocol, Some("TLS 1.2" | "TLS 1.3")));
            let leaf = dirlark::certificates::inspect(
                &capture.chain[0],
                dirlark::certificates::Kind::Certificate,
                x509_parser::time::ASN1Time::now().timestamp(),
            )
            .unwrap();
            let fields = &leaf[0].certificate.as_ref().unwrap().fields;
            assert!(
                fields
                    .iter()
                    .any(|(name, value)| name.starts_with("SAN ") && value.contains("localhost"))
            );
            let root = client.read("").await.unwrap();
            assert_eq!(root.values("namingContexts"), vec!["dc=example"]);
            let found = client
                .search(
                    "dc=example",
                    ldap3::Scope::Subtree,
                    "(cn=Pilot)",
                    vec!["*".into()],
                )
                .await
                .unwrap();
            assert_eq!(found.len(), 1);
            assert!(
                !client.schema("dc=example").await.unwrap()[0]
                    .values("attributeTypes")
                    .is_empty()
            );
            client
                .apply(&Change::Modify {
                    dn: found[0].dn.clone(),
                    changes: vec![AttributeChange::Replace(
                        "description".into(),
                        vec![b"fixture".to_vec()],
                    )],
                })
                .await
                .unwrap();
            let mut new_entry = found[0].clone();
            new_entry
                .attrs
                .retain(|name, _| !dirlark::model::protected_attribute(name));
            client.apply(&Change::Add(new_entry)).await.unwrap();
            client
                .apply(&Change::Delete(found[0].dn.clone()))
                .await
                .unwrap();
            client.disconnect().await;
            let seen = server.operations.lock().unwrap();
            assert!(
                seen.contains(&0x60)
                    && seen.contains(&0x63)
                    && seen.contains(&0x66)
                    && seen.contains(&0x68)
                    && seen.contains(&0x4a)
            );
        })
        .await
        .unwrap();
    });
}
#[test]
fn simple_bind_requires_nonempty_secret_and_rejects_password_with_blank_bind_dn() {
    runtime().block_on(async {
        let mut server = Mock::start("localhost", false).await;
        // Blank Bind DN with a non-empty password must be rejected locally without sending an anonymous bind.
        for blank_dn in ["", "   "] {
            server.profile.bind_dn = blank_dn.into();
            let err = Directory::connect(&server.profile, "test-only-not-a-real-credential")
                .await
                .err()
                .unwrap();
            assert_eq!(err, dirlark::directory::BLANK_BIND_DN_WITH_PASSWORD);
            assert!(
                server.operations.lock().unwrap().is_empty(),
                "no LDAP operation may be sent when Bind DN is blank and password is non-empty"
            );
        }
        // Anonymous bind (blank Bind DN and blank password) remains unchanged and succeeds.
        server.profile.bind_dn.clear();
        let mut anon = Directory::connect(&server.profile, "").await.unwrap();
        anon.disconnect().await;
        // Exactly one bind, with an empty name and an empty password on the wire.
        assert_eq!(
            *server.binds.lock().unwrap(),
            vec![(Vec::<u8>::new(), Vec::<u8>::new())]
        );
        server.operations.lock().unwrap().clear();
        server.binds.lock().unwrap().clear();

        // Non-empty Bind DN with blank password is still rejected without network operations.
        server.profile.bind_dn = "cn=fixture,dc=example".into();
        assert!(Directory::connect(&server.profile, "").await.is_err());
        assert!(server.operations.lock().unwrap().is_empty());
        let mut c = Directory::connect(&server.profile, "test-only-not-a-real-credential")
            .await
            .unwrap();
        c.disconnect().await;
        // Positive control: an authenticated bind does carry the password, so the capture works.
        assert_eq!(
            *server.binds.lock().unwrap(),
            vec![(
                b"cn=fixture,dc=example".to_vec(),
                b"test-only-not-a-real-credential".to_vec()
            )]
        );
    });
}
#[test]
fn simple_bind_sends_the_exact_password_bytes_including_symbols() {
    // Symbols, quoting characters, LDAP/URL-special characters and non-ASCII text
    // must reach the server byte-for-byte, with no trimming or re-encoding.
    let secrets = [
        "p@ss\"w\\rd!#$%&'()*+,-./:;<=>?[]^_`{|}~",
        "caf\u{e9}-\u{a3}-\u{20ac}-\u{f8}-\u{1f511}",
        " leading and trailing space ",
        "tab\tinside",
    ];
    runtime().block_on(async {
        let mut server = Mock::start("localhost", false).await;
        server.profile.bind_dn = "uid=test.user,ou=People,dc=example".into();
        for secret in secrets {
            let mut c = Directory::connect(&server.profile, secret).await.unwrap();
            c.disconnect().await;
        }
        let seen = server.binds.lock().unwrap();
        assert_eq!(seen.len(), secrets.len());
        for ((dn, password), secret) in seen.iter().zip(secrets) {
            assert_eq!(dn, b"uid=test.user,ou=People,dc=example");
            assert_eq!(
                password,
                secret.as_bytes(),
                "bind password changed on the wire"
            );
        }
    });
}
#[test]
fn tls_rejects_unknown_ca_wrong_host_and_expired_certificate() {
    runtime().block_on(async {
        let server = Mock::start("localhost", false).await;
        let mut unknown = server.profile.clone();
        unknown.ca_bundle.clear();
        let (unknown_err, unknown_capture) = Directory::connect_observed(&unknown, "")
            .await
            .err()
            .unwrap();
        assert!(
            unknown_err.contains("unknown CA") || unknown_err.contains("not trusted"),
            "unexpected unknown CA error: {unknown_err}"
        );
        assert_eq!(unknown_capture.failure, Some("Untrusted issuer"));
        assert!(!unknown_capture.chain.is_empty());
        assert!(server.operations.lock().unwrap().is_empty());
        let wrong = Mock::start("wrong.example", false).await;
        let (wrong_err, wrong_capture) = Directory::connect_observed(&wrong.profile, "")
            .await
            .err()
            .unwrap();
        assert!(
            wrong_err.contains("hostname mismatch") && wrong_err.contains("localhost"),
            "unexpected wrong host error: {wrong_err}"
        );
        assert_eq!(wrong_capture.failure, Some("Hostname mismatch"));
        assert!(!wrong_capture.chain.is_empty());
        assert!(wrong.operations.lock().unwrap().is_empty());
        let expired = Mock::start("localhost", true).await;
        let (expired_err, expired_capture) = Directory::connect_observed(&expired.profile, "")
            .await
            .err()
            .unwrap();
        assert!(
            expired_err.contains("expired"),
            "unexpected expired cert error: {expired_err}"
        );
        assert_eq!(expired_capture.failure, Some("Expired"));
        assert!(!expired_capture.chain.is_empty());
        assert!(expired.operations.lock().unwrap().is_empty());
    });
}
#[test]
fn mock_server_credential_attributes_are_excluded_from_export_by_default_and_included_when_enabled()
{
    runtime().block_on(async {
        let server = Mock::start("localhost", false).await;
        let mut client = Directory::connect(&server.profile, "").await.unwrap();
        let entry = client
            .read("cn=CredentialFixture,dc=example")
            .await
            .unwrap();
        assert!(entry.attrs.contains_key("userPassword"));
        assert!(entry.attrs.contains_key("unicodePwd;binary"));
        let safe_export = dirlark::ldif::export(std::slice::from_ref(&entry));
        assert!(safe_export.contains("cn: CredentialFixture"));
        assert!(!safe_export.contains("userPassword"));
        assert!(!safe_export.contains("unicodePwd"));
        assert!(!safe_export.contains("synthetic-test-only-hash"));
        assert!(!safe_export.contains("synthetic-unicode-pwd"));
        let explicit_export =
            dirlark::ldif::export_with_credentials(std::slice::from_ref(&entry), true);
        assert!(explicit_export.contains("WARNING"));
        assert!(explicit_export.contains("userPassword: {SSHA}synthetic-test-only-hash"));
        assert!(explicit_export.contains("unicodePwd;binary: synthetic-unicode-pwd"));
        client.disconnect().await;
    });
}

#[test]
fn client_rejects_overflow_partial_results_and_referrals() {
    runtime().block_on(async {
        let server = Mock::start("localhost", false).await;
        let mut client = Directory::connect(&server.profile, "").await.unwrap();
        for base in ["dc=overflow", "dc=partial", "dc=referral"] {
            let result = client
                .search(
                    base,
                    ldap3::Scope::Subtree,
                    "(objectClass=*)",
                    vec!["*".into()],
                )
                .await;
            assert!(
                result.is_err(),
                "{base} must not be presented as a complete search"
            );
        }
        assert_eq!(
            server
                .operations
                .lock()
                .unwrap()
                .iter()
                .filter(|op| **op == 0x60)
                .count(),
            1
        );
    });
}
#[test]
fn changed_entry_is_not_overwritten_and_import_reports_partial_progress() {
    runtime().block_on(async {
        let server = Mock::start("localhost", false).await;
        let mut client = Directory::connect(&server.profile, "").await.unwrap();
        let mut original = client.read("cn=Pilot,dc=example").await.unwrap();
        original
            .attrs
            .insert("description".into(), vec![b"older value".to_vec()]);
        let change = Change::Delete(original.dn.clone());
        assert!(
            client
                .apply_changes(&[change], Some(&original))
                .await
                .unwrap_err()
                .contains("changed on the server")
        );
        assert!(!server.operations.lock().unwrap().contains(&0x4a));
        let err = client
            .apply_changes(
                &[
                    Change::Delete("cn=First,dc=example".into()),
                    Change::Delete("cn=Denied,dc=example".into()),
                    Change::Delete("cn=NeverSent,dc=example".into()),
                ],
                None,
            )
            .await
            .unwrap_err();
        assert!(err.starts_with("1/3 records applied; stopped:"));
        assert_eq!(
            server
                .operations
                .lock()
                .unwrap()
                .iter()
                .filter(|op| **op == 0x4a)
                .count(),
            2
        );
    });
}

fn uint(value: &[u8]) -> u32 {
    value.iter().fold(0, |n, b| (n << 8) | u32::from(*b))
}
fn int(n: u32) -> Vec<u8> {
    let mut value = vec![0];
    value.extend(n.to_be_bytes());
    tlv(2, value)
}
fn raw_control(oid: &str, value: Vec<u8>) -> Vec<u8> {
    tlv(0x30, [tlv(4, oid), tlv(4, value)].concat())
}
fn scale_query(base: &str) -> Query {
    Query {
        base: base.into(),
        scope: 2,
        filter: "(objectClass=*)".into(),
        attrs: vec!["cn".into()],
        sort: "cn".into(),
        ordering_rule: String::new(),
    }
}
#[test]
fn million_entry_peer_is_lazy_with_vlv_seek_and_forward_fallback() {
    runtime().block_on(async {
        let server = Mock::start("localhost", false).await;
        let mut client = Directory::connect(&server.profile, "").await.unwrap();
        let cancel = AtomicBool::new(false);
        let query = scale_query("dc=million");
        let first = client.page(&query, 25, None, None, &cancel).await.unwrap();
        assert_eq!(first.mode, Mode::Vlv);
        assert_eq!(first.total, Some(1_000_000));
        assert_eq!(first.entries.len(), 25);
        let last = client
            .page(&query, 25, first.next.as_ref(), Some(999_976), &cancel)
            .await
            .unwrap();
        assert_eq!(last.entries[0].dn, "cn=Person0999975,dc=example");
        assert!(last.next.is_none());
        assert_eq!(server.generated.load(Ordering::Relaxed), 50);
        let query = scale_query("dc=million-fallback");
        let mut page = client
            .page(&query, 500, None, None, &cancel)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "{e}; generated={}, ops={:?}",
                    server.generated.load(Ordering::Relaxed),
                    server.operations.lock().unwrap()
                )
            });
        assert_eq!(page.mode, Mode::Forward);
        assert!(page.warning.as_ref().unwrap().contains("forward-only"));
        assert_eq!(
            page.total, None,
            "RFC 2696 estimate must not be displayed as a total"
        );
        for n in 1..4 {
            page = client
                .page(&query, 500, page.next.as_ref(), None, &cancel)
                .await
                .unwrap();
            assert_eq!(
                page.entries[0].dn,
                format!("cn=Person{:07},dc=example", n * 500)
            );
        }
        assert_eq!(server.generated.load(Ordering::Relaxed), 2050);
        let cursor = page.next.take().unwrap();
        assert!(
            client
                .page(&scale_query("dc=another"), 25, Some(&cursor), None, &cancel)
                .await
                .is_err()
        );
        assert!(
            client
                .page(&query, 25, Some(&cursor), Some(100), &cancel)
                .await
                .is_err()
        );
        client.close_cursor(cursor).await;
        assert_eq!(
            server.generated.load(Ordering::Relaxed),
            2050,
            "closing the sequence must fetch no data"
        );
        for size in [0, 24, 501] {
            assert!(
                client
                    .page(&query, size, None, None, &cancel)
                    .await
                    .is_err()
            );
        }
    });
}
#[test]
fn in_flight_page_cancellation_abandons_without_breaking_connection() {
    runtime().block_on(async {
        let server = Mock::start("localhost", false).await;
        let mut client = Directory::connect(&server.profile, "").await.unwrap();
        client.capabilities().await.unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let trigger = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(60)).await;
            trigger.store(true, Ordering::Release);
        });
        let error = tokio::time::timeout(
            Duration::from_secs(2),
            client.page(&scale_query("dc=slow"), 25, None, None, &cancel),
        )
        .await
        .unwrap()
        .err()
        .unwrap();
        assert!(error.contains("cancelled"));
        assert!(client.read("").await.is_ok());
        assert!(server.operations.lock().unwrap().contains(&0x50));
    });
}

#[test]
fn bounded_pages_report_server_limits_and_reject_oversized_responses() {
    runtime().block_on(async {
        let server = Mock::start("localhost", false).await;
        let mut client = Directory::connect(&server.profile, "").await.unwrap();
        let page = client
            .page(
                &scale_query("dc=partial"),
                25,
                None,
                None,
                &AtomicBool::new(false),
            )
            .await
            .unwrap();
        assert_eq!(page.entries.len(), 1);
        assert!(page.next.is_none());
        assert!(page.warning.unwrap().contains("size limit"));
        let error = client
            .page(
                &scale_query("dc=overflow"),
                25,
                None,
                None,
                &AtomicBool::new(false),
            )
            .await
            .err()
            .unwrap();
        assert!(error.contains("page size"));
    });
}

#[test]
fn paged_children_and_limit_byte_guards_remain_bounded() {
    runtime().block_on(async {
        let server = Mock::start("localhost", false).await;
        let mut client = Directory::connect(&server.profile, "").await.unwrap();
        let cancel = AtomicBool::new(false);
        let mut query = scale_query("dc=million-children");
        query.scope = 1;
        let first = client.page(&query, 500, None, None, &cancel).await.unwrap();
        let second = client
            .page(&query, 500, first.next.as_ref(), None, &cancel)
            .await
            .unwrap();
        assert_eq!(second.entries[0].dn, "cn=Person0000500,dc=example");
        assert_eq!(server.generated.load(Ordering::Relaxed), 1000);
        for (base, kind) in [("dc=admin", "administrative"), ("dc=time", "time")] {
            let page = client
                .page(&scale_query(base), 25, None, None, &cancel)
                .await
                .unwrap();
            assert_eq!(page.entries.len(), 1);
            assert!(page.next.is_none());
            assert!(page.warning.unwrap().contains(kind));
        }
        let error = client
            .page(&scale_query("dc=byte-overflow"), 25, None, None, &cancel)
            .await
            .err()
            .unwrap();
        assert!(
            error.contains("2 MiB"),
            "unexpected page error: {error}; buffered TLS tails: {}",
            server.buffered_tails.load(Ordering::Relaxed)
        );
        assert!(client.read("").await.is_ok());
    });
}

#[test]
fn oversized_pages_keep_byte_limit_under_concurrent_fragmented_tls_delivery() {
    runtime().block_on(async {
        let server = Mock::start("localhost", false).await;
        let mut clients = tokio::task::JoinSet::new();
        // Eight prescribed, independent requests: coverage under load, not retries.
        for n in 0..8 {
            let profile = server.profile.clone();
            clients.spawn(async move {
                let mut client = Directory::connect(&profile, "").await.unwrap();
                let base = if n % 2 == 0 {
                    "dc=byte-overflow"
                } else {
                    "dc=byte-overflow-fragmented"
                };
                let error = client
                    .page(&scale_query(base), 25, None, None, &AtomicBool::new(false))
                    .await
                    .err()
                    .unwrap();
                assert!(
                    error.contains("2 MiB"),
                    "unexpected complete-page error: {error}"
                );
                assert!(
                    client.read("").await.is_ok(),
                    "connection must survive bounded page rejection"
                );
            });
        }
        while let Some(result) = clients.join_next().await {
            result.unwrap();
        }
        assert_eq!(server.buffered_tails.load(Ordering::Relaxed), 8);
    });
}

#[test]
fn truncated_oversize_frame_is_transport_failure_not_a_fabricated_budget_error() {
    runtime().block_on(async {
        let server = Mock::start("localhost", false).await;
        let mut client = Directory::connect(&server.profile, "").await.unwrap();
        let error = client
            .page(
                &scale_query("dc=byte-truncated"),
                25,
                None,
                None,
                &AtomicBool::new(false),
            )
            .await
            .err()
            .unwrap();
        assert_eq!(
            error,
            "LDAP operation failed; verify TLS trust, hostname, connectivity and access rights"
        );
        assert_eq!(server.buffered_tails.load(Ordering::Relaxed), 0);
    });
}
