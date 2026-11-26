#![cfg(all(feature = "shared-ca-store", unix))]

use isahc::{
    config::{CaCertificate, Configurable, SslOption},
    error::ErrorKind,
    HttpClient,
};
use once_cell::sync::Lazy;
use std::{fs, path::PathBuf};
use tls_support::{capture_client_hello, TestCa, TlsServer};

mod tls_support;

struct Fixture {
    _dir: tempfile::TempDir,
    bundle: PathBuf,
    untrusted_pem: PathBuf,
    untrusted: TestCa,
    trusted_server: TlsServer,
    untrusted_server: TlsServer,
}

static FIXTURE: Lazy<Fixture> = Lazy::new(|| {
    let trusted = TestCa::generate("shared-ca trusted");
    let untrusted = TestCa::generate("shared-ca untrusted");
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("bundle.pem");
    let untrusted_pem = dir.path().join("untrusted.pem");
    let certs = dir.path().join("certs");
    fs::write(&bundle, trusted.pem()).unwrap();
    fs::write(&untrusted_pem, untrusted.pem()).unwrap();
    fs::create_dir(&certs).unwrap();
    std::env::set_var("SSL_CERT_FILE", &bundle);
    std::env::set_var("SSL_CERT_DIR", &certs);
    let trusted_server = TlsServer::start(&trusted, &["localhost"]);
    let untrusted_server = TlsServer::start(&untrusted, &["localhost"]);
    Fixture {
        _dir: dir,
        bundle,
        untrusted_pem,
        untrusted,
        trusted_server,
        untrusted_server,
    }
});

fn url(server: &TlsServer) -> String {
    format!("https://localhost:{}/", server.port())
}

#[test]
fn trusted_root_is_accepted() {
    let fixture = &*FIXTURE;
    let response = HttpClient::new().unwrap().get(url(&fixture.trusted_server)).unwrap();
    assert_eq!(response.status(), 200);
}

#[test]
fn untrusted_root_is_rejected() {
    let fixture = &*FIXTURE;
    let error = HttpClient::new()
        .unwrap()
        .get(url(&fixture.untrusted_server))
        .unwrap_err();
    assert_eq!(error.kind(), &ErrorKind::BadServerCertificate);
}

#[test]
fn bundle_is_read_once_per_process() {
    let fixture = &*FIXTURE;
    let first = HttpClient::new().unwrap().get(url(&fixture.trusted_server)).unwrap();
    assert_eq!(first.status(), 200);

    fs::write(&fixture.bundle, fixture.untrusted.pem()).unwrap();

    let client = HttpClient::new().unwrap();
    assert_eq!(client.get(url(&fixture.trusted_server)).unwrap().status(), 200);
    let error = client.get(url(&fixture.untrusted_server)).unwrap_err();
    assert_eq!(error.kind(), &ErrorKind::BadServerCertificate);
}

#[test]
fn custom_ca_certificate_bypasses_the_shared_store() {
    let fixture = &*FIXTURE;
    let client = HttpClient::builder()
        .ssl_ca_certificate(CaCertificate::file(&fixture.untrusted_pem))
        .build()
        .unwrap();
    assert_eq!(client.get(url(&fixture.untrusted_server)).unwrap().status(), 200);
    let error = client.get(url(&fixture.trusted_server)).unwrap_err();
    assert_eq!(error.kind(), &ErrorKind::BadServerCertificate);
}

#[test]
fn accept_invalid_certs_still_skips_verification() {
    let fixture = &*FIXTURE;
    let client = HttpClient::builder()
        .ssl_options(SslOption::DANGER_ACCEPT_INVALID_CERTS)
        .build()
        .unwrap();
    assert_eq!(client.get(url(&fixture.untrusted_server)).unwrap().status(), 200);
}

#[test]
fn client_hello_is_the_same_with_and_without_the_shared_store() {
    let fixture = &*FIXTURE;
    let (shared_addr, shared) = capture_client_hello(false);
    let _ = HttpClient::new()
        .unwrap()
        .get(format!("https://localhost:{}/", shared_addr.port()));
    let (custom_addr, custom) = capture_client_hello(false);
    let _ = HttpClient::builder()
        .ssl_ca_certificate(CaCertificate::file(&fixture.untrusted_pem))
        .build()
        .unwrap()
        .get(format!("https://localhost:{}/", custom_addr.port()));
    let shared = shared.join().unwrap();
    let custom = custom.join().unwrap();
    assert_eq!(shared.server_name.as_deref(), Some("localhost"));
    assert_eq!(shared.normalized, custom.normalized);
}
