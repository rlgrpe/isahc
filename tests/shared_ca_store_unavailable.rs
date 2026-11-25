#![cfg(all(feature = "shared-ca-store", unix))]

use isahc::{
    config::{Configurable, SslOption},
    error::ErrorKind,
    HttpClient,
};
use once_cell::sync::Lazy;
use std::fs;
use tls_support::{TestCa, TlsServer};

mod tls_support;

struct Fixture {
    _dir: tempfile::TempDir,
    server: TlsServer,
}

static FIXTURE: Lazy<Fixture> = Lazy::new(|| {
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("bundle.pem");
    let certs = dir.path().join("certs");
    fs::write(&bundle, "not a certificate").unwrap();
    fs::create_dir(&certs).unwrap();
    std::env::set_var("SSL_CERT_FILE", &bundle);
    std::env::set_var("SSL_CERT_DIR", &certs);
    let server = TlsServer::start(&TestCa::generate("shared-ca untrusted"), &["localhost"]);
    Fixture { _dir: dir, server }
});

#[test]
fn unreadable_bundle_keeps_curl_behaviour() {
    let fixture = &*FIXTURE;
    let error = HttpClient::new()
        .unwrap()
        .get(format!("https://localhost:{}/", fixture.server.port()))
        .unwrap_err();
    assert_eq!(error.kind(), &ErrorKind::BadClientCertificate);
}

#[test]
fn unreadable_bundle_does_not_block_unverified_requests() {
    let fixture = &*FIXTURE;
    let client = HttpClient::builder()
        .ssl_options(SslOption::DANGER_ACCEPT_INVALID_CERTS)
        .build()
        .unwrap();
    let response = client
        .get(format!("https://localhost:{}/", fixture.server.port()))
        .unwrap();
    assert_eq!(response.status(), 200);
}
