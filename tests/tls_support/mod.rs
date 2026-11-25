//! Throwaway certificate authorities, a loopback TLS server and a ClientHello
//! capture for TLS trust tests. Everything runs on `std` threads.
#![allow(dead_code)]

use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    ssl::{SslAcceptor, SslMethod},
    x509::{
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
        X509NameBuilder,
        X509,
    },
};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
};

fn p256_key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

fn build_cert(
    common_name: &str,
    key: &PKey<Private>,
    issuer: Option<&TestCa>,
    dns_names: &[&str],
) -> X509 {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", common_name).unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    let mut serial = BigNum::new().unwrap();
    serial.rand(127, MsbOption::MAYBE_ZERO, false).unwrap();
    builder
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();
    builder.set_subject_name(&name).unwrap();
    match issuer {
        Some(ca) => builder.set_issuer_name(ca.cert.subject_name()).unwrap(),
        None => builder.set_issuer_name(&name).unwrap(),
    }
    builder.set_pubkey(key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    match issuer {
        None => {
            builder
                .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                .unwrap();
            builder
                .append_extension(
                    KeyUsage::new()
                        .critical()
                        .key_cert_sign()
                        .crl_sign()
                        .build()
                        .unwrap(),
                )
                .unwrap();
        }
        Some(ca) => {
            builder
                .append_extension(BasicConstraints::new().build().unwrap())
                .unwrap();
            builder
                .append_extension(
                    KeyUsage::new()
                        .critical()
                        .digital_signature()
                        .build()
                        .unwrap(),
                )
                .unwrap();
            builder
                .append_extension(ExtendedKeyUsage::new().server_auth().build().unwrap())
                .unwrap();
            let mut san = SubjectAlternativeName::new();
            for dns in dns_names {
                san.dns(dns);
            }
            let san = san
                .build(&builder.x509v3_context(Some(&ca.cert), None))
                .unwrap();
            builder.append_extension(san).unwrap();
        }
    }
    let signer = issuer.map_or(key, |ca| &ca.key);
    builder.sign(signer, MessageDigest::sha256()).unwrap();
    builder.build()
}

pub struct TestCa {
    cert: X509,
    key: PKey<Private>,
}

impl TestCa {
    /// P-256 key, self-signed, `CA:TRUE`, `keyCertSign`, valid one day.
    pub fn generate(common_name: &str) -> Self {
        let key = p256_key();
        let cert = build_cert(common_name, &key, None, &[]);
        Self { cert, key }
    }

    /// The certificate alone, PEM.
    pub fn pem(&self) -> Vec<u8> {
        self.cert.to_pem().unwrap()
    }
}

pub struct TlsServer {
    port: u16,
    accepted: Arc<AtomicUsize>,
    completed: Arc<AtomicUsize>,
}

impl TlsServer {
    /// Binds 127.0.0.1:0. Leaf: P-256, SAN = `dns_names`, `serverAuth`, signed by `ca`.
    pub fn start(ca: &TestCa, dns_names: &[&str]) -> Self {
        let key = p256_key();
        let leaf = build_cert("shared-ca leaf", &key, Some(ca), dns_names);
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        acceptor.set_private_key(&key).unwrap();
        acceptor.set_certificate(&leaf).unwrap();
        let acceptor = Arc::new(acceptor.build());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        {
            let accepted = accepted.clone();
            let completed = completed.clone();
            thread::spawn(move || {
                for stream in listener.incoming() {
                    let stream = match stream {
                        Ok(stream) => stream,
                        Err(_) => continue,
                    };
                    accepted.fetch_add(1, Ordering::SeqCst);
                    let acceptor = acceptor.clone();
                    let completed = completed.clone();
                    thread::spawn(move || {
                        if let Ok(mut tls) = acceptor.accept(stream) {
                            completed.fetch_add(1, Ordering::SeqCst);
                            if read_head(&mut tls).is_some() {
                                let _ = tls.write_all(
                                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 20\r\nConnection: close\r\n\r\n{\"ip\":\"203.0.113.7\"}",
                                );
                                let _ = tls.flush();
                                let _ = tls.shutdown();
                            }
                        }
                    });
                }
            });
        }
        Self {
            port,
            accepted,
            completed,
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// TCP connections accepted.
    pub fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    /// TLS handshakes the client let finish.
    pub fn completed_handshakes(&self) -> usize {
        self.completed.load(Ordering::SeqCst)
    }
}

fn read_head<S: Read>(stream: &mut S) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return Some(buf);
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

fn relay(mut from: TcpStream, mut to: TcpStream) {
    let mut buf = [0u8; 16384];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = to.shutdown(std::net::Shutdown::Write);
}

/// HTTP CONNECT proxy that sends every tunnel to `target`, whatever host was asked for.
pub fn start_connect_proxy(target: SocketAddr) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut client = match stream {
                Ok(stream) => stream,
                Err(_) => continue,
            };
            thread::spawn(move || {
                let head = match read_head(&mut client) {
                    Some(head) => head,
                    None => return,
                };
                if !head.starts_with(b"CONNECT ") {
                    let _ = client
                        .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n");
                    return;
                }
                let upstream = match TcpStream::connect(target) {
                    Ok(upstream) => upstream,
                    Err(_) => return,
                };
                if client
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .is_err()
                {
                    return;
                }
                let (c2, u2) = (client.try_clone().unwrap(), upstream.try_clone().unwrap());
                thread::spawn(move || relay(c2, u2));
                relay(upstream, client);
            });
        }
    });
    addr
}

pub struct ClientHello {
    /// The ClientHello handshake message with `random`, `legacy_session_id`
    /// and every `key_share` key zeroed.
    pub normalized: Vec<u8>,
    pub alpn: Vec<String>,
    pub server_name: Option<String>,
}

fn u16_at(data: &[u8], at: usize) -> usize {
    ((data[at] as usize) << 8) | data[at + 1] as usize
}

fn parse_client_hello(mut msg: Vec<u8>) -> ClientHello {
    assert_eq!(msg[0], 0x01, "not a ClientHello");
    let body_len = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | msg[3] as usize;
    assert_eq!(body_len + 4, msg.len(), "ClientHello spans several records");
    let mut at = 4 + 2; // version
    for b in &mut msg[at..at + 32] {
        *b = 0;
    }
    at += 32;
    let session_len = msg[at] as usize;
    at += 1;
    for b in &mut msg[at..at + session_len] {
        *b = 0;
    }
    at += session_len;
    let ciphers_len = u16_at(&msg, at);
    at += 2 + ciphers_len;
    let compression_len = msg[at] as usize;
    at += 1 + compression_len;
    let extensions_end = at + 2 + u16_at(&msg, at);
    assert_eq!(extensions_end, msg.len(), "unexpected ClientHello length");
    at += 2;

    let mut alpn = Vec::new();
    let mut server_name = None;
    while at < extensions_end {
        let kind = u16_at(&msg, at);
        let len = u16_at(&msg, at + 2);
        let data = at + 4;
        let end = data + len;
        match kind {
            0x0000 => {
                // list length (2), name type (1), name length (2), name
                let name_len = u16_at(&msg, data + 3);
                let name = &msg[data + 5..data + 5 + name_len];
                server_name = Some(String::from_utf8(name.to_vec()).unwrap());
            }
            0x0010 => {
                let mut p = data + 2;
                while p < end {
                    let l = msg[p] as usize;
                    alpn.push(String::from_utf8(msg[p + 1..p + 1 + l].to_vec()).unwrap());
                    p += 1 + l;
                }
            }
            0x0033 => {
                let mut p = data + 2;
                while p < end {
                    let key_len = u16_at(&msg, p + 2);
                    for b in &mut msg[p + 4..p + 4 + key_len] {
                        *b = 0;
                    }
                    p += 4 + key_len;
                }
            }
            _ => {}
        }
        at = end;
    }
    assert_eq!(at, extensions_end, "malformed ClientHello extensions");
    ClientHello {
        normalized: msg,
        alpn,
        server_name,
    }
}

/// Listens on 127.0.0.1:0, takes one connection, reads one ClientHello and closes.
/// With `after_connect` it first reads an HTTP CONNECT head and answers
/// `HTTP/1.1 200 Connection established\r\n\r\n`.
pub fn capture_client_hello(after_connect: bool) -> (SocketAddr, JoinHandle<ClientHello>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        if after_connect {
            // Read the CONNECT head byte by byte so no TLS byte is consumed.
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                head.push(byte[0]);
            }
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .unwrap();
        }
        let mut header = [0u8; 5];
        stream.read_exact(&mut header).unwrap();
        assert_eq!(header[0], 0x16, "not a TLS handshake record");
        let len = u16_at(&header, 3);
        let mut msg = vec![0u8; len];
        stream.read_exact(&mut msg).unwrap();
        parse_client_hello(msg)
    });
    (addr, handle)
}
