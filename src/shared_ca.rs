//! One `X509_STORE` for every TLS connection of the process.
//!
//! The `curl` crate points every easy handle at the CA file and the CA
//! directory `openssl-probe` finds. With a directory set, curl does not cache
//! the parsed store, so each new connection parses the whole bundle. Here the
//! bundle is parsed once; handles that use it have both options cleared and
//! get the store through the SSL context callback.
#![allow(unsafe_code)]

use once_cell::sync::Lazy;
use openssl_sys::{SSL_CTX, X509_STORE};
use std::{
    ffi::CString,
    os::{
        raw::{c_char, c_int, c_void},
        unix::ffi::OsStrExt,
    },
    path::Path,
    ptr,
};

extern "C" {
    // OpenSSL 3.0 and later; openssl-sys 0.9 does not bind them.
    fn X509_STORE_load_file(store: *mut X509_STORE, file: *const c_char) -> c_int;
    fn X509_STORE_load_path(store: *mut X509_STORE, dir: *const c_char) -> c_int;
    fn SSL_CTX_set1_cert_store(ctx: *mut SSL_CTX, store: *mut X509_STORE);
}

struct SharedStore(*mut X509_STORE);

// SAFETY: an X509_STORE carries its own lock and reference count; OpenSSL
// documents sharing one store between SSL contexts. The pointer is never freed.
unsafe impl Send for SharedStore {}
unsafe impl Sync for SharedStore {}

static STORE: Lazy<Option<SharedStore>> = Lazy::new(load);

fn unavailable(reason: &'static str, path: Option<&Path>) -> Option<SharedStore> {
    tracing::warn!(
        reason,
        path = ?path,
        "Shared CA store unavailable; every TLS connection loads the CA bundle itself"
    );
    None
}

fn load() -> Option<SharedStore> {
    openssl_sys::init();
    // The same probe the `curl` crate runs, so the same file and directory.
    let probe = openssl_probe::probe();
    let file = match probe.cert_file {
        Some(file) => file,
        None => return unavailable("no_ca_file", None),
    };
    let c_file = match CString::new(file.as_os_str().as_bytes()) {
        Ok(c_file) => c_file,
        Err(_) => return unavailable("ca_file_path_has_nul", Some(&file)),
    };
    let c_dir = match probe.cert_dir.as_deref() {
        Some(dir) => match CString::new(dir.as_os_str().as_bytes()) {
            Ok(c_dir) => Some(c_dir),
            Err(_) => return unavailable("ca_dir_path_has_nul", Some(dir)),
        },
        None => None,
    };
    unsafe {
        let store = openssl_sys::X509_STORE_new();
        if store.is_null() {
            return unavailable("store_alloc_failed", None);
        }
        if X509_STORE_load_file(store, c_file.as_ptr()) != 1 {
            openssl_sys::X509_STORE_free(store);
            openssl_sys::ERR_clear_error();
            return unavailable("ca_file_unreadable", Some(&file));
        }
        if let Some(c_dir) = c_dir.as_ref() {
            if X509_STORE_load_path(store, c_dir.as_ptr()) != 1 {
                openssl_sys::X509_STORE_free(store);
                openssl_sys::ERR_clear_error();
                return unavailable("ca_dir_unusable", probe.cert_dir.as_deref());
            }
        }
        // The flags curl sets on the store it fills itself.
        openssl_sys::X509_STORE_set_flags(
            store,
            openssl_sys::X509_V_FLAG_TRUSTED_FIRST | openssl_sys::X509_V_FLAG_PARTIAL_CHAIN,
        );
        tracing::info!(
            cert_file = %file.display(),
            cert_dir = ?probe.cert_dir,
            "Shared CA store loaded"
        );
        Some(SharedStore(store))
    }
}

/// Whether the process has a shared store. The first call loads it.
pub(crate) fn is_available() -> bool {
    STORE.is_some()
}

/// Clears the CA file and directory the `curl` crate set on `easy`, so curl
/// parses nothing before the SSL context callback runs.
pub(crate) fn detach_curl_ca_lookup(easy: *mut curl_sys::CURL) -> Result<(), curl::Error> {
    for &option in &[curl_sys::CURLOPT_CAINFO, curl_sys::CURLOPT_CAPATH] {
        let code = unsafe { curl_sys::curl_easy_setopt(easy, option, ptr::null::<c_char>()) };
        if code != curl_sys::CURLE_OK {
            return Err(curl::Error::new(code));
        }
    }
    Ok(())
}

/// Makes `ssl_ctx` verify against the shared store. Takes its own reference.
pub(crate) fn attach(ssl_ctx: *mut c_void) {
    if let Some(store) = STORE.as_ref() {
        unsafe { SSL_CTX_set1_cert_store(ssl_ctx as *mut SSL_CTX, store.0) };
    }
}
