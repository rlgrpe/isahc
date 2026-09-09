#![cfg(feature = "cookies")]

use http::Uri;
use isahc::{
    HttpClient,
    config::RedirectPolicy,
    cookies::{Cookie, CookieJar, SameSite},
    prelude::*,
};
use std::collections::HashSet;
use testserver::mock;

#[test]
fn cookie_lifecycle() {
    let jar = CookieJar::default();
    let client = HttpClient::builder()
        .cookie_jar(jar.clone())
        .build()
        .unwrap();

    let m1 = mock! {
        headers {
            "set-cookie": "foo=bar",
            "set-cookie": "baz=123",
        }
    };
    let m2 = mock!();

    let response1 = client.get(m1.url()).unwrap();

    assert!(response1.cookie_jar().is_some());

    let response2 = client.get(m2.url()).unwrap();

    assert!(response2.cookie_jar().is_some());

    let header = m2
        .request()
        .get_header("cookie")
        .next()
        .expect("outgoing cookie header");
    let tokens: HashSet<&str> = header.split("; ").collect();
    assert_eq!(tokens, HashSet::from(["foo=bar", "baz=123"]));
}

#[test]
fn interceptor_rejects_foreign_domain_and_leaves_existing_flags() {
    let jar = CookieJar::new();
    let foreign: Uri = "https://evil.example/".parse().unwrap();
    jar.set(
        Cookie::builder("foreign", "keep")
            .domain("evil.example")
            .path("/")
            .http_only(true)
            .same_site(SameSite::Lax)
            .build()
            .unwrap(),
        &foreign,
    )
    .unwrap();

    let client = HttpClient::builder()
        .cookie_jar(jar.clone())
        .build()
        .unwrap();
    let m = mock! {
        headers {
            "set-cookie": "foreign=new; Domain=evil.example; Path=/",
            "set-cookie": "ok=yes; Path=/",
        }
    };

    client.get(m.url()).unwrap();

    let snapshot = jar.snapshot();
    let foreign = snapshot
        .iter()
        .find(|cookie| cookie.name == "foreign")
        .expect("seeded foreign cookie remains");
    assert_eq!(foreign.value, "keep");
    assert!(foreign.http_only);
    assert_eq!(foreign.same_site, Some(SameSite::Lax));
    assert_eq!(foreign.effective_domain, "evil.example");
    assert!(snapshot.iter().any(|cookie| cookie.name == "ok"
        && cookie.value == "yes"
        && cookie.host_only
        && !cookie.http_only
        && cookie.same_site.is_none()));
}

#[test]
fn interceptor_replacement_owns_current_flags() {
    let jar = CookieJar::new();
    let client = HttpClient::builder()
        .cookie_jar(jar.clone())
        .build()
        .unwrap();

    let first = mock! {
        headers {
            "set-cookie": "v=one; HttpOnly; SameSite=Lax; Path=/",
        }
    };
    client.get(first.url()).unwrap();
    let one = jar
        .snapshot()
        .into_iter()
        .find(|cookie| cookie.name == "v")
        .unwrap();
    assert_eq!(one.value, "one");
    assert!(one.http_only);
    assert_eq!(one.same_site, Some(SameSite::Lax));

    let second = mock! {
        headers {
            "set-cookie": "v=two; Path=/",
        }
    };
    client.get(second.url()).unwrap();
    let two = jar
        .snapshot()
        .into_iter()
        .find(|cookie| cookie.name == "v")
        .unwrap();
    assert_eq!(two.value, "two");
    assert!(!two.http_only);
    assert_eq!(two.same_site, None);

    let third = mock! {
        headers {
            "set-cookie": "v=three; SameSite=None; Path=/",
        }
    };
    client.get(third.url()).unwrap();
    let three = jar
        .snapshot()
        .into_iter()
        .find(|cookie| cookie.name == "v")
        .unwrap();
    assert_eq!(three.value, "three");
    assert_eq!(three.same_site, Some(SameSite::None));
    assert_ne!(three.same_site, None);
}

#[test]
fn interceptor_max_age_zero_deletes() {
    let jar = CookieJar::new();
    let client = HttpClient::builder()
        .cookie_jar(jar.clone())
        .build()
        .unwrap();

    let set = mock! {
        headers {
            "set-cookie": "gone=1; Path=/",
        }
    };
    client.get(set.url()).unwrap();
    assert!(jar.snapshot().iter().any(|cookie| cookie.name == "gone"));

    let delete = mock! {
        headers {
            "set-cookie": "gone=; Max-Age=0; Path=/",
        }
    };
    client.get(delete.url()).unwrap();
    assert!(jar.snapshot().iter().all(|cookie| cookie.name != "gone"));

    let follow = mock!();
    client.get(follow.url()).unwrap();
    assert!(follow.request().get_header("cookie").next().is_none());
}

#[test]
fn interceptor_keeps_distinct_scopes_and_host_only() {
    let jar = CookieJar::new();
    let client = HttpClient::builder()
        .cookie_jar(jar.clone())
        .build()
        .unwrap();

    let root = mock! {
        headers {
            "set-cookie": "n=host; Path=/",
        }
    };
    client.get(root.url()).unwrap();

    let nested = mock! {
        headers {
            "set-cookie": "n=nested; Domain=127.0.0.1; Path=/appointment",
        }
    };
    client.get(format!("{}appointment", nested.url())).unwrap();

    let snapshot = jar.snapshot();
    let host = snapshot
        .iter()
        .find(|cookie| cookie.value == "host")
        .expect("host-only cookie");
    let domain = snapshot
        .iter()
        .find(|cookie| cookie.value == "nested")
        .expect("domain cookie");
    assert!(host.host_only);
    assert_eq!(host.effective_path, "/");
    assert!(!domain.host_only);
    assert_eq!(domain.effective_path, "/appointment");
}

#[test]
fn interceptor_redirect_keeps_accepted_cookie() {
    let jar = CookieJar::new();
    let client = HttpClient::builder()
        .cookie_jar(jar.clone())
        .redirect_policy(RedirectPolicy::Follow)
        .build()
        .unwrap();

    let hop = mock!();
    let location = hop.url();
    let start = mock! {
        status: 302,
        headers {
            "Location": location,
            "set-cookie": "hop=1; HttpOnly; SameSite=Strict; Path=/",
        }
    };

    client.get(start.url()).unwrap();

    hop.request()
        .expect_header_matches("cookie", |value| value.contains("hop=1"));
    let cookie = jar
        .snapshot()
        .into_iter()
        .find(|cookie| cookie.name == "hop")
        .unwrap();
    assert_eq!(cookie.value, "1");
    assert!(cookie.http_only);
    assert_eq!(cookie.same_site, Some(SameSite::Strict));
}
