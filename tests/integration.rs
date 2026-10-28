//! SQL-level integration tests: LOAD the built `.duckdb_extension` into a real
//! in-memory DuckDB and exercise the full IOC surface — 12 scalars (2 VARCHAR,
//! 7 LIST(VARCHAR) extractors, 1 VARCHAR classifier, 1 BOOLEAN) + the
//! extract_iocs(text) table function.
//!
//! Lists are folded through `array_to_string(list, ',')` so each assertion
//! reads a single scalar VARCHAR.

use quack_rs::testing::InMemoryDb;

fn db() -> InMemoryDb {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/release/ioc.duckdb_extension");
    assert!(path.exists(), "build first: make release -> {path:?}");
    let d = InMemoryDb::open_unsigned().expect("open in-memory db");
    d.execute_batch(&format!("LOAD '{}'", path.display())).expect("load extension");
    d
}

/// Fold a LIST(VARCHAR) column into a scalar comma-joined string.
fn list(d: &InMemoryDb, expr: &str) -> Option<String> {
    d.query_one(&format!("SELECT array_to_string({expr}, ',')")).unwrap()
}

#[test]
fn defang_refang_roundtrip() {
    let d = db();
    assert_eq!(
        d.query_one::<String>("SELECT defang('http://evil.com/x')").unwrap(),
        "hxxp[://]evil[.]com/x"
    );
    assert_eq!(
        d.query_one::<String>("SELECT refang('hxxp[://]evil[.]com/x')").unwrap(),
        "http://evil.com/x"
    );
    // NULL in -> NULL out.
    assert_eq!(d.query_one::<Option<String>>("SELECT defang(NULL)").unwrap(), None);
    assert_eq!(d.query_one::<Option<String>>("SELECT refang(NULL)").unwrap(), None);
}

#[test]
fn extract_ipv4_refangs() {
    let d = db();
    let v = list(&d, "extract_ipv4('beacon from 10[.]0[.]0[.]5 and 1.2.3.4')").unwrap();
    assert!(v.contains("10.0.0.5"));
    assert!(v.contains("1.2.3.4"));
}

#[test]
fn extract_domains_excludes_url_hosts() {
    let d = db();
    // evil.com is the host of a URL, so it must NOT be emitted as a bare domain.
    let v = list(
        &d,
        "extract_domains('go to http://evil.com and also legit[.]org')",
    )
    .unwrap();
    assert!(v.contains("legit.org"));
    assert!(!v.contains("evil.com"));
}

#[test]
fn extract_emails_refangs() {
    let d = db();
    let v = list(&d, "extract_emails('phish mail bad[at]evil[.]com')").unwrap();
    assert_eq!(v, "bad@evil.com");
}

#[test]
fn extract_hashes_and_cves() {
    let d = db();
    let h = list(
        &d,
        "extract_hashes('hash d41d8cd98f00b204e9800998ecf8427e seen')",
    )
    .unwrap();
    assert_eq!(h, "d41d8cd98f00b204e9800998ecf8427e");
    let c = list(&d, "extract_cves('exploits CVE-2021-44228')").unwrap();
    assert_eq!(c, "CVE-2021-44228");
}

#[test]
fn hash_type_classifier() {
    let d = db();
    // 32 hex = md5
    assert_eq!(
        d.query_one::<Option<String>>("SELECT hash_type('d41d8cd98f00b204e9800998ecf8427e')")
            .unwrap()
            .as_deref(),
        Some("md5")
    );
    // 64 hex = sha256
    assert_eq!(
        d.query_one::<Option<String>>(
            "SELECT hash_type('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')"
        )
        .unwrap()
        .as_deref(),
        Some("sha256")
    );
    // Not a hash -> NULL
    assert_eq!(
        d.query_one::<Option<String>>("SELECT hash_type('nothash')").unwrap(),
        None
    );
}

#[test]
fn is_ioc_bool() {
    let d = db();
    assert!(d
        .query_one::<bool>("SELECT is_ioc('c2 at 10.0.0.5')")
        .unwrap());
    assert!(!d
        .query_one::<bool>("SELECT is_ioc('just some words')")
        .unwrap());
    assert_eq!(d.query_one::<Option<bool>>("SELECT is_ioc(NULL)").unwrap(), None);
}

#[test]
fn extract_iocs_table_rows() {
    let d = db();
    let mut stmt = d
        .conn()
        .prepare("SELECT type, value FROM extract_iocs('beacon to hxxp://evil[.]com from 10[.]0[.]0[.]5 and bad[at]evil[.]com') ORDER BY type, value")
        .unwrap();
    let rows: Vec<(String, String)> = stmt
        .query_map([], |row| Ok((row.get(0).unwrap(), row.get(1).unwrap())))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let types: Vec<&str> = rows.iter().map(|(t, _)| t.as_str()).collect();
    assert!(types.contains(&"email"));
    assert!(types.contains(&"ipv4"));
    assert!(types.contains(&"url"));
    // The URL host evil.com must not also appear as a bare domain row.
    assert!(!rows.iter().any(|(t, v)| t == "domain" && v == "evil.com"));
}

#[test]
fn extract_iocs_empty_text_zero_rows() {
    let d = db();
    let n: i64 = d
        .query_one("SELECT count(*) FROM extract_iocs('')")
        .unwrap();
    assert_eq!(n, 0);
}

#[test]
fn scalar_null_handling() {
    let d = db();
    // Extractors: NULL -> NULL list -> array_to_string(NULL) = NULL.
    assert_eq!(
        d.query_one::<Option<String>>("SELECT array_to_string(extract_ipv4(NULL), ',')").unwrap(),
        None
    );
    assert_eq!(
        d.query_one::<Option<String>>("SELECT array_to_string(extract_urls(NULL), ',')").unwrap(),
        None
    );
}
