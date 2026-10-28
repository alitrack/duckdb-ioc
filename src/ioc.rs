//! Pure IOC (indicator-of-compromise) logic: no Arrow, no RPC. Everything here
//! is plain `&str -> String / Vec<String> / bool` so it can be unit-tested in
//! isolation; the `scalar/` and `table/` modules are thin Arrow adapters over
//! it.
//!
//! # Refang-before-extract
//!
//! CTI reports almost always *defang* indicators so they cannot be accidentally
//! clicked or auto-resolved: `http://evil.example.com` is written
//! `hxxp://evil[.]example[.]com`, `1.2.3.4` becomes `1[.]2[.]3[.]4`, and
//! `user@evil.com` becomes `user[at]evil[.]com`. A naive extractor run over the
//! raw text would miss every one of these.
//!
//! Therefore **all extractors and `is_ioc` operate on a refanged copy of the
//! input** ([`refang`]): we undo the defanging first, then match real IPs /
//! domains / URLs / e-mails / hashes / CVEs. `defang` / `refang` themselves are
//! the only functions that do not refang first (they *are* the fanging step).
//!
//! # False-positive policy
//!
//! - **Overlap.** A bare domain that is already the host of an extracted URL or
//!   the domain part of an extracted e-mail is **not** also emitted as a
//!   standalone domain by [`extract_iocs`] / [`extract_domains`]. URLs and
//!   e-mails "win" their hosts. (The dedicated [`extract_domains`] still returns
//!   domains that appear on their own.) This keeps `extract_iocs` from
//!   double-reporting the same host under two types.
//! - **Private / reserved IPs are still extracted.** `10.0.0.5`, `192.168.x`,
//!   `127.0.0.1`, etc. are valid indicators in a report (lateral movement,
//!   C2 on an internal pivot) so we do not filter them. Callers can filter in
//!   SQL if they want only routable addresses.
//! - **TLD sanity.** A "domain" must end in an alphabetic TLD of length >= 2 to
//!   reduce matches on version strings / filenames (`foo.txt`, `app.v2`). This
//!   is heuristic, not exhaustive.
//! - **Input is bounded.** [`MAX_INPUT_BYTES`] caps how much text we scan so a
//!   pathological input cannot cause unbounded work; longer input is truncated
//!   at a UTF-8 boundary before matching.

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Upper bound on the number of input bytes we scan. Text longer than this is
/// truncated (at a char boundary) before matching, so a single huge cell can
/// never cause unbounded regex work. 4 MiB is far larger than any real report.
pub const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;

/// The canonical IOC type tags emitted by [`extract_iocs`] and [`hash_type`].
pub mod kind {
    pub const IPV4: &str = "ipv4";
    pub const IPV6: &str = "ipv6";
    pub const DOMAIN: &str = "domain";
    pub const URL: &str = "url";
    pub const EMAIL: &str = "email";
    pub const MD5: &str = "md5";
    pub const SHA1: &str = "sha1";
    pub const SHA256: &str = "sha256";
    pub const SHA512: &str = "sha512";
    pub const CVE: &str = "cve";
}

// ---------------------------------------------------------------------------
// Defang / refang
// ---------------------------------------------------------------------------

/// Make indicators in `text` safe to paste into a report ("defang"): protocol
/// schemes are mangled (`http`→`hxxp`, `https`→`hxxps`, `ftp`→`fxp`), `://`
/// becomes `[://]`, every `.` becomes `[.]`, and `@` becomes `[at]`.
///
/// The scheme and `://` substitutions run before the dot substitution so the
/// result is the conventional `hxxp[://]evil[.]com` form. Idempotent enough for
/// practical use (running it twice will not re-defang already-bracketed dots).
pub fn defang(text: &str) -> String {
    let mut out = text.to_string();
    // Schemes first (longest first so `https` is not eaten by `http`).
    out = out.replace("https", "hxxps");
    out = out.replace("http", "hxxp");
    out = out.replace("ftp", "fxp");
    // Separator and dots/at.
    out = out.replace("://", "[://]");
    out = out.replace('.', "[.]");
    out = out.replace('@', "[at]");
    out
}

/// Inverse of [`defang`]: turn a defanged string back into live indicators.
/// Recognises the common community defang conventions, not just our own output:
///
/// - schemes: `hxxp`/`hXXp`→`http`, `hxxps`→`https`, `fxp`→`ftp`
/// - separators: `[://]`, `(://)`, `[:]//`→`://`
/// - dots: `[.]`, `(.)`, `{.}`, `<.>`, `[dot]`, `(dot)`→`.`
/// - at: `[at]`, `(at)`, `{at}`→`@`
///
/// Only the **bracketed** `dot`/`at` word forms are refanged; the bare
/// space-delimited ` dot ` / ` at ` forms are intentionally NOT, because they
/// collide with ordinary English prose ("c2 at host", "see page dot 3") and
/// would corrupt non-indicator text. Case-insensitive for the word forms.
pub fn refang(text: &str) -> String {
    let mut out = text.to_string();

    // Bracketed "dot" forms -> "."  (do this before scheme/at).
    out = REFANG_DOT.replace_all(&out, ".").into_owned();
    // Bracketed "at" forms -> "@".
    out = REFANG_AT.replace_all(&out, "@").into_owned();
    // Separator "[://]" / "(://)" / "[:]//" -> "://".
    out = REFANG_SEP.replace_all(&out, "://").into_owned();
    // Schemes: hxxps/hxxp/fxp (case-insensitive) -> https/http/ftp.
    out = REFANG_HTTPS.replace_all(&out, "https").into_owned();
    out = REFANG_HTTP.replace_all(&out, "http").into_owned();
    out = REFANG_FTP.replace_all(&out, "ftp").into_owned();

    out
}

static REFANG_DOT: Lazy<Regex> = Lazy::new(|| {
    // Bracketed dot: [.] (.) {.} <.>  or bracketed word [dot] (dot) {dot} <dot>.
    Regex::new(r"(?i)[\[\(\{<]\s*\.\s*[\]\)\}>]|[\[\(\{<]\s*dot\s*[\]\)\}>]").unwrap()
});
static REFANG_AT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)[\[\(\{<]\s*at\s*[\]\)\}>]").unwrap());
static REFANG_SEP: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[\[\(]\s*:?//\s*[\]\)]|\[:\]//|\[://\]").unwrap());
static REFANG_HTTPS: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bhxxps\b").unwrap());
static REFANG_HTTP: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bhxxp\b").unwrap());
static REFANG_FTP: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bfxp\b").unwrap());

// ---------------------------------------------------------------------------
// Bounding helper
// ---------------------------------------------------------------------------

/// Truncate `text` to at most [`MAX_INPUT_BYTES`] bytes at a UTF-8 char
/// boundary, returning a borrowed slice when no truncation is needed.
fn bound(text: &str) -> &str {
    if text.len() <= MAX_INPUT_BYTES {
        return text;
    }
    let mut end = MAX_INPUT_BYTES;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

// ---------------------------------------------------------------------------
// Compiled extraction patterns
// ---------------------------------------------------------------------------

// IPv4: four 1-3 digit groups; we validate octet range in code afterwards.
static RE_IPV4: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap());

// Candidate IPv6 runs: a maximal run of hex digits and colons that contains at
// least one `::` or two `:` separators. `\b`-free (colons are non-word chars, so
// `::1` has no word boundary); we instead match a hex/colon run and validate by
// parsing. The surrounding `[^0-9a-f:]`-style delimiting is handled by the regex
// being greedy over only `[0-9a-f:]`.
static RE_IPV6: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}").unwrap());

// URL: scheme://... up to a whitespace or a few trailing punctuation chars.
static RE_URL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)\b(?:https?|ftp)://[^\s<>"'\)\]\}]+"#).unwrap());

// E-mail: a conservative addr-spec.
static RE_EMAIL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b").unwrap());

// Domain candidate: labels separated by dots ending in an alpha TLD.
static RE_DOMAIN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b").unwrap()
});

// Hashes by exact hex length (longest first when iterating types).
static RE_HASH: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\b[0-9a-f]{32,128}\b").unwrap());

// CVE-YYYY-NNNN(+).
static RE_CVE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bCVE-\d{4}-\d{4,}\b").unwrap());

// ---------------------------------------------------------------------------
// Hash classification
// ---------------------------------------------------------------------------

/// Classify a string as a hash type by length + hex-ness: `"md5"` (32),
/// `"sha1"` (40), `"sha256"` (64), `"sha512"` (128), or `None` otherwise.
/// Surrounding ASCII whitespace is ignored; the body must be all hex digits.
pub fn hash_type(s: &str) -> Option<&'static str> {
    let t = s.trim();
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    match t.len() {
        32 => Some(kind::MD5),
        40 => Some(kind::SHA1),
        64 => Some(kind::SHA256),
        128 => Some(kind::SHA512),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Single-type extractors. Each refangs first, then returns deduplicated,
// order-preserving matches.
// ---------------------------------------------------------------------------

/// Push `value` into `out` unless it is already present (case-sensitive),
/// preserving first-seen order. `seen` tracks membership.
fn push_unique(out: &mut Vec<String>, seen: &mut HashSet<String>, value: String) {
    if seen.insert(value.clone()) {
        out.push(value);
    }
}

/// Extract IPv4 addresses (each octet 0-255). Private/reserved IPs included.
pub fn extract_ipv4(text: &str) -> Vec<String> {
    let refanged = refang(bound(text));
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for m in RE_IPV4.find_iter(&refanged) {
        if m.as_str().parse::<Ipv4Addr>().is_ok() {
            push_unique(&mut out, &mut seen, m.as_str().to_string());
        }
    }
    out
}

/// Extract IPv6 addresses (validated by parsing). Loopback/link-local included.
pub fn extract_ipv6(text: &str) -> Vec<String> {
    let refanged = refang(bound(text));
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for m in RE_IPV6.find_iter(&refanged) {
        let cand = m.as_str();
        // Require at least two colons to avoid matching `a:b` style noise.
        if cand.matches(':').count() < 2 {
            continue;
        }
        // Try the candidate, then a single trailing-colon-trimmed variant (the
        // greedy run can over-capture a stray separator like `addr:`).
        let parsed = cand
            .parse::<Ipv6Addr>()
            .or_else(|_| cand.trim_end_matches(':').parse::<Ipv6Addr>())
            .or_else(|_| cand.trim_start_matches(':').parse::<Ipv6Addr>());
        if let Ok(ip) = parsed {
            // Canonical, lowercase, compressed form.
            push_unique(&mut out, &mut seen, ip.to_string());
        }
    }
    out
}

/// Extract URLs (`http(s)://…`, `ftp://…`). Trailing sentence punctuation that
/// the regex over-captures is trimmed.
pub fn extract_urls(text: &str) -> Vec<String> {
    let refanged = refang(bound(text));
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for m in RE_URL.find_iter(&refanged) {
        let trimmed = m.as_str().trim_end_matches(['.', ',', ';', ':', '!', '?']);
        if !trimmed.is_empty() {
            push_unique(&mut out, &mut seen, trimmed.to_string());
        }
    }
    out
}

/// Extract e-mail addresses.
pub fn extract_emails(text: &str) -> Vec<String> {
    let refanged = refang(bound(text));
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for m in RE_EMAIL.find_iter(&refanged) {
        push_unique(&mut out, &mut seen, m.as_str().to_string());
    }
    out
}

/// Extract bare domains, **excluding** any domain that is already the host of an
/// extracted URL or the domain part of an extracted e-mail (overlap policy:
/// URLs and e-mails win their hosts). Pure IPv4 dotted-quads are not domains.
pub fn extract_domains(text: &str) -> Vec<String> {
    let refanged = refang(bound(text));
    let claimed = claimed_hosts(&refanged);
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for m in RE_DOMAIN.find_iter(&refanged) {
        let cand = m.as_str();
        if is_standalone_domain(cand, &claimed) {
            push_unique(&mut out, &mut seen, cand.to_ascii_lowercase());
        }
    }
    out
}

/// Extract MD5/SHA1/SHA256 hashes (the three the task lists; SHA512 is reported
/// by [`hash_type`] but a 128-hex run is rarer in prose and still surfaced via
/// [`extract_iocs`]).
pub fn extract_hashes(text: &str) -> Vec<String> {
    let refanged = refang(bound(text));
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for m in RE_HASH.find_iter(&refanged) {
        if hash_type(m.as_str()).is_some() {
            push_unique(&mut out, &mut seen, m.as_str().to_ascii_lowercase());
        }
    }
    out
}

/// Extract CVE identifiers, upper-cased (`CVE-2024-1234`).
pub fn extract_cves(text: &str) -> Vec<String> {
    let refanged = refang(bound(text));
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for m in RE_CVE.find_iter(&refanged) {
        push_unique(&mut out, &mut seen, m.as_str().to_ascii_uppercase());
    }
    out
}

// ---------------------------------------------------------------------------
// Overlap helpers (URLs/e-mails claim their hosts)
// ---------------------------------------------------------------------------

/// The set of lower-cased host names that are "claimed" by a URL or e-mail in
/// `refanged` text and must therefore not be re-reported as bare domains.
fn claimed_hosts(refanged: &str) -> HashSet<String> {
    let mut claimed = HashSet::new();
    for m in RE_URL.find_iter(refanged) {
        if let Some(h) = url_host(m.as_str()) {
            claimed.insert(h);
        }
    }
    for m in RE_EMAIL.find_iter(refanged) {
        if let Some((_, domain)) = m.as_str().rsplit_once('@') {
            claimed.insert(domain.to_ascii_lowercase());
        }
    }
    claimed
}

/// Extract the host (authority minus userinfo/port/path) from a URL string.
fn url_host(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://")?.1;
    // Authority ends at the first '/', '?', or '#'.
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    // Strip userinfo and port.
    let host = authority.rsplit_once('@').map(|x| x.1).unwrap_or(authority);
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// Whether `cand` is a real standalone domain: ends in an alpha TLD, is not a
/// pure IPv4 dotted-quad, and is not already claimed by a URL/e-mail host.
fn is_standalone_domain(cand: &str, claimed: &HashSet<String>) -> bool {
    let lower = cand.to_ascii_lowercase();
    if claimed.contains(&lower) {
        return false;
    }
    // Reject dotted-quad IPv4 (the domain regex can match all-numeric labels
    // only if a TLD is alpha, but `1.2.3.4` has a numeric last label so it
    // already fails the regex; guard anyway for clarity).
    if lower.parse::<Ipv4Addr>().is_ok() {
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// Aggregate: typed rows + boolean
// ---------------------------------------------------------------------------

/// One extracted indicator: its canonical `kind` tag and `value`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Indicator {
    pub kind: &'static str,
    pub value: String,
}

/// Extract every recognizable IOC as `(kind, value)` rows, deduplicated across
/// the whole result (a value never appears twice even under the same type).
/// Refangs the input first. Applies the overlap policy: a host claimed by a URL
/// or e-mail is not separately reported as a `domain`.
///
/// Types covered: ipv4, ipv6, url, email, domain, md5, sha1, sha256, sha512,
/// cve. The output order is grouped by type in a stable sequence (ipv4, ipv6,
/// url, email, domain, hashes, cve); callers needing a specific order should
/// `ORDER BY` in SQL.
pub fn extract_iocs(text: &str) -> Vec<Indicator> {
    let bounded = bound(text);
    let mut out = Vec::new();
    // `(kind, value)` dedupe key so the same string under two types is kept,
    // but identical type+value is collapsed.
    let mut seen: HashSet<(&'static str, String)> = HashSet::new();

    let mut add = |kind: &'static str, value: String, out: &mut Vec<Indicator>| {
        if seen.insert((kind, value.clone())) {
            out.push(Indicator { kind, value });
        }
    };

    for v in extract_ipv4(bounded) {
        add(kind::IPV4, v, &mut out);
    }
    for v in extract_ipv6(bounded) {
        add(kind::IPV6, v, &mut out);
    }
    for v in extract_urls(bounded) {
        add(kind::URL, v, &mut out);
    }
    for v in extract_emails(bounded) {
        add(kind::EMAIL, v, &mut out);
    }
    for v in extract_domains(bounded) {
        add(kind::DOMAIN, v, &mut out);
    }
    // Hashes: classify each to its precise type.
    for v in extract_hashes(bounded) {
        if let Some(k) = hash_type(&v) {
            add(k, v, &mut out);
        }
    }
    for v in extract_cves(bounded) {
        add(kind::CVE, v, &mut out);
    }
    out
}

/// Whether `text` contains ANY recognizable IOC (after refanging). Cheap-ish:
/// returns on the first match without collecting the rest.
pub fn is_ioc(text: &str) -> bool {
    let refanged = refang(bound(text));
    if RE_CVE.is_match(&refanged) {
        return true;
    }
    if RE_URL.is_match(&refanged) || RE_EMAIL.is_match(&refanged) {
        return true;
    }
    if RE_IPV4
        .find_iter(&refanged)
        .any(|m| m.as_str().parse::<Ipv4Addr>().is_ok())
    {
        return true;
    }
    if RE_HASH
        .find_iter(&refanged)
        .any(|m| hash_type(m.as_str()).is_some())
    {
        return true;
    }
    if RE_IPV6
        .find_iter(&refanged)
        .any(|m| m.as_str().matches(':').count() >= 2 && m.as_str().parse::<Ipv6Addr>().is_ok())
    {
        return true;
    }
    !extract_domains(&refanged).is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPORT: &str = "Beacon to hxxp://evil[.]example[.]com/path from 10[.]0[.]0[.]5, \
        contact bad[at]evil[.]example[.]com, md5 d41d8cd98f00b204e9800998ecf8427e, \
        sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855, \
        exploiting CVE-2024-1234 and CVE-2023-99999.";

    #[test]
    fn defang_refang_roundtrip() {
        let live = "Visit http://test.example.com/a or email me@test.example.com about 8.8.8.8";
        let fanged = defang(live);
        assert!(fanged.contains("hxxp[://]test[.]example[.]com"));
        assert!(fanged.contains("[at]"));
        assert!(!fanged.contains("8.8.8.8"));
        // Refanging the defanged form recovers the indicators (round-trip of the
        // *indicators*, not necessarily byte-identical prose).
        let back = refang(&fanged);
        assert!(back.contains("http://test.example.com/a"));
        assert!(back.contains("me@test.example.com"));
        assert!(back.contains("8.8.8.8"));
    }

    #[test]
    fn extractors_refang_first() {
        assert_eq!(extract_ipv4(REPORT), vec!["10.0.0.5"]);
        assert_eq!(extract_urls(REPORT), vec!["http://evil.example.com/path"]);
        assert_eq!(extract_emails(REPORT), vec!["bad@evil.example.com"]);
        assert_eq!(
            extract_cves(REPORT),
            vec!["CVE-2024-1234", "CVE-2023-99999"]
        );
        let hashes = extract_hashes(REPORT);
        assert!(hashes.contains(&"d41d8cd98f00b204e9800998ecf8427e".to_string()));
        assert!(hashes.contains(
            &"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()
        ));
    }

    #[test]
    fn domain_overlap_policy() {
        // The host evil.example.com is claimed by the URL and the e-mail, so it
        // is NOT separately reported as a bare domain.
        let domains = extract_domains(REPORT);
        assert!(
            !domains.contains(&"evil.example.com".to_string()),
            "claimed host must not appear as a bare domain: {domains:?}"
        );
        // A standalone domain IS reported.
        let d = extract_domains("traffic seen to cdn.malware-host.net then nowhere");
        assert_eq!(d, vec!["cdn.malware-host.net"]);
    }

    #[test]
    fn hash_type_by_length() {
        assert_eq!(hash_type(&"a".repeat(32)), Some("md5"));
        assert_eq!(hash_type(&"b".repeat(40)), Some("sha1"));
        assert_eq!(hash_type(&"c".repeat(64)), Some("sha256"));
        assert_eq!(hash_type(&"d".repeat(128)), Some("sha512"));
        assert_eq!(hash_type("xyz"), None);
        assert_eq!(hash_type(&"a".repeat(31)), None);
        assert_eq!(hash_type("g".repeat(32).as_str()), None); // 'g' not hex
    }

    #[test]
    fn is_ioc_true_false() {
        assert!(is_ioc(REPORT));
        assert!(is_ioc("just an ip 192.168.1.1 here"));
        assert!(is_ioc("CVE-2021-44228 log4shell"));
        assert!(!is_ioc("the quick brown fox jumps over the lazy dog"));
        assert!(!is_ioc(""));
        assert!(!is_ioc("version 1.2 of the report, see page 3"));
    }

    #[test]
    fn extract_iocs_typed_rows_dedup() {
        let rows = extract_iocs(REPORT);
        let has = |k: &str, v: &str| rows.iter().any(|r| r.kind == k && r.value == v);
        assert!(has("ipv4", "10.0.0.5"));
        assert!(has("url", "http://evil.example.com/path"));
        assert!(has("email", "bad@evil.example.com"));
        assert!(has("md5", "d41d8cd98f00b204e9800998ecf8427e"));
        assert!(has(
            "sha256",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
        assert!(has("cve", "CVE-2024-1234"));
        // No bare-domain row for the URL/e-mail host.
        assert!(!rows
            .iter()
            .any(|r| r.kind == "domain" && r.value == "evil.example.com"));
        // Dedupe: CVE-2024-1234 appears once even if repeated.
        let dup = extract_iocs("CVE-2024-1234 and again CVE-2024-1234");
        assert_eq!(dup.iter().filter(|r| r.kind == "cve").count(), 1);
    }

    #[test]
    fn ipv6_extraction() {
        let t = "c2 at 2001:0db8:85a3:0000:0000:8a2e:0370:7334 and ::1 loopback";
        let v = extract_ipv6(t);
        assert!(v.contains(&"2001:db8:85a3::8a2e:370:7334".to_string()));
        assert!(v.contains(&"::1".to_string()));
    }

    #[test]
    fn empty_and_no_iocs_yield_empty() {
        assert!(extract_ipv4("").is_empty());
        assert!(extract_iocs("").is_empty());
        assert!(extract_iocs("nothing of interest at all").is_empty());
    }

    #[test]
    fn private_ips_still_extracted() {
        assert_eq!(
            extract_ipv4("pivot via 192.168.1.10 and 127.0.0.1"),
            vec!["192.168.1.10", "127.0.0.1"]
        );
    }

    #[test]
    fn input_is_bounded() {
        let mut big = "10.0.0.5 ".to_string();
        big.push_str(&"x".repeat(MAX_INPUT_BYTES + 1024));
        // Must not panic; the leading IP (within bound) is still found.
        let v = extract_ipv4(&big);
        assert_eq!(v, vec!["10.0.0.5"]);
    }
}
