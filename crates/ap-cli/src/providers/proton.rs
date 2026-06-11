//! Proton Pass CLI credential provider
//!
//! Wraps the `pass-cli` tool (<https://protonpass.github.io/pass-cli/>) to look
//! up credentials, check session status, and authenticate via a Personal Access
//! Token (including the agent-scoped tokens from `pass-cli agent create`).
//!
//! ## How it maps onto `pass-cli`
//!
//! * **status** → `pass-cli info --output json` (exit 0 ⇒ an active session).
//! * **unlock** → `pass-cli login` with `PROTON_PASS_PERSONAL_ACCESS_TOKEN` set,
//!   i.e. a Personal Access Token (`pst_...::KEY`). This is the non-interactive
//!   auth path intended for agents and automation.
//! * **lookup** → items are addressed by a `pass://SHARE_ID/ITEM_ID` URI. We
//!   enumerate vaults (`vault list`) and, per vault, list items to resolve a
//!   query to a concrete item.
//!
//! ## Two lookup paths
//!
//! 1. **Fast path** — `item list --show-secrets` returns each item's full
//!    content (URLs, password, TOTP) in a single call per vault, so a domain can
//!    be matched locally and the credential built directly from the listing. No
//!    per-item reads.
//! 2. **Agent fallback** — `--show-secrets` is rejected for agent-scoped
//!    sessions, so we fall back to a metadata listing plus `item view` per
//!    candidate. Agent tokens are scoped to a small set of items, so this stays
//!    cheap. Each `item view` carries `PROTON_PASS_AGENT_REASON`, which Proton
//!    requires and records in the agent audit log.
//!
//! Note: Proton share IDs commonly start with `-`, so `--share-id` is always
//! passed in attached form (`--share-id=VALUE`) to avoid being parsed as a flag.

use std::process::{Command, Stdio};

use ap_client::CredentialData;
use secrecy::zeroize::Zeroizing;
use serde::Deserialize;
use tracing::info;

use super::{CredentialProvider, CredentialQuery, LookupResult, ProviderStatus};

/// Well-known fallback locations checked when `pass-cli` is not on `$PATH`.
/// `~/.local/bin` (the default installer location) is checked first via `$HOME`.
const PASS_FALLBACK_PATHS: &[&str] = &["/opt/homebrew/bin/pass-cli", "/usr/local/bin/pass-cli"];

/// Default reason recorded against an item read when the caller hasn't set
/// `PROTON_PASS_AGENT_REASON` themselves.
const DEFAULT_AGENT_REASON: &str = "agent-access credential request";

/// Proton caps `PROTON_PASS_AGENT_REASON` at 300 characters.
const MAX_AGENT_REASON_LEN: usize = 300;

// -- pass-cli JSON shapes ---------------------------------------------------

/// `pass-cli info --output json`
#[derive(Deserialize)]
struct PassInfo {
    email: Option<String>,
}

/// `pass-cli vault list --output json`
#[derive(Deserialize)]
struct VaultList {
    vaults: Vec<VaultEntry>,
}

#[derive(Deserialize)]
struct VaultEntry {
    share_id: String,
}

/// `pass-cli item list --output json` (metadata only).
#[derive(Deserialize)]
struct ItemList {
    items: Vec<ItemEntry>,
}

#[derive(Clone, Deserialize)]
struct ItemEntry {
    id: String,
    title: Option<String>,
    item_type: Option<String>,
}

/// `pass-cli item list --show-secrets --output json` and the `item` field of
/// `pass-cli item view` share the same item shape.
#[derive(Deserialize)]
struct ItemListFull {
    items: Vec<PassItem>,
}

/// `pass-cli item view <uri> --output json`
#[derive(Deserialize)]
struct PassView {
    item: PassItem,
}

#[derive(Deserialize)]
struct PassItem {
    id: Option<String>,
    content: PassItemContent,
}

#[derive(Deserialize)]
struct PassItemContent {
    title: Option<String>,
    note: Option<String>,
    content: PassTypedContent,
}

/// Tagged by item type; we only care about the `Login` variant.
#[derive(Deserialize)]
struct PassTypedContent {
    #[serde(rename = "Login")]
    login: Option<PassLogin>,
}

#[derive(Deserialize)]
struct PassLogin {
    email: Option<String>,
    username: Option<String>,
    password: Option<String>,
    urls: Option<Vec<String>>,
    /// `otpauth://` URI (the TOTP secret), not a generated code.
    totp_uri: Option<String>,
}

/// Outcome of a session check.
enum Session {
    /// An active session exists (optional account email).
    Active(Option<String>),
    /// No usable session — login required.
    Inactive,
}

/// Credential provider backed by the Proton Pass CLI (`pass-cli`).
pub struct ProtonProvider {
    /// Cached path to the `pass-cli` binary (resolved once on construction).
    pass_path: Option<String>,
}

impl ProtonProvider {
    /// Create a new provider, resolving the `pass-cli` binary location.
    pub fn new() -> Self {
        Self {
            pass_path: resolve_pass_path(),
        }
    }
}

/// Find `pass-cli` on `$PATH`, falling back to well-known install locations.
fn resolve_pass_path() -> Option<String> {
    let which_cmd = if cfg!(target_os = "windows") {
        "where"
    } else {
        "which"
    };
    let from_path = Command::new(which_cmd)
        .arg("pass-cli")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .next()
                .unwrap_or_default()
                .trim()
                .to_string()
        })
        .filter(|s| !s.is_empty());

    if from_path.is_some() {
        return from_path;
    }

    // Default installer location: ~/.local/bin/pass-cli
    if let Ok(home) = std::env::var("HOME") {
        let candidate = format!("{home}/.local/bin/pass-cli");
        if std::path::Path::new(&candidate).exists() {
            return Some(candidate);
        }
    }

    for candidate in PASS_FALLBACK_PATHS {
        if std::path::Path::new(candidate).exists() {
            return Some((*candidate).to_string());
        }
    }

    None
}

/// Check whether there is an active `pass-cli` session via `pass-cli info`.
fn check_session(pass: &str) -> Session {
    match Command::new(pass)
        .args(["info", "--output", "json"])
        .output()
    {
        Ok(o) if o.status.success() => {
            let email = serde_json::from_slice::<PassInfo>(&o.stdout)
                .ok()
                .and_then(|i| i.email)
                .filter(|s| !s.is_empty());
            Session::Active(email)
        }
        _ => Session::Inactive,
    }
}

/// The reason recorded against an item read, from `PROTON_PASS_AGENT_REASON`.
///
/// Proton requires this to be non-empty and at most 300 characters for
/// agent-scoped sessions, so we fall back to a default and truncate.
fn agent_reason() -> String {
    let reason = std::env::var("PROTON_PASS_AGENT_REASON")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_AGENT_REASON.to_string());
    if reason.chars().count() > MAX_AGENT_REASON_LEN {
        reason.chars().take(MAX_AGENT_REASON_LEN).collect()
    } else {
        reason
    }
}

/// List the vaults (share IDs) the session can access.
fn list_vaults(pass: &str) -> Vec<VaultEntry> {
    Command::new(pass)
        .args(["vault", "list", "--output", "json"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| serde_json::from_slice::<VaultList>(&o.stdout).ok())
        .map(|v| v.vaults)
        .unwrap_or_default()
}

/// List items within a vault with full content via `--show-secrets`.
///
/// Returns `None` when `--show-secrets` is unavailable — most importantly for
/// agent-scoped sessions, where Proton rejects it — signalling the caller to use
/// the per-item `item view` fallback.
fn list_items_full(pass: &str, share_id: &str, login_only: bool) -> Option<Vec<PassItem>> {
    // `--share-id` is attached (`=VALUE`): share IDs can start with `-`.
    let mut cmd = Command::new(pass);
    cmd.arg("item")
        .arg("list")
        .arg(format!("--share-id={share_id}"))
        .arg("--show-secrets")
        .arg("--output")
        .arg("json");
    if login_only {
        cmd.arg("--filter-type").arg("login");
    }
    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }
    serde_json::from_slice::<ItemListFull>(&output.stdout)
        .ok()
        .map(|l| l.items)
}

/// List item metadata (no secrets) within a vault.
fn list_items_meta(pass: &str, share_id: &str) -> Vec<ItemEntry> {
    Command::new(pass)
        .arg("item")
        .arg("list")
        .arg(format!("--share-id={share_id}"))
        .arg("--output")
        .arg("json")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| serde_json::from_slice::<ItemList>(&o.stdout).ok())
        .map(|l| l.items)
        .unwrap_or_default()
}

/// Read a single item by `pass://SHARE_ID/ITEM_ID` and map it to a credential.
///
/// Returns `None` for a failed read or a non-login item.
fn view_item(pass: &str, share_id: &str, item_id: &str, reason: &str) -> Option<CredentialData> {
    let uri = format!("pass://{share_id}/{item_id}");
    let output = Command::new(pass)
        .args(["item", "view", &uri, "--output", "json"])
        .env("PROTON_PASS_AGENT_REASON", reason)
        .stdin(Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        info!("pass-cli item view failed: {}", stderr.trim());
        return None;
    }

    let view: PassView = serde_json::from_slice(&output.stdout).ok()?;
    cred_from_item(view.item)
}

/// Map a parsed Proton item into a [`CredentialData`], or `None` if it is not a
/// login item.
fn cred_from_item(item: PassItem) -> Option<CredentialData> {
    let note = item.content.note;
    let login = item.content.content.login?;

    let uri = login
        .urls
        .unwrap_or_default()
        .into_iter()
        .find(|u| !u.is_empty());
    let domain = uri.as_deref().and_then(domain_from_uri);

    // Proton stores email and username separately; prefer an explicit username.
    let username = non_empty(login.username).or_else(|| non_empty(login.email));

    Some(CredentialData {
        username,
        password: non_empty(login.password).map(Zeroizing::new),
        totp: non_empty(login.totp_uri),
        uri,
        notes: non_empty(note),
        credential_id: item.id,
        domain,
    })
}

/// Whether a login item satisfies a domain query, checking the item title and
/// every stored URL host.
fn item_matches_domain(item: &PassItem, domain: &str) -> bool {
    if let Some(title) = &item.content.title {
        if domain_matches(title, domain) {
            return true;
        }
    }
    item.content
        .content
        .login
        .as_ref()
        .and_then(|l| l.urls.as_ref())
        .into_iter()
        .flatten()
        .filter_map(|u| domain_from_uri(u))
        .any(|host| domain_matches(&host, domain))
}

/// Resolve a query within a single vault.
///
/// The common cases — an item id, a title, or a domain that matches an item
/// title — are served by a cheap metadata listing plus a single `item view`, so
/// lookups stay fast even on large vaults (and don't freeze the caller while a
/// whole vault's secrets are pulled). Only a domain that matches *no* title
/// falls back to inspecting stored URLs: one bulk `--show-secrets` listing, or
/// per-item `item view` for agent sessions where `--show-secrets` is rejected.
fn resolve_in_vault(
    pass: &str,
    share_id: &str,
    query: &CredentialQuery,
    reason: &str,
) -> Option<CredentialData> {
    let meta = list_items_meta(pass, share_id);

    // Cheap resolution by id or title — no bulk secret retrieval.
    let direct = match query {
        CredentialQuery::Id(id) => meta.iter().find(|m| m.id == *id).cloned(),
        CredentialQuery::Search(term) => find_by_title(&meta, term),
        CredentialQuery::Domain(domain) => meta
            .iter()
            .find(|m| {
                m.title
                    .as_deref()
                    .is_some_and(|t| domain_matches(t, domain))
            })
            .cloned(),
    };
    if let Some(m) = direct {
        if let Some(cred) = view_item(pass, share_id, &m.id, reason) {
            return Some(cred);
        }
    }

    // Domain with no matching title: inspect stored URLs.
    if let CredentialQuery::Domain(domain) = query {
        // One bulk listing with secrets, when permitted (non-agent sessions).
        if let Some(items) = list_items_full(pass, share_id, true) {
            return items
                .into_iter()
                .find(|it| item_matches_domain(it, domain))
                .and_then(cred_from_item);
        }
        // Agent sessions: view login candidates individually (scoped, so few).
        for m in &meta {
            if m.item_type.as_deref() != Some("login") {
                continue;
            }
            if let Some(cred) = view_item(pass, share_id, &m.id, reason) {
                if cred
                    .domain
                    .as_deref()
                    .is_some_and(|h| domain_matches(h, domain))
                {
                    return Some(cred);
                }
            }
        }
    }
    None
}

/// Find the first metadata entry whose title matches `term` (exact preferred,
/// otherwise a case-insensitive substring match).
fn find_by_title(items: &[ItemEntry], term: &str) -> Option<ItemEntry> {
    let needle = term.to_lowercase();
    let mut substring: Option<&ItemEntry> = None;
    for it in items {
        if let Some(title) = &it.title {
            let title = title.to_lowercase();
            if title == needle {
                return Some(it.clone());
            }
            if substring.is_none() && title.contains(&needle) {
                substring = Some(it);
            }
        }
    }
    substring.cloned()
}

/// Whether a credential's host satisfies a domain query, allowing for
/// sub/parent-domain relationships (`mail.example.com` ~ `example.com`).
fn domain_matches(host: &str, query: &str) -> bool {
    let host = host.to_lowercase();
    let query = query.to_lowercase();
    host == query || host.ends_with(&format!(".{query}")) || query.ends_with(&format!(".{host}"))
}

/// Trim a possibly-empty CLI string into an `Option`, dropping empties.
fn non_empty(s: Option<String>) -> Option<String> {
    s.filter(|v| !v.is_empty())
}

/// Extract the domain (host) from a URI string, e.g. `https://example.com/path` → `example.com`.
fn domain_from_uri(uri: &str) -> Option<String> {
    // Strip scheme (e.g. "https://")
    let after_scheme = match uri.split_once("://") {
        Some((_, rest)) => rest,
        None => uri,
    };
    // Strip userinfo (e.g. "user:pass@")
    let after_userinfo = match after_scheme.split_once('@') {
        Some((_, rest)) => rest,
        None => after_scheme,
    };
    // Take host (before any '/' or ':')
    let host = after_userinfo.split(['/', ':']).next()?;
    if host.is_empty() {
        return None;
    }
    Some(host.to_string())
}

/// Create a `ProtonProvider` with an explicit path (for testing without
/// spawning `which`).
#[cfg(test)]
impl ProtonProvider {
    fn with_path(pass_path: Option<String>) -> Self {
        Self { pass_path }
    }
}

impl CredentialProvider for ProtonProvider {
    fn name(&self) -> &str {
        "Proton Pass"
    }

    fn status(&self) -> ProviderStatus {
        let pass = match &self.pass_path {
            Some(p) => p,
            None => {
                return ProviderStatus::NotInstalled {
                    install_hint: "Install the Proton Pass CLI and add it to your path: https://protonpass.github.io/pass-cli/get-started/installation/".to_string(),
                };
            }
        };

        match check_session(pass) {
            Session::Active(email) => ProviderStatus::Ready { user_info: email },
            Session::Inactive => ProviderStatus::Locked {
                prompt: "Proton Pass personal access token (pst_...)".to_string(),
                user_info: None,
            },
        }
    }

    fn unlock(&mut self, input: &str) -> Result<(), String> {
        let pass = self
            .pass_path
            .as_deref()
            .ok_or("Proton Pass CLI not found")?;

        // A Personal Access Token authenticates non-interactively when supplied
        // via the environment; `stdin = null` prevents any interactive fallback.
        let output = Command::new(pass)
            .arg("login")
            .env("PROTON_PASS_PERSONAL_ACCESS_TOKEN", input)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("Failed to run pass-cli login: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(if stderr.is_empty() {
                "pass-cli login failed".to_string()
            } else {
                stderr
            });
        }

        match check_session(pass) {
            Session::Active(_) => Ok(()),
            Session::Inactive => {
                Err("Login succeeded but no active session could be established".to_string())
            }
        }
    }

    fn lookup(&self, query: &CredentialQuery) -> LookupResult {
        let pass = match &self.pass_path {
            Some(p) => p,
            None => {
                return LookupResult::NotReady {
                    message: "Proton Pass CLI not found".to_string(),
                };
            }
        };

        if let Session::Inactive = check_session(pass) {
            return LookupResult::NotReady {
                message: "Proton Pass session is not active — provide a personal access token"
                    .to_string(),
            };
        }

        let vaults = list_vaults(pass);
        if vaults.is_empty() {
            return LookupResult::NotReady {
                message: "No accessible Proton Pass vaults".to_string(),
            };
        }

        let reason = agent_reason();
        for vault in &vaults {
            if let Some(cred) = resolve_in_vault(pass, &vault.share_id, query, &reason) {
                return LookupResult::Found(cred);
            }
        }
        LookupResult::NotFound
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- domain_from_uri() ---------------------------------------------------

    #[test]
    fn domain_from_uri_with_scheme_and_path() {
        assert_eq!(
            domain_from_uri("https://example.com/path"),
            Some("example.com".into())
        );
    }

    #[test]
    fn domain_from_uri_with_port_and_userinfo() {
        assert_eq!(
            domain_from_uri("https://user:pass@example.com:8080/x"),
            Some("example.com".into())
        );
    }

    #[test]
    fn domain_from_uri_empty() {
        assert_eq!(domain_from_uri("https://"), None);
        assert_eq!(domain_from_uri(""), None);
    }

    // -- domain_matches() ----------------------------------------------------

    #[test]
    fn domain_matches_exact_and_relatives() {
        assert!(domain_matches("example.com", "example.com"));
        assert!(domain_matches("mail.example.com", "example.com"));
        assert!(domain_matches("example.com", "mail.example.com"));
        assert!(domain_matches("EXAMPLE.com", "example.COM"));
        assert!(!domain_matches("notexample.com", "example.com"));
        assert!(!domain_matches("example.org", "example.com"));
    }

    // -- non_empty() ---------------------------------------------------------

    #[test]
    fn non_empty_drops_empty_strings() {
        assert_eq!(non_empty(Some("x".into())), Some("x".into()));
        assert_eq!(non_empty(Some(String::new())), None);
        assert_eq!(non_empty(None), None);
    }

    // -- agent_reason() ------------------------------------------------------

    #[test]
    fn agent_reason_truncates_to_limit() {
        // SAFETY: env mutation is fine in this single-threaded test.
        unsafe { std::env::set_var("PROTON_PASS_AGENT_REASON", "x".repeat(500)) };
        assert_eq!(agent_reason().chars().count(), MAX_AGENT_REASON_LEN);
        unsafe { std::env::remove_var("PROTON_PASS_AGENT_REASON") };
        assert_eq!(agent_reason(), DEFAULT_AGENT_REASON);
    }

    // -- find_by_title() / select_by_title() --------------------------------

    fn meta(id: &str, title: &str) -> ItemEntry {
        ItemEntry {
            id: id.into(),
            title: Some(title.into()),
            item_type: Some("login".into()),
        }
    }

    #[test]
    fn find_by_title_prefers_exact_over_substring() {
        let items = vec![
            meta("1", "My GitHub Account"),
            meta("2", "github"),
            meta("3", "GitHub Enterprise"),
        ];
        assert_eq!(
            find_by_title(&items, "GitHub").expect("exact match").id,
            "2"
        );
        assert!(find_by_title(&items, "gitlab").is_none());
    }

    // -- item view / list JSON parsing --------------------------------------

    const LOGIN_JSON: &str = r#"{
        "id": "item-123",
        "share_id": "share-1",
        "vault_id": "vault-1",
        "content": {
            "title": "Example",
            "note": "a note",
            "item_uuid": "uuid-1",
            "content": {
                "Login": {
                    "email": "alice@example.com",
                    "username": "",
                    "password": "s3cret",
                    "urls": ["https://example.com/login", "https://mail.example.com"],
                    "totp_uri": "otpauth://totp/x?secret=ABC",
                    "passkeys": [{"key_id": "k", "content": [1, 2, 3]}]
                }
            }
        }
    }"#;

    #[test]
    fn parses_login_item_and_maps_credential() {
        let item: PassItem = serde_json::from_str(LOGIN_JSON).expect("should parse");
        let cred = cred_from_item(item).expect("login item maps to a credential");
        // username empty → falls back to email.
        assert_eq!(cred.username.as_deref(), Some("alice@example.com"));
        assert_eq!(cred.password.as_deref().map(String::as_str), Some("s3cret"));
        assert_eq!(cred.totp.as_deref(), Some("otpauth://totp/x?secret=ABC"));
        assert_eq!(cred.uri.as_deref(), Some("https://example.com/login"));
        assert_eq!(cred.domain.as_deref(), Some("example.com"));
        assert_eq!(cred.credential_id.as_deref(), Some("item-123"));
        assert_eq!(cred.notes.as_deref(), Some("a note"));
    }

    #[test]
    fn item_matches_domain_by_title_and_secondary_url() {
        let item: PassItem = serde_json::from_str(LOGIN_JSON).expect("should parse");
        // Matches the second URL's host via parent-domain relationship.
        assert!(item_matches_domain(&item, "example.com"));
        // Matches the title.
        assert!(item_matches_domain(&item, "Example"));
        assert!(!item_matches_domain(&item, "other.org"));
    }

    #[test]
    fn item_view_view_wrapper_parses() {
        let json = format!(r#"{{ "item": {LOGIN_JSON} }}"#);
        let view: PassView = serde_json::from_str(&json).expect("view wrapper parses");
        assert_eq!(view.item.id.as_deref(), Some("item-123"));
    }

    #[test]
    fn non_login_item_has_no_login_variant() {
        let json = r#"{
            "id": "n1",
            "content": {
                "title": "Secure Note",
                "note": "text",
                "content": { "Note": {} }
            }
        }"#;
        let item: PassItem = serde_json::from_str(json).expect("should parse");
        assert!(cred_from_item(item).is_none());
    }

    // -- provider construction ----------------------------------------------

    #[test]
    fn provider_name_is_proton_pass() {
        let p = ProtonProvider::with_path(None);
        assert_eq!(p.name(), "Proton Pass");
    }

    #[test]
    fn status_not_installed_without_binary() {
        let p = ProtonProvider::with_path(None);
        assert!(matches!(p.status(), ProviderStatus::NotInstalled { .. }));
    }

    #[test]
    fn lookup_not_ready_without_binary() {
        let p = ProtonProvider::with_path(None);
        assert!(matches!(
            p.lookup(&CredentialQuery::Domain("example.com".into())),
            LookupResult::NotReady { .. }
        ));
    }

    // -- live integration ----------------------------------------------------
    // Requires a real `pass-cli` session and an item titled (or URL'd) for
    // "proton.me". Run explicitly: `cargo test -p ap-cli -- --ignored live_`
    // Asserts booleans only — never prints secret values.

    #[test]
    #[ignore = "requires a live pass-cli session"]
    fn live_status_is_ready() {
        let p = ProtonProvider::new();
        assert!(
            matches!(p.status(), ProviderStatus::Ready { .. }),
            "expected an active pass-cli session"
        );
    }

    #[test]
    #[ignore = "requires a live pass-cli session with a 'proton.me' login item"]
    fn live_lookup_by_domain() {
        let p = ProtonProvider::new();
        match p.lookup(&CredentialQuery::Domain("proton.me".into())) {
            LookupResult::Found(cred) => {
                assert!(
                    cred.password.is_some(),
                    "login item should carry a password"
                );
                assert!(cred.credential_id.is_some(), "should carry an item id");
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }
}
