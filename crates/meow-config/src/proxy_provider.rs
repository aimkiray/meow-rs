use crate::proxy_parser;
use crate::raw::{RawHealthCheck, RawProxyProvider};
use meow_common::atomic::AtomicU;
use meow_common::{ProviderSlot, Proxy};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

pub struct HealthCheckConfig {
    pub url: String,
    pub interval: u64,
    pub timeout: u64,
    pub expected_status: String,
    pub lazy: bool,
}

pub struct ProxyProvider {
    pub name: String,
    pub slot: ProviderSlot,
    pub vehicle_type: &'static str,
    vehicle: Vehicle,
    filter: Option<regex::Regex>,
    exclude_filter: Option<regex::Regex>,
    exclude_type: Vec<String>,
    pub health_check: Option<HealthCheckConfig>,
    updated_at: AtomicU,
    /// Flattened custom request headers (name-sorted; one entry per value,
    /// so multi-value headers repeat the name — RFC 9110 §5.2).
    header: Vec<(String, String)>,
    ipv6: bool,
    /// Whether `plugin:` on provider-sourced nodes may name an external
    /// SIP003 executable. Provider content is remote-controlled; without the
    /// opt-in such nodes are rejected before reaching `Command::new`.
    allow_external_plugin: bool,
    /// Top-level `strict: true` (issue #533): an unparseable node in the
    /// payload fails the parse instead of being warn-skipped — at load time
    /// that rejects the whole config; on refresh it keeps the last-good set.
    /// Atomic so a committed `strict`-flip (`PUT /configs`) reaches provider
    /// objects that were reused across the rebuild.
    strict: AtomicBool,
    /// Group-level filtered views of `slot` (issue #358), re-populated on
    /// every refresh. Weak: each view is kept alive by the group built from
    /// it, so views belonging to dropped or rebuilt groups get pruned here.
    derived: RwLock<Vec<(GroupFilter, WeakSlot)>>,
    /// The declaration this provider was built from (plus the effective
    /// `ipv6` it was parsed under — not part of `def`), normalized by
    /// [`Self::def_identity`]. Runtime rebuilds reuse a live provider only
    /// when the candidate def matches; a changed `url`/`path`/`filter`/
    /// `health-check`/`allow-external-plugin` must produce a fresh
    /// provider, not silently keep fetching the old one (issue #533
    /// review).
    def: RawProxyProvider,
}

/// Weak counterpart of [`ProviderSlot`].
type WeakSlot = std::sync::Weak<RwLock<Vec<Arc<dyn Proxy>>>>;

/// Compiled group-level member filter (issue #358): the `filter`,
/// `exclude-filter`, and `exclude-type` fields declared on a proxy-group
/// apply to the proxies that group pulls from providers (`use:` /
/// `include-all`), mirroring mihomo. Static `proxies:` members bypass the
/// filter, also matching upstream (compatible providers are not filtered).
#[derive(Clone, Debug)]
pub struct GroupFilter {
    filter: Option<regex::Regex>,
    exclude_filter: Option<regex::Regex>,
    exclude_type: Vec<String>,
}

impl GroupFilter {
    /// Compile the filter fields of a raw proxy-group. Returns `Ok(None)`
    /// when the group declares no filtering at all.
    pub fn from_raw_group(raw: &crate::raw::RawProxyGroup) -> Result<Option<Self>, String> {
        let filter = compile_opt_regex(&raw.filter, "filter")?;
        let exclude_filter = compile_opt_regex(&raw.exclude_filter, "exclude-filter")?;
        let exclude_type = split_exclude_types(raw.exclude_type.as_deref());
        if filter.is_none() && exclude_filter.is_none() && exclude_type.is_empty() {
            return Ok(None);
        }
        Ok(Some(Self {
            filter,
            exclude_filter,
            exclude_type,
        }))
    }

    fn keep(&self, proxy: &dyn Proxy) -> bool {
        let name = proxy.name();
        if let Some(re) = &self.filter {
            if !re.is_match(name) {
                return false;
            }
        }
        if let Some(re) = &self.exclude_filter {
            if re.is_match(name) {
                return false;
            }
        }
        !self
            .exclude_type
            .iter()
            .any(|t| adapter_type_matches(t, proxy.adapter_type()))
    }
}

/// Match an `exclude-type` token against a parsed adapter's type. Accepts
/// both the adapter display name ("Shadowsocks") and the config-file alias
/// ("ss") so either spelling works, case-insensitively.
fn adapter_type_matches(token: &str, adapter_type: meow_common::AdapterType) -> bool {
    if token.eq_ignore_ascii_case(&adapter_type.to_string()) {
        return true;
    }
    matches!(adapter_type, meow_common::AdapterType::Shadowsocks)
        && token.eq_ignore_ascii_case("ss")
}

/// `exclude-type` accepts a YAML list or a mihomo-style `|`-separated string
/// ("ss|http"); flatten both into lowercase tokens.
fn split_exclude_types(raw: Option<&[String]>) -> Vec<String> {
    raw.unwrap_or(&[])
        .iter()
        .flat_map(|s| s.split('|'))
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

enum Vehicle {
    File(PathBuf),
    Http {
        url: String,
        /// `None` = fetch to memory only (no containment root available for
        /// an on-disk cache; issue #429).
        cache_path: Option<PathBuf>,
    },
}

impl ProxyProvider {
    pub fn new(
        name: &str,
        raw: &RawProxyProvider,
        cache_dir: Option<&Path>,
        ipv6: bool,
        strict: bool,
    ) -> Result<Self, String> {
        // Any on-disk location (read or write) must stay inside `cache_dir`
        // (issue #429): `path:` — and the provider *name* feeding the implicit
        // cache location — are attacker-influenced when the config document
        // does not come from a trusted on-disk file. Without a `cache_dir`
        // there is no containment root, so no caller-named path is honoured.
        let (vehicle, vehicle_type) = match raw.provider_type.as_str() {
            "file" => {
                let path_str = raw
                    .path
                    .as_deref()
                    .ok_or("file proxy-provider requires 'path'")?;
                let Some(dir) = cache_dir else {
                    return Err(format!(
                        "proxy-provider '{name}': 'path' cannot be used without a provider \
                         cache directory"
                    ));
                };
                let path = crate::safe_path::resolve_contained(dir, Path::new(path_str))
                    .map_err(|e| format!("proxy-provider '{name}': {e}"))?;
                (Vehicle::File(path), "File")
            }
            "http" => {
                let url = raw
                    .url
                    .as_deref()
                    .ok_or("http proxy-provider requires 'url'")?
                    .to_string();
                // An unparseable `url:` is a permanent defect, not a
                // transient fetch failure — under strict surface it at
                // load instead of registering an empty provider that
                // retries forever (issue #533 review).
                if strict && url::Url::parse(&url).is_err() {
                    return Err(format!(
                        "proxy-provider '{name}': invalid url '{url}' (strict mode)"
                    ));
                }
                let cache_path = match (raw.path.as_deref(), cache_dir) {
                    (Some(p), Some(dir)) => Some(
                        crate::safe_path::resolve_contained(dir, Path::new(p))
                            .map_err(|e| format!("proxy-provider '{name}': {e}"))?,
                    ),
                    (Some(_), None) => {
                        warn!(
                            provider = %name,
                            "ignoring 'path' (no provider cache directory in this context); \
                             fetching to memory without an on-disk cache"
                        );
                        None
                    }
                    (None, Some(dir)) => Some(
                        crate::safe_path::resolve_contained(
                            dir,
                            Path::new(&format!("provider_{name}.yaml")),
                        )
                        .map_err(|e| format!("proxy-provider '{name}': {e}"))?,
                    ),
                    (None, None) => None,
                };
                (Vehicle::Http { url, cache_path }, "HTTP")
            }
            t => return Err(format!("unknown proxy-provider type '{t}'")),
        };

        let filter = compile_opt_regex(&raw.filter, "filter")?;
        let exclude_filter = compile_opt_regex(&raw.exclude_filter, "exclude-filter")?;
        let exclude_type = split_exclude_types(raw.exclude_type.as_deref());

        let health_check = build_health_check_config(raw.health_check.as_ref());
        let header = raw
            .header
            .as_ref()
            .map(crate::raw::flatten_header_map)
            .unwrap_or_default();

        Ok(Self {
            name: name.to_string(),
            slot: Arc::new(RwLock::new(Vec::new())),
            vehicle_type,
            vehicle,
            filter,
            exclude_filter,
            exclude_type,
            health_check,
            updated_at: AtomicU::new(0),
            header,
            ipv6,
            allow_external_plugin: raw.allow_external_plugin.unwrap_or(false),
            strict: AtomicBool::new(strict),
            derived: RwLock::new(Vec::new()),
            def: Self::def_identity(raw),
        })
    }

    /// The fields of a declaration that determine provider identity.
    /// `interval` is excluded: no periodic proxy-provider refresh task
    /// consumes it (only the manual PUT endpoint exists), so changing it
    /// alone must not force a rebuild + refetch (issue #533 review).
    fn def_identity(raw: &RawProxyProvider) -> RawProxyProvider {
        RawProxyProvider {
            interval: None,
            ..raw.clone()
        }
    }

    /// Update the strict flag after a committed config rebuild — providers
    /// reused across a `PUT /configs` must follow the new generation's
    /// strictness (issue #533 review).
    pub fn set_strict(&self, strict: bool) {
        self.strict.store(strict, Ordering::Relaxed);
    }

    /// `true` when this provider was built from `def` under the same
    /// effective `ipv6` — the identity check `use:`/`include-all` rebuilds
    /// apply before deciding to reuse the live object. A changed
    /// declaration rebuilds the provider instead of silently fetching the
    /// old source forever (issue #533 review).
    pub fn matches_def(&self, def: &RawProxyProvider, ipv6: bool) -> bool {
        self.ipv6 == ipv6 && self.def == Self::def_identity(def)
    }

    /// Create a live filtered view of this provider's proxies for one group
    /// (issue #358). The view is seeded from the current slot contents and
    /// re-populated on every [`refresh`](Self::refresh).
    pub fn derived_slot(&self, filter: &GroupFilter) -> ProviderSlot {
        let seeded: Vec<Arc<dyn Proxy>> = self
            .slot
            .read()
            .iter()
            .filter(|p| filter.keep(p.as_ref()))
            .map(Arc::clone)
            .collect();
        let slot: ProviderSlot = Arc::new(RwLock::new(seeded));
        self.derived
            .write()
            .push((filter.clone(), Arc::downgrade(&slot)));
        slot
    }

    fn update_derived(&self, proxies: &[Arc<dyn Proxy>]) {
        let mut derived = self.derived.write();
        derived.retain(|(filter, weak)| {
            let Some(slot) = weak.upgrade() else {
                return false;
            };
            *slot.write() = proxies
                .iter()
                .filter(|p| filter.keep(p.as_ref()))
                .map(Arc::clone)
                .collect();
            true
        });
    }

    /// Drop derived slots whose owning group is gone. Candidate builds
    /// register views on *live* reused providers before validation finishes,
    /// so a failed build leaves dead `Weak`s behind — pruning at commit
    /// keeps that bounded instead of waiting for the next refresh
    /// (issue #533 review).
    pub fn prune_dead_derived(&self) {
        self.derived
            .write()
            .retain(|(_, weak)| weak.upgrade().is_some());
    }

    async fn fetch_content(&self) -> Result<String, String> {
        match &self.vehicle {
            Vehicle::File(path) => tokio::fs::read_to_string(path).await.map_err(|e| {
                format!(
                    "proxy-provider '{}': failed to read {:?}: {}",
                    self.name, path, e
                )
            }),
            Vehicle::Http { url, cache_path } => {
                let fetched = crate::internal_http::fetch(url, None, &self.header)
                    .await
                    .and_then(|bytes| {
                        String::from_utf8(bytes)
                            .map_err(|e| anyhow::anyhow!("response body is not UTF-8: {e}"))
                    });
                match fetched {
                    Ok(text) => {
                        // Cache to disk for offline fallback — atomic
                        // write-then-rename on a unique scratch: the
                        // manual-refresh endpoint and a detached initial
                        // fetch can race this write unlaned, and a torn
                        // cache would poison the next fallback read
                        // (issue #543 review).
                        if let Some(cache_path) = cache_path {
                            if let Some(parent) = cache_path.parent() {
                                let _ = tokio::fs::create_dir_all(parent).await;
                            }
                            let tmp = crate::unique_scratch_path(cache_path);
                            let saved = match tokio::fs::write(&tmp, &text).await {
                                Ok(()) => tokio::fs::rename(&tmp, cache_path).await.is_ok(),
                                Err(_) => false,
                            };
                            if !saved {
                                let _ = tokio::fs::remove_file(&tmp).await;
                            }
                        }
                        Ok(text)
                    }
                    Err(e) => {
                        warn!(provider = %self.name, error = %e, "HTTP provider fetch failed, trying cache");
                        read_cache(cache_path.as_deref(), &self.name).await
                    }
                }
            }
        }
    }

    /// Parse a fetched provider payload into proxies. `Err` only under
    /// `strict` (`strict: true`, issue #533) — a malformed document or an
    /// unparseable node; the lenient path warns and skips instead.
    async fn parse_proxies(&self, content: &str) -> Result<Vec<Arc<dyn Proxy>>, String> {
        let strict = self.strict.load(Ordering::Relaxed);
        if !crate::yaml_within_depth(content) {
            if strict {
                return Err(
                    "provider YAML exceeds the nesting-depth limit (strict mode)".to_string(),
                );
            }
            warn!(provider = %self.name, "provider YAML exceeds the nesting-depth limit");
            return Ok(Vec::new());
        }
        let doc: serde_yaml::Value = match serde_yaml::from_str(content) {
            Ok(v) => v,
            Err(e) => {
                if strict {
                    return Err(format!("provider YAML is malformed (strict mode): {e}"));
                }
                warn!(provider = %self.name, error = %e, "failed to parse provider YAML");
                return Ok(Vec::new());
            }
        };

        // Accept both `proxies: [...]` wrapper and a bare list. A
        // `Value::Null` document is an empty or comments-only file — treat
        // it as an empty provider rather than a parse defect so an editor /
        // external tool mid-rewrite doesn't hard-fail strict mode
        // (parity with the missing-file acquisition path, issue #533).
        let list_val = match doc.get("proxies").cloned().unwrap_or_else(|| doc.clone()) {
            serde_yaml::Value::Null => serde_yaml::Value::Sequence(Vec::new()),
            v => v,
        };

        let mut proxy_maps: Vec<HashMap<String, serde_yaml::Value>> = match serde_yaml::from_value(
            list_val,
        ) {
            Ok(v) => v,
            Err(e) => {
                if strict {
                    return Err(format!(
                        "provider content is not a proxy list (strict mode): {e}"
                    ));
                }
                warn!(provider = %self.name, error = %e, "provider content is not a proxy list");
                return Ok(Vec::new());
            }
        };

        // Pre-resolve any DNS-sourced ECH configs into inline base64 — keeps
        // `parse_proxy` itself sync. An `ech-opts.enable: true` node with no
        // query source at all is a defect — strict turns it into an error.
        crate::ech_dns::preresolve_ech(&mut proxy_maps, strict)
            .await
            .map_err(|e| format!("{e} (strict mode)"))?;

        let mut result = Vec::new();
        for raw_map in &proxy_maps {
            // Get raw name/type before parsing so we can filter cheaply.
            let raw_name = raw_map.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let raw_type = raw_map
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();

            if let Some(ref re) = self.filter {
                if !re.is_match(raw_name) {
                    continue;
                }
            }
            if let Some(ref re) = self.exclude_filter {
                if re.is_match(raw_name) {
                    continue;
                }
            }
            if self.exclude_type.iter().any(|t| t == &raw_type) {
                continue;
            }

            match proxy_parser::parse_proxy_provider_node(
                raw_map,
                self.ipv6,
                self.allow_external_plugin,
            ) {
                Ok(proxy) => result.push(proxy),
                Err(e) => {
                    if strict {
                        return Err(format!(
                            "node '{raw_name}' failed to parse (strict mode): {e}"
                        ));
                    }
                    warn!(provider = %self.name, proxy = raw_name, error = %e, "failed to parse proxy");
                }
            }
        }

        Ok(result)
    }

    /// Publish a freshly parsed node set — shared by `refresh` and the
    /// strict-gated initial load in [`load_proxy_providers`].
    fn commit(&self, proxies: Vec<Arc<dyn Proxy>>) {
        info!(provider = %self.name, count = proxies.len(), "proxy-provider refreshed");
        // Main slot first, then the derived views — readers can never
        // observe new derived contents against a stale main slot.
        *self.slot.write() = proxies;
        self.update_derived(&self.slot.read());
        self.updated_at.store(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as meow_common::atomic::Uint,
            Ordering::Relaxed,
        );
    }

    pub async fn refresh(&self) -> Result<(), String> {
        match self.fetch_content().await {
            Ok(content) => match self.parse_proxies(&content).await {
                Ok(proxies) => {
                    self.commit(proxies);
                    Ok(())
                }
                Err(e) => {
                    // Reachable only under `strict` — a torn payload keeps the
                    // last-good set instead of replacing it with nothing.
                    warn!(provider = %self.name, error = %e, "proxy-provider refresh failed");
                    Err(e)
                }
            },
            Err(e) => {
                warn!(provider = %self.name, error = %e, "proxy-provider refresh failed");
                Err(e)
            }
        }
    }

    pub fn proxies(&self) -> Vec<Arc<dyn Proxy>> {
        self.slot.read().clone()
    }

    #[cfg(test)]
    fn derived_len(&self) -> usize {
        self.derived.read().len()
    }

    pub fn updated_at_secs(&self) -> u64 {
        #[allow(
            clippy::useless_conversion,
            reason = "identity on 64-bit; widens u32 on targets without 64-bit atomics"
        )]
        self.updated_at.load(Ordering::Relaxed).into()
    }
}

/// Validate every proxy-provider's on-disk path up front, so a path escaping
/// the provider cache directory fails the whole (re)build loudly — matching
/// `rule_provider::validate_paths` — instead of the provider being silently
/// warn-skipped and every group referencing it degrading (PR #444 review
/// follow-up).
///
/// Scope is containment only: paths that resolve outside `cache_dir`
/// (explicit `path:` or the implicit name-derived cache location). Other
/// per-provider problems (missing fields, unknown type, fetch failures) keep
/// their historical warn-and-skip semantics in [`ProxyProvider::new`] /
/// [`load_proxy_providers`]. Must stay in sync with the path resolution in
/// [`ProxyProvider::new`].
pub(crate) fn validate_paths(
    raw_map: &HashMap<String, RawProxyProvider>,
    cache_dir: Option<&Path>,
) -> Result<(), String> {
    // No containment root: no on-disk path is honoured at all, so there is
    // nothing to contain (`ProxyProvider::new` errors/warns per provider).
    let Some(dir) = cache_dir else {
        return Ok(());
    };
    for (name, raw) in raw_map {
        let requested = match (raw.provider_type.as_str(), raw.path.as_deref()) {
            ("file" | "http", Some(p)) => PathBuf::from(p),
            // The implicit http cache location is derived from the provider
            // *name* (a YAML map key, also attacker-influenced).
            ("http", None) => PathBuf::from(format!("provider_{name}.yaml")),
            _ => continue,
        };
        crate::safe_path::resolve_contained(dir, &requested)
            .map_err(|e| format!("proxy-provider '{name}': {e}"))?;
    }
    Ok(())
}

pub async fn load_proxy_providers(
    raw_map: &HashMap<String, RawProxyProvider>,
    cache_dir: Option<&Path>,
    ipv6: bool,
    strict: bool,
) -> Result<HashMap<String, Arc<ProxyProvider>>, anyhow::Error> {
    let mut result = HashMap::new();
    for (name, raw) in raw_map {
        match ProxyProvider::new(name, raw, cache_dir, ipv6, strict) {
            Ok(provider) => {
                let provider = Arc::new(provider);
                if strict {
                    // Strict gates the *parse*, not the fetch: a transient
                    // download failure is not a config defect, so a provider
                    // that can't be fetched still starts empty and stays
                    // empty until a manual refresh or restart.
                    match provider.fetch_content().await {
                        Ok(content) => {
                            let proxies = provider
                                .parse_proxies(&content)
                                .await
                                .map_err(|e| anyhow::anyhow!("proxy-provider '{name}': {e}"))?;
                            provider.commit(proxies);
                        }
                        Err(e) => {
                            warn!(provider = %name, error = %e,
                                "initial fetch failed; starting empty");
                        }
                    }
                } else {
                    let _ = provider.refresh().await;
                }
                result.insert(name.clone(), provider);
            }
            Err(e) if strict => {
                return Err(anyhow::anyhow!(
                    "proxy-provider '{name}' failed to load (strict mode): {e}"
                ));
            }
            Err(e) => {
                warn!(provider = %name, error = %e, "failed to create proxy-provider, skipping");
            }
        }
    }
    Ok(result)
}

fn compile_opt_regex(
    pattern: &Option<String>,
    field: &str,
) -> Result<Option<regex::Regex>, String> {
    match pattern.as_deref() {
        Some(p) => regex::Regex::new(p).map(Some).map_err(|e| {
            let hint = if ["(?!", "(?=", "(?<"].iter().any(|la| p.contains(la)) {
                "; look-around assertions are not supported — split the pattern \
                 into `filter` + `exclude-filter` instead"
            } else {
                ""
            };
            format!("{field} regex error: {e}{hint}")
        }),
        None => Ok(None),
    }
}

async fn read_cache(path: Option<&Path>, name: &str) -> Result<String, String> {
    let Some(path) = path else {
        return Err(format!(
            "proxy-provider '{name}': fetch failed and no on-disk cache is configured"
        ));
    };
    tokio::fs::read_to_string(path)
        .await
        .map_err(|e| format!("proxy-provider '{name}': no cache at {path:?}: {e}"))
}

fn build_health_check_config(raw: Option<&RawHealthCheck>) -> Option<HealthCheckConfig> {
    let hc = raw?;
    if !hc.enable.unwrap_or(true) {
        return None;
    }
    Some(HealthCheckConfig {
        url: hc
            .url
            .clone()
            .unwrap_or_else(|| "https://www.gstatic.com/generate_204".to_string()),
        interval: hc.interval.unwrap_or(300),
        timeout: hc.timeout.unwrap_or(5000),
        expected_status: hc.expected_status.clone().unwrap_or_default(),
        lazy: hc.lazy.unwrap_or(false),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::RawProxyProvider;

    fn raw_file_provider(path: &str) -> RawProxyProvider {
        RawProxyProvider {
            provider_type: "file".to_string(),
            url: None,
            path: Some(path.to_string()),
            interval: None,
            filter: None,
            exclude_filter: None,
            exclude_type: None,
            health_check: None,
            allow_external_plugin: None,
            header: None,
        }
    }

    #[test]
    fn file_provider_new_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let raw = raw_file_provider("proxies.yaml");
        let p = ProxyProvider::new("test", &raw, Some(dir.path()), true, false).unwrap();
        assert_eq!(p.name, "test");
        assert_eq!(p.vehicle_type, "File");
        assert!(p.header.is_empty());
    }

    #[test]
    fn file_provider_requires_cache_dir_for_path() {
        let raw = raw_file_provider("/tmp/proxies.yaml");
        let Err(err) = ProxyProvider::new("test", &raw, None, true, false) else {
            panic!("file path without a cache dir must fail");
        };
        assert!(err.contains("cache directory"), "unexpected: {err}");
    }

    #[test]
    fn file_provider_path_escaping_cache_dir_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        for path in ["../../etc/pwned", "/etc/pwned"] {
            let raw = raw_file_provider(path);
            let Err(err) = ProxyProvider::new("test", &raw, Some(dir.path()), true, false) else {
                panic!("escaping path {path} must be rejected");
            };
            assert!(err.contains("escapes"), "path {path}: unexpected: {err}");
        }
    }

    #[test]
    fn http_provider_path_escaping_cache_dir_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let raw = RawProxyProvider {
            provider_type: "http".to_string(),
            url: Some("http://127.0.0.1:1/proxies.yaml".to_string()),
            path: Some("/etc/cron.d/pwned".to_string()),
            interval: None,
            filter: None,
            exclude_filter: None,
            exclude_type: None,
            health_check: None,
            allow_external_plugin: None,
            header: None,
        };
        let Err(err) = ProxyProvider::new("test", &raw, Some(dir.path()), true, false) else {
            panic!("escaping http cache path must be rejected");
        };
        assert!(err.contains("escapes"), "unexpected: {err}");
    }

    // PR #444 review follow-up: a proxy-provider path escaping the cache dir
    // must fail the whole rebuild loudly (rule-provider parity), not just
    // warn-skip the provider and silently degrade the groups using it.
    #[test]
    fn validate_paths_rejects_escaping_provider_paths() {
        let dir = tempfile::tempdir().unwrap();
        for path in ["../../etc/pwned", "/etc/cron.d/pwned"] {
            let mut map = HashMap::new();
            map.insert("evil".to_string(), raw_file_provider(path));
            let err = validate_paths(&map, Some(dir.path()))
                .expect_err("escaping path must fail validation");
            assert!(err.contains("evil"), "must name the provider: {err}");
            assert!(err.contains("escapes"), "path {path}: unexpected: {err}");
        }
    }

    #[test]
    fn validate_paths_accepts_contained_and_pathless_providers() {
        let dir = tempfile::tempdir().unwrap();
        let mut map = HashMap::new();
        map.insert("f".to_string(), raw_file_provider("sub/proxies.yaml"));
        map.insert(
            "h".to_string(),
            RawProxyProvider {
                provider_type: "http".to_string(),
                url: Some("http://127.0.0.1:1/proxies.yaml".to_string()),
                path: None, // implicit cache location from the name
                interval: None,
                filter: None,
                exclude_filter: None,
                exclude_type: None,
                health_check: None,
                allow_external_plugin: None,
                header: None,
            },
        );
        validate_paths(&map, Some(dir.path())).expect("contained paths must validate");
        // Rootless context: nothing on disk is honoured, nothing to contain.
        validate_paths(&map, None).expect("no cache dir means nothing to validate");
    }

    #[test]
    fn http_provider_new_with_custom_headers() {
        let mut headers = HashMap::new();
        headers.insert(
            "X-Token".to_string(),
            crate::raw::StringOrList::Single("secret".to_string()),
        );
        let raw = RawProxyProvider {
            provider_type: "http".to_string(),
            url: Some("https://example.com/proxies.yaml".to_string()),
            path: None,
            interval: None,
            filter: None,
            exclude_filter: None,
            exclude_type: None,
            health_check: None,
            allow_external_plugin: None,
            header: Some(headers),
        };
        let p = ProxyProvider::new("airport", &raw, None, true, false).unwrap();
        assert_eq!(p.vehicle_type, "HTTP");
        assert!(p
            .header
            .contains(&("X-Token".to_string(), "secret".to_string())));
    }

    #[test]
    fn http_provider_new_with_multi_value_headers() {
        // mihomo's canonical list form: one name, several values.
        let mut headers = HashMap::new();
        headers.insert(
            "User-Agent".to_string(),
            crate::raw::StringOrList::List(vec![
                "Clash/v1.18.0".to_string(),
                "mihomo/1.18.3".to_string(),
            ]),
        );
        headers.insert(
            "Authorization".to_string(),
            crate::raw::StringOrList::Single("token 1231231".to_string()),
        );
        let raw = RawProxyProvider {
            provider_type: "http".to_string(),
            url: Some("https://example.com/proxies.yaml".to_string()),
            path: None,
            interval: None,
            filter: None,
            exclude_filter: None,
            exclude_type: None,
            health_check: None,
            allow_external_plugin: None,
            header: Some(headers),
        };
        let p = ProxyProvider::new("airport", &raw, None, true, false).unwrap();
        // Multi-value entries repeat the name (one field line per value),
        // sorted by name like Go net/http.
        assert_eq!(
            p.header,
            vec![
                ("Authorization".to_string(), "token 1231231".to_string()),
                ("User-Agent".to_string(), "Clash/v1.18.0".to_string()),
                ("User-Agent".to_string(), "mihomo/1.18.3".to_string()),
            ]
        );
    }

    #[test]
    fn raw_proxy_provider_deserializes_header() {
        let yaml = r#"
type: http
url: "https://example.com/proxies.yaml"
header:
  Authorization: "Bearer token123"
  X-Custom: "value"
"#;
        let raw: RawProxyProvider = serde_yaml::from_str(yaml).unwrap();
        let headers = raw.header.unwrap();
        assert_eq!(
            headers.get("Authorization"),
            Some(&crate::raw::StringOrList::Single(
                "Bearer token123".to_string()
            ))
        );
        assert_eq!(
            headers.get("X-Custom"),
            Some(&crate::raw::StringOrList::Single("value".to_string()))
        );
    }

    #[test]
    fn raw_proxy_provider_deserializes_list_header() {
        // The mihomo wiki form: sequence values under `header:`.
        let yaml = r#"
type: http
url: "https://example.com/proxies.yaml"
header:
  User-Agent:
    - "Clash/v1.18.0"
    - "mihomo/1.18.3"
  Authorization:
    - 'token 1231231'
"#;
        let raw: RawProxyProvider = serde_yaml::from_str(yaml).unwrap();
        let headers = raw.header.unwrap();
        assert_eq!(
            headers.get("User-Agent"),
            Some(&crate::raw::StringOrList::List(vec![
                "Clash/v1.18.0".to_string(),
                "mihomo/1.18.3".to_string(),
            ]))
        );
        assert_eq!(
            headers.get("Authorization"),
            Some(&crate::raw::StringOrList::List(vec![
                "token 1231231".to_string()
            ]))
        );
    }

    #[test]
    fn raw_proxy_provider_no_header_defaults_empty() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = "type: file\npath: proxies.yaml\n";
        let raw: RawProxyProvider = serde_yaml::from_str(yaml).unwrap();
        assert!(raw.header.is_none());
        let p = ProxyProvider::new("p", &raw, Some(dir.path()), true, false).unwrap();
        assert!(p.header.is_empty());
    }

    fn group_filter(
        filter: Option<&str>,
        exclude_filter: Option<&str>,
        exclude_type: Option<&[&str]>,
    ) -> GroupFilter {
        let raw = crate::raw::RawProxyGroup {
            name: "g".to_string(),
            group_type: "select".to_string(),
            filter: filter.map(str::to_string),
            exclude_filter: exclude_filter.map(str::to_string),
            exclude_type: exclude_type.map(|v| v.iter().map(|s| (*s).to_string()).collect()),
            ..Default::default()
        };
        GroupFilter::from_raw_group(&raw).unwrap().unwrap()
    }

    fn write_provider_file(path: &std::path::Path, entries: &[(&str, &str)]) {
        use std::fmt::Write as _;
        let mut yaml = String::from("proxies:\n");
        for (name, ty) in entries {
            writeln!(
                yaml,
                "  - {{name: \"{name}\", type: {ty}, server: 127.0.0.1, port: 443, \
                 cipher: aes-128-gcm, password: pass}}"
            )
            .unwrap();
        }
        std::fs::write(path, yaml).unwrap();
    }

    fn slot_names(slot: &ProviderSlot) -> Vec<String> {
        slot.read().iter().map(|p| p.name().to_string()).collect()
    }

    async fn file_provider(path: &std::path::Path) -> ProxyProvider {
        let raw = raw_file_provider(path.to_str().unwrap());
        let cache_dir = path.parent().expect("temp file has a parent dir");
        let p = ProxyProvider::new("airport", &raw, Some(cache_dir), true, false).unwrap();
        p.refresh().await.unwrap();
        p
    }

    #[tokio::test]
    async fn derived_slot_applies_group_filter() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_provider_file(
            tmp.path(),
            &[("US 1", "ss"), ("US 2", "ss"), ("HK 1", "ss")],
        );
        let provider = file_provider(tmp.path()).await;

        let f = group_filter(Some("(?i)us"), Some("2"), None);
        let derived = provider.derived_slot(&f);
        assert_eq!(slot_names(&derived), ["US 1"]);
        // The provider's own slot stays unfiltered.
        assert_eq!(provider.proxies().len(), 3);
    }

    #[tokio::test]
    async fn derived_slot_updates_on_refresh_and_prunes_dropped_views() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_provider_file(tmp.path(), &[("US 1", "ss"), ("HK 1", "ss")]);
        let provider = file_provider(tmp.path()).await;

        let f = group_filter(Some("US"), None, None);
        let derived = provider.derived_slot(&f);
        assert_eq!(slot_names(&derived), ["US 1"]);

        write_provider_file(
            tmp.path(),
            &[("US 1", "ss"), ("US 9", "ss"), ("HK 2", "ss")],
        );
        provider.refresh().await.unwrap();
        assert_eq!(slot_names(&derived), ["US 1", "US 9"]);

        drop(derived);
        provider.refresh().await.unwrap();
        assert_eq!(provider.derived_len(), 0);
    }

    #[tokio::test]
    async fn derived_slot_exclude_type_accepts_alias_and_display_name() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_provider_file(tmp.path(), &[("US ss", "ss"), ("US direct", "direct")]);
        let provider = file_provider(tmp.path()).await;

        // Note: parse_direct keeps DirectAdapter's hardcoded "DIRECT" name.
        let by_alias = provider.derived_slot(&group_filter(None, None, Some(&["ss"])));
        assert_eq!(slot_names(&by_alias), ["DIRECT"]);

        let by_display = provider.derived_slot(&group_filter(None, None, Some(&["Shadowsocks"])));
        assert_eq!(slot_names(&by_display), ["DIRECT"]);

        // mihomo-style `|`-separated string form.
        let piped = provider.derived_slot(&group_filter(None, None, Some(&["ss|direct"])));
        assert!(slot_names(&piped).is_empty());
    }

    #[test]
    fn group_filter_absent_fields_yield_none() {
        let raw = crate::raw::RawProxyGroup {
            name: "g".to_string(),
            group_type: "select".to_string(),
            ..Default::default()
        };
        assert!(GroupFilter::from_raw_group(&raw).unwrap().is_none());
    }

    #[test]
    fn group_filter_lookahead_error_carries_hint() {
        let raw = crate::raw::RawProxyGroup {
            name: "g".to_string(),
            group_type: "select".to_string(),
            filter: Some("^(?!.*expat).*US".to_string()),
            ..Default::default()
        };
        let err = GroupFilter::from_raw_group(&raw).unwrap_err();
        assert!(err.contains("look-around"), "unexpected error: {err}");
    }
}
